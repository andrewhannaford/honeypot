import os
import socket
import threading
import time
import traceback
import re
import paramiko
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import SSH_PORT, SSH_BANNER, SSH_ACCEPT_RATE
from services.fake_shell import run_shell
from payloads import save_payload

KEY_PATH = "data/ssh_host_key"
URL_REGEX = re.compile(r"https?://\S+")


def _get_host_key():
    if os.path.exists(KEY_PATH):
        return paramiko.RSAKey(filename=KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_PATH)
    return key


HOST_KEY = _get_host_key()


class _SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.attempt_count = 0
        self.username = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        try:
            cmd_str = command.decode("utf-8", errors="replace")
            urls = URL_REGEX.findall(cmd_str)
            is_download = bool(urls) or "wget " in cmd_str or "curl " in cmd_str

            event_type = "download_attempt" if is_download else "exec_attempt"
            data = {"command": cmd_str}
            if urls:
                data["urls"] = urls

            event = log_event(self.client_ip, SSH_PORT, "SSH", event_type, data)
            send_alert("SSH", self.client_ip, f"Exec: `{cmd_str}`", alert_type=event_type)
            save_payload(self.client_ip, "SSH", command, event_id=event.get("rowid"))

            channel.send_exit_status(0)
            channel.close()
            return True
        except Exception:
            traceback.print_exc()
            return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_auth_password(self, username, password):
        self.username = username
        self.attempt_count += 1
        log_event(self.client_ip, SSH_PORT, "SSH", "credential",
                  {"username": username, "password": password})
        send_alert("SSH", self.client_ip, f"Login attempt: `{username}` / `{password}`",
                   alert_type="credential")

        if self.attempt_count >= SSH_ACCEPT_RATE:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.username = username
        log_event(self.client_ip, SSH_PORT, "SSH", "pubkey_attempt",
                  {"username": username, "key_type": key.get_name()})
        send_alert("SSH", self.client_ip,
                   f"Public key attempt: `{username}` ({key.get_name()})",
                   alert_type="credential")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"


def _handle_client(client_sock, client_addr):
    client_ip = client_addr[0]
    transport = None
    try:
        log_event(client_ip, SSH_PORT, "SSH", "connect")
        send_alert("SSH", client_ip, "New connection", alert_type="connect")

        transport = paramiko.Transport(client_sock)
        transport.local_version = SSH_BANNER
        transport.add_server_key(HOST_KEY)

        server = _SSHServer(client_ip)
        transport.start_server(server=server)

        # Wait up to 60s for auth and channel requests
        channel = transport.accept(60)
        if channel:
            # If we are here, auth succeeded and a channel was opened.
            # Set a timeout for interactive inactivity
            channel.settimeout(120)

            def send_fn(x):
                try:
                    channel.send(x.encode("utf-8", errors="replace"))
                except Exception:
                    pass

            def recv_line_fn():
                buffer = b""
                while True:
                    try:
                        char = channel.recv(1)
                        if not char:
                            return None
                        if char in (b"\r", b"\n"):
                            send_fn("\r\n")
                            return buffer.decode("utf-8", errors="replace")
                        if char in (b"\x7f", b"\x08"):  # Backspace
                            if len(buffer) > 0:
                                buffer = buffer[:-1]
                                send_fn("\b \b")
                            continue
                        if char == b"\x1b":  # ANSI escape (basic)
                            # Try to consume [A, [B, etc.
                            channel.recv(2)
                            continue
                        buffer += char
                        send_fn(char.decode("utf-8", errors="replace"))
                    except Exception:
                        return None

            run_shell(send_fn, recv_line_fn, client_ip, SSH_PORT, "SSH", server.username)
            channel.close()

    except Exception:
        # traceback.print_exc()
        pass
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        else:
            try:
                client_sock.close()
            except Exception:
                pass
        ratelimit.release()


def start_ssh_server():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", SSH_PORT))
            sock.listen(100)
            print(f"[SSH] Listening on port {SSH_PORT}")
            while True:
                client, addr = sock.accept()
                if not ratelimit.check_and_acquire(addr[0]):
                    client.close()
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[SSH] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
