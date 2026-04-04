import os
import socket
import threading
import time
import traceback
import paramiko
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import SSH_PORT, SSH_BANNER

KEY_PATH = "data/ssh_host_key"


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

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_event(self.client_ip, SSH_PORT, "SSH", "credential",
                  {"username": username, "password": password})
        send_alert("SSH", self.client_ip, f"Login attempt: `{username}` / `{password}`",
                   alert_type="credential")
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
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

        # Wait up to 30 s for auth attempts then close
        channel = transport.accept(30)
        if channel:
            channel.send("Permission denied.\r\n")
            channel.close()
    except Exception:
        traceback.print_exc()
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
