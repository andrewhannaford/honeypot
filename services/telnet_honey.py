import socket
import threading
import time
import traceback
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import TELNET_PORT, TELNET_BANNER

# Telnet negotiation bytes: WILL SUPPRESS-GO-AHEAD, WILL ECHO
_NEGOTIATE = b"\xff\xfb\x03\xff\xfb\x01"


def _recv_line(sock, max_len=1024):
    """Read one line from socket one byte at a time, discarding Telnet IAC sequences.

    Handles all three IAC forms:
      - 2-byte: IAC <command>                       (NOP, DM, BRK, IP, etc.)
      - 3-byte: IAC WILL/WONT/DO/DONT <option>
      - variable: IAC SB ... IAC SE                 (sub-negotiation)
    """
    buf = b""
    while len(buf) < max_len:
        b = sock.recv(1)
        if not b:
            return None
        byte = b[0]

        if byte == 0xFF:  # IAC
            cmd = sock.recv(1)
            if not cmd:
                return None
            cmd_byte = cmd[0]
            if cmd_byte in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL, WONT, DO, DONT — 3-byte
                sock.recv(1)  # consume option byte
            elif cmd_byte == 0xFA:  # SB — sub-negotiation, read until IAC SE
                prev = 0
                while True:
                    sb = sock.recv(1)
                    if not sb:
                        return None
                    if prev == 0xFF and sb[0] == 0xF0:  # IAC SE
                        break
                    prev = sb[0]
            # All other commands (2-byte total) — cmd byte already consumed, continue
            continue

        if byte in (0x0D, 0x0A):  # CR or LF — end of line
            if buf:
                return buf.decode("utf-8", errors="ignore").strip()
        else:
            buf += bytes([byte])

    # Line exceeded max_len — return what we have
    return buf.decode("utf-8", errors="ignore").strip()


def _handle_client(client_sock, client_addr):
    client_ip = client_addr[0]
    try:
        log_event(client_ip, TELNET_PORT, "TELNET", "connect")
        send_alert("TELNET", client_ip, "New connection", alert_type="connect")

        client_sock.settimeout(30)
        client_sock.sendall(_NEGOTIATE)
        client_sock.sendall(f"\r\n{TELNET_BANNER}\r\n\r\nlogin: ".encode())

        username = _recv_line(client_sock)
        if username is None:
            return

        client_sock.sendall(b"Password: ")
        password = _recv_line(client_sock)
        if password is None:
            return

        log_event(client_ip, TELNET_PORT, "TELNET", "credential",
                  {"username": username, "password": password})
        send_alert("TELNET", client_ip, f"Login attempt: `{username}` / `{password}`",
                   alert_type="credential")

        client_sock.sendall(b"\r\nLogin incorrect\r\n")
    except Exception:
        traceback.print_exc()
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        ratelimit.release()


def start_telnet_server():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", TELNET_PORT))
            sock.listen(100)
            print(f"[TELNET] Listening on port {TELNET_PORT}")
            while True:
                client, addr = sock.accept()
                if not ratelimit.check_and_acquire(addr[0]):
                    client.close()
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[TELNET] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
