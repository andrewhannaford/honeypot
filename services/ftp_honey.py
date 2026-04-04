import socket
import threading
import time
import traceback
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import FTP_PORT, FTP_BANNER


def _handle_client(client_sock, client_addr):
    client_ip = client_addr[0]
    try:
        log_event(client_ip, FTP_PORT, "FTP", "connect")
        send_alert("FTP", client_ip, "New connection", alert_type="connect")

        client_sock.settimeout(30)
        client_sock.sendall(f"{FTP_BANNER}\r\n".encode())

        username = None
        buf = ""
        done = False
        while not done:
            data = client_sock.recv(1024)
            if not data:
                break
            buf += data.decode("utf-8", errors="ignore")
            if len(buf) > 4096:   # drop abusive clients sending data without newlines
                break

            # Process every complete line in the buffer
            while "\r\n" in buf or "\n" in buf:
                if "\r\n" in buf:
                    line, buf = buf.split("\r\n", 1)
                else:
                    line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue

                parts = line.split(" ", 1)
                command = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if command == "USER":
                    username = arg
                    client_sock.sendall(b"331 Password required for " + arg.encode() + b"\r\n")
                elif command == "PASS":
                    if username is None:
                        client_sock.sendall(b"503 Login with USER first.\r\n")
                    else:
                        log_event(client_ip, FTP_PORT, "FTP", "credential",
                                  {"username": username, "password": arg})
                        send_alert("FTP", client_ip, f"Login attempt: `{username}` / `{arg}`",
                                   alert_type="credential")
                        client_sock.sendall(b"530 Login incorrect.\r\n")
                elif command == "QUIT":
                    client_sock.sendall(b"221 Goodbye.\r\n")
                    done = True
                    break
                else:
                    client_sock.sendall(b"530 Please login with USER and PASS.\r\n")
    except Exception:
        traceback.print_exc()
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        ratelimit.release()


def start_ftp_server():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", FTP_PORT))
            sock.listen(100)
            print(f"[FTP] Listening on port {FTP_PORT}")
            while True:
                client, addr = sock.accept()
                if not ratelimit.check_and_acquire(addr[0]):
                    client.close()
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[FTP] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
