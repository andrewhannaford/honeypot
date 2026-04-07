import socket
import threading
import time
import base64
import traceback
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import SMTP_PORT
from payloads import save_payload

def _handle_client(client_sock, client_addr):
    client_ip = client_addr[0]
    try:
        log_event(client_ip, SMTP_PORT, "SMTP", "connect")
        send_alert("SMTP", client_ip, "New connection", alert_type="connect")

        client_sock.settimeout(30)
        client_sock.sendall(b"220 ubuntu ESMTP Postfix\r\n")

        helo = ""
        mail_from = ""
        rcpt_to = []
        data_mode = False
        body_lines = []
        
        while True:
            line_raw = client_sock.recv(1024)
            if not line_raw:
                break
                
            line = line_raw.decode("utf-8", errors="ignore").strip()
            
            if data_mode:
                if line == ".":
                    data_mode = False
                    body = "\n".join(body_lines)
                    subject = ""
                    for bl in body_lines:
                        if bl.lower().startswith("subject:"):
                            subject = bl[8:].strip()
                            break
                    
                    event = log_event(client_ip, SMTP_PORT, "SMTP", "email_attempt", {
                        "helo": helo,
                        "from": mail_from,
                        "to": rcpt_to,
                        "subject": subject,
                        "body_preview": body[:200]
                    })
                    save_payload(client_ip, "SMTP", body.encode("utf-8", errors="replace"),
                                 event_id=event.get("rowid"))
                    client_sock.sendall(b"250 2.0.0 Ok: queued as 12345ABCDE\r\n")
                else:
                    body_lines.append(line)
                continue

            cmd = line.split(" ", 1)[0].upper()
            
            if cmd in ("HELO", "EHLO"):
                helo = line.split(" ", 1)[1] if " " in line else ""
                client_sock.sendall(b"250-ubuntu\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250 8BITMIME\r\n")
            elif cmd == "MAIL":
                mail_from = line[10:].strip("<>") if "FROM:" in line.upper() else ""
                client_sock.sendall(b"250 2.1.0 Ok\r\n")
            elif cmd == "RCPT":
                rcpt = line[8:].strip("<>") if "TO:" in line.upper() else ""
                rcpt_to.append(rcpt)
                client_sock.sendall(b"250 2.1.5 Ok\r\n")
            elif cmd == "DATA":
                data_mode = True
                client_sock.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            elif cmd == "AUTH":
                auth_parts = line.split(" ")
                if len(auth_parts) > 1:
                    mech = auth_parts[1].upper()
                    if mech == "PLAIN":
                        if len(auth_parts) > 2:
                            # AUTH PLAIN <base64>
                            _log_auth_plain(client_ip, auth_parts[2])
                        else:
                            # Prompt for it? Real servers might. 
                            client_sock.sendall(b"334 \r\n")
                            resp = client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
                            _log_auth_plain(client_ip, resp)
                    elif mech == "LOGIN":
                        # AUTH LOGIN
                        client_sock.sendall(b"334 VXNlcm5hbWU6\r\n") # "Username:" in b64
                        user_b64 = client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
                        client_sock.sendall(b"334 UGFzc3dvcmQ6\r\n") # "Password:" in b64
                        pass_b64 = client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
                        _log_auth_login(client_ip, user_b64, pass_b64)
                
                client_sock.sendall(b"235 2.7.0 Authentication successful\r\n")
            elif cmd == "QUIT":
                client_sock.sendall(b"221 2.0.0 Bye\r\n")
                break
            elif cmd == "RSET":
                mail_from = ""
                rcpt_to = []
                body_lines = []
                client_sock.sendall(b"250 2.0.0 Ok\r\n")
            elif cmd == "NOOP":
                client_sock.sendall(b"250 2.0.0 Ok\r\n")
            else:
                client_sock.sendall(b"502 5.5.1 Command not implemented\r\n")
                
    except Exception:
        # traceback.print_exc()
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        ratelimit.release()

def _log_auth_plain(ip, b64_str):
    try:
        decoded = base64.b64decode(b64_str)
        # PLAIN is \x00user\x00pass
        parts = decoded.split(b"\x00")
        if len(parts) >= 3:
            user = parts[1].decode("utf-8", errors="replace")
            pw = parts[2].decode("utf-8", errors="replace")
            log_event(ip, SMTP_PORT, "SMTP", "credential", {"username": user, "password": pw, "mech": "PLAIN"})
            send_alert("SMTP", ip, f"Login (PLAIN): `{user}` / `{pw}`", alert_type="credential")
    except Exception:
        pass

def _log_auth_login(ip, user_b64, pass_b64):
    try:
        user = base64.b64decode(user_b64).decode("utf-8", errors="replace")
        pw = base64.b64decode(pass_b64).decode("utf-8", errors="replace")
        log_event(ip, SMTP_PORT, "SMTP", "credential", {"username": user, "password": pw, "mech": "LOGIN"})
        send_alert("SMTP", ip, f"Login (LOGIN): `{user}` / `{pw}`", alert_type="credential")
    except Exception:
        pass

def start_smtp_server():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", SMTP_PORT))
            sock.listen(100)
            print(f"[SMTP] Listening on port {SMTP_PORT}")
            while True:
                client, addr = sock.accept()
                if not ratelimit.check_and_acquire(addr[0]):
                    client.close()
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[SMTP] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
