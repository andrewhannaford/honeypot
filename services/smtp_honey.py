import datetime
import os
import re
import socket
import ssl
import threading
import time
import base64
import traceback
import uuid
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from payloads import save_payload
from config import SMTP_PORT, DATA_DIR

_CERT_PATH = os.path.join(DATA_DIR, "smtp_honey_cert.pem")
_KEY_PATH = os.path.join(DATA_DIR, "smtp_honey_key.pem")

# MAIL FROM:<addr> / RCPT TO:<addr> parsing — previously fixed-offset slicing
# (line[10:], line[8:]) which breaks on RFC 1870 SIZE= parameters or the extra
# whitespace real MTAs (e.g. swaks) commonly send, silently corrupting the
# captured address. Regex-based and tolerant of both.
_MAIL_FROM_RE = re.compile(r"FROM:\s*<?([^<>\s]*)>?", re.IGNORECASE)
_RCPT_TO_RE = re.compile(r"TO:\s*<?([^<>\s]*)>?", re.IGNORECASE)

# Unlike ftp_honey.py's upload buffer (capped at 4096), DATA mode here had no
# size limit at all — an attacker could stream lines indefinitely and grow
# body_lines without bound for the life of the connection. Captured payloads
# in this threat model (cron/script droppers, credential phish bodies) are
# small; this only bounds the attacker-controlled growth, not real mail size.
_MAX_BODY_BYTES = 65536


def _parse_addr(line, regex):
    m = regex.search(line)
    return m.group(1) if m else ""


def _ensure_cert():
    """Same pattern as https_honey.py's _ensure_cert — a persisted self-signed
    cert so STARTTLS's fingerprint doesn't change across restarts."""
    if os.path.exists(_CERT_PATH) and os.path.exists(_KEY_PATH):
        return True
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print("[SMTP] cryptography not available — STARTTLS disabled")
        return False

    os.makedirs(DATA_DIR, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ubuntu")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=390))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("ubuntu")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(_KEY_PATH, 0o600)
    with open(_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("[SMTP] Generated self-signed cert for STARTTLS")
    return True


_STARTTLS_AVAILABLE = _ensure_cert()


def _handle_client(client_sock, client_addr):
    client_ip = client_addr[0]
    sock = client_sock  # rebound to a TLS-wrapped socket after a successful STARTTLS
    connection_id = uuid.uuid4().hex
    try:
        log_event(client_ip, SMTP_PORT, "SMTP", "connect", connection_id=connection_id)
        send_alert("SMTP", client_ip, "New connection", alert_type="connect")

        sock.settimeout(30)
        sock.sendall(b"220 ubuntu ESMTP Postfix\r\n")

        helo = ""
        mail_from = ""
        rcpt_to = []
        data_mode = False
        body_lines = []

        while True:
            line_raw = sock.recv(1024)
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
                    }, connection_id=connection_id)
                    save_payload(client_ip, "SMTP", body.encode("utf-8", errors="replace"),
                                 event_id=event.get("rowid"))
                    sock.sendall(b"250 2.0.0 Ok: queued as 12345ABCDE\r\n")
                else:
                    if sum(len(bl) for bl in body_lines) < _MAX_BODY_BYTES:
                        body_lines.append(line)
                continue

            cmd = line.split(" ", 1)[0].upper()

            if cmd in ("HELO", "EHLO"):
                helo = line.split(" ", 1)[1] if " " in line else ""
                caps = [b"250-ubuntu", b"250-PIPELINING", b"250-SIZE 10240000"]
                if _STARTTLS_AVAILABLE:
                    caps.append(b"250-STARTTLS")
                caps += [b"250-AUTH PLAIN LOGIN", b"250-ENHANCEDSTATUSCODES", b"250 8BITMIME"]
                sock.sendall(b"\r\n".join(caps) + b"\r\n")
            elif cmd == "STARTTLS" and _STARTTLS_AVAILABLE and not isinstance(sock, ssl.SSLSocket):
                # Real Postfix advertises and implements this; not doing so was
                # a code-confirmed gap that makes any TLS-requiring client bail
                # before ever reaching AUTH/DATA. Wraps the *same* connection —
                # everything after this point (including the next HELO/EHLO a
                # real client re-sends post-STARTTLS) goes over the encrypted
                # socket.
                sock.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(certfile=_CERT_PATH, keyfile=_KEY_PATH)
                    try:
                        ctx.minimum_version = ssl.TLSVersion.TLSv1
                    except (ValueError, AttributeError):
                        pass
                    ctx.set_ciphers("ALL:@SECLEVEL=0")
                    sock = ctx.wrap_socket(sock, server_side=True)
                    sock.settimeout(30)
                    helo = mail_from = ""
                    rcpt_to = []
                except Exception as e:
                    log_event(client_ip, SMTP_PORT, "SMTP", "connect", {"tls_error": str(e)[:120]},
                              connection_id=connection_id)
                    break
            elif cmd == "MAIL":
                mail_from = _parse_addr(line, _MAIL_FROM_RE)
                sock.sendall(b"250 2.1.0 Ok\r\n")
            elif cmd == "RCPT":
                rcpt = _parse_addr(line, _RCPT_TO_RE)
                rcpt_to.append(rcpt)
                # Open-relay abuse test: a spammer's classic probe is "can I
                # relay through you to some domain that has nothing to do with
                # you." Every AUTH here always "succeeds" (see below), so
                # authentication state can't distinguish legitimate-vs-abuse —
                # domain mismatch against what was HELO'd is the signal instead.
                rcpt_domain = rcpt.split("@")[-1].lower() if "@" in rcpt else ""
                helo_domain = helo.lower()
                if rcpt_domain and helo_domain and rcpt_domain not in helo_domain and helo_domain not in rcpt_domain:
                    log_event(client_ip, SMTP_PORT, "SMTP", "relay_attempt", {"helo": helo, "rcpt": rcpt},
                              connection_id=connection_id)
                    send_alert("SMTP", client_ip, f"Possible open-relay test: RCPT TO `{rcpt}` (HELO `{helo}`)",
                               alert_type="relay_attempt")
                sock.sendall(b"250 2.1.5 Ok\r\n")
            elif cmd == "DATA":
                data_mode = True
                sock.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            elif cmd == "AUTH":
                auth_parts = line.split(" ")
                if len(auth_parts) > 1:
                    mech = auth_parts[1].upper()
                    if mech == "PLAIN":
                        if len(auth_parts) > 2:
                            # AUTH PLAIN <base64>
                            _log_auth_plain(client_ip, auth_parts[2], connection_id)
                        else:
                            # Prompt for it? Real servers might.
                            sock.sendall(b"334 \r\n")
                            resp = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                            _log_auth_plain(client_ip, resp, connection_id)
                    elif mech == "LOGIN":
                        # AUTH LOGIN
                        sock.sendall(b"334 VXNlcm5hbWU6\r\n") # "Username:" in b64
                        user_b64 = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                        sock.sendall(b"334 UGFzc3dvcmQ6\r\n") # "Password:" in b64
                        pass_b64 = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                        _log_auth_login(client_ip, user_b64, pass_b64, connection_id)

                sock.sendall(b"235 2.7.0 Authentication successful\r\n")
            elif cmd == "QUIT":
                sock.sendall(b"221 2.0.0 Bye\r\n")
                break
            elif cmd == "RSET":
                mail_from = ""
                rcpt_to = []
                body_lines = []
                sock.sendall(b"250 2.0.0 Ok\r\n")
            elif cmd == "NOOP":
                sock.sendall(b"250 2.0.0 Ok\r\n")
            else:
                sock.sendall(b"502 5.5.1 Command not implemented\r\n")

    except Exception:
        # traceback.print_exc()
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
        ratelimit.release()

def _log_auth_plain(ip, b64_str, connection_id=None):
    try:
        decoded = base64.b64decode(b64_str)
        # PLAIN is \x00user\x00pass
        parts = decoded.split(b"\x00")
        if len(parts) >= 3:
            user = parts[1].decode("utf-8", errors="replace")
            pw = parts[2].decode("utf-8", errors="replace")
            log_event(ip, SMTP_PORT, "SMTP", "credential", {"username": user, "password": pw, "mech": "PLAIN"},
                      connection_id=connection_id)
            send_alert("SMTP", ip, f"Login (PLAIN): `{user}` / `{pw}`", alert_type="credential")
    except Exception:
        pass

def _log_auth_login(ip, user_b64, pass_b64, connection_id=None):
    try:
        user = base64.b64decode(user_b64).decode("utf-8", errors="replace")
        pw = base64.b64decode(pass_b64).decode("utf-8", errors="replace")
        log_event(ip, SMTP_PORT, "SMTP", "credential", {"username": user, "password": pw, "mech": "LOGIN"},
                  connection_id=connection_id)
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
                    log_event(addr[0], SMTP_PORT, "SMTP", "rate_limited")
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[SMTP] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
