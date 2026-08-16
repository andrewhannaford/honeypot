import socket
import struct
import threading
import time
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import POSTGRES_PORT, POSTGRES_VERSION

SSL_REQUEST = 80877103
GSSENC_REQUEST = 80877104

def _read_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: return None
        buf += chunk
    return buf

def _read_startup(sock):
    """Startup packets have no type byte — just Int32 length then the body."""
    header = _read_exactly(sock, 4)
    if header is None: return None
    length = struct.unpack("!I", header)[0]
    if length < 8 or length > 65536: return None
    return _read_exactly(sock, length - 4)

def _parse_params(body):
    """Body is Int32 protocol version then null-terminated key/value pairs."""
    params = {}
    parts = body[4:].split(b"\x00")
    for i in range(0, len(parts) - 1, 2):
        key = parts[i].decode("utf-8", errors="replace")
        if not key: break
        params[key] = parts[i + 1].decode("utf-8", errors="replace")
    return params

def _error(message, username):
    fields = (
        b"SFATAL\x00"
        + b"C28P01\x00"                       # invalid_password
        + b"M" + message.encode() + b"\x00"
        + b"\x00"
    )
    return b"E" + struct.pack("!I", len(fields) + 4) + fields

def _handle_client(client_sock, client_addr):
    client_ip = client_addr[0]
    try:
        log_event(client_ip, POSTGRES_PORT, "POSTGRES", "connect")
        send_alert("POSTGRES", client_ip, "New connection", alert_type="connect")

        client_sock.settimeout(30)

        body = _read_startup(client_sock)
        if body is None:
            return

        # Clients probe for TLS/GSSAPI before the real startup. Decline both so the
        # conversation continues in plaintext, where the password is readable.
        version = struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0
        while version in (SSL_REQUEST, GSSENC_REQUEST):
            client_sock.sendall(b"N")
            body = _read_startup(client_sock)
            if body is None:
                return
            version = struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0

        params = _parse_params(body)
        username = params.get("user", "")
        database = params.get("database", username)

        # AuthenticationCleartextPassword (code 3) — the client will now send the
        # password with no hashing at all.
        client_sock.sendall(b"R" + struct.pack("!II", 8, 3))

        password = ""
        tag = _read_exactly(client_sock, 1)
        if tag == b"p":
            length_bytes = _read_exactly(client_sock, 4)
            if length_bytes is not None:
                length = struct.unpack("!I", length_bytes)[0]
                if 4 < length <= 4096:
                    raw = _read_exactly(client_sock, length - 4) or b""
                    password = raw.rstrip(b"\x00").decode("utf-8", errors="replace")

        log_event(client_ip, POSTGRES_PORT, "POSTGRES", "credential",
                  {"username": username, "password": password, "database": database})
        send_alert("POSTGRES", client_ip,
                   f"Login attempt: `{username}` / `{password}` (db: `{database}`)",
                   alert_type="credential")

        client_sock.sendall(
            _error(f'password authentication failed for user "{username}"', username)
        )
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        ratelimit.release()

def start_postgres_server():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", POSTGRES_PORT))
            sock.listen(100)
            print(f"[POSTGRES] Listening on port {POSTGRES_PORT}")
            while True:
                client, addr = sock.accept()
                if not ratelimit.check_and_acquire(addr[0]):
                    client.close()
                    log_event(addr[0], POSTGRES_PORT, "POSTGRES", "rate_limited")
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[POSTGRES] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
