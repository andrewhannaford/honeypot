import socket
import struct
import threading
import time
import os
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import MYSQL_PORT, MYSQL_VERSION

# MySQL wire protocol: every message is a 3-byte little-endian length,
# a 1-byte sequence number, then the payload.
def _pkt(payload, seq):
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload

def _read_pkt(sock):
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk: return None, None
        header += chunk
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    seq = header[3]
    body = b""
    while len(body) < length:
        chunk = sock.recv(min(4096, length - len(body)))
        if not chunk: return None, None
        body += chunk
    return body, seq

def _handshake(conn_id):
    salt1 = os.urandom(8)
    salt2 = os.urandom(12)
    return (
        b"\x0a"                              # protocol version 10
        + MYSQL_VERSION.encode() + b"\x00"
        + struct.pack("<I", conn_id)
        + salt1 + b"\x00"
        + struct.pack("<H", 0xFFF7)          # capabilities (lower) — includes PROTOCOL_41
        + b"\x21"                            # charset utf8_general_ci
        + struct.pack("<H", 0x0002)          # status: autocommit
        + struct.pack("<H", 0x81FF)          # capabilities (upper) — includes PLUGIN_AUTH
        + bytes([21])                        # auth plugin data length
        + b"\x00" * 10                       # reserved
        + salt2 + b"\x00"
        + b"mysql_native_password\x00"
    )

def _parse_login(payload):
    """HandshakeResponse41: username starts after caps(4) + maxpkt(4) + charset(1) + filler(23)."""
    if len(payload) < 33:
        return None, None
    rest = payload[32:]
    end = rest.find(b"\x00")
    if end < 0:
        return None, None
    username = rest[:end].decode("utf-8", errors="replace")

    # Whatever follows is the native-password scramble. It's a SHA1 digest, not the
    # password, so it is only worth recording as a fingerprint — the auth switch below
    # is what actually yields cleartext.
    scramble = rest[end + 1:]
    return username, scramble.hex()[:64]

def _error(msg, seq):
    return _pkt(
        b"\xff"
        + struct.pack("<H", 1045)             # ER_ACCESS_DENIED_ERROR
        + b"#28000"
        + msg.encode(),
        seq,
    )

def _handle_client(client_sock, client_addr):
    client_ip = client_addr[0]
    try:
        log_event(client_ip, MYSQL_PORT, "MYSQL", "connect")
        send_alert("MYSQL", client_ip, "New connection", alert_type="connect")

        client_sock.settimeout(30)
        client_sock.sendall(_pkt(_handshake(threading.get_ident() & 0xFFFFFFFF), 0))

        payload, seq = _read_pkt(client_sock)
        if payload is None:
            return

        username, scramble = _parse_login(payload)
        if username is None:
            return

        # Ask the client to switch to cleartext auth. Real servers do this for PAM/LDAP
        # backends, so compliant clients comply — and then send the password in the clear.
        client_sock.sendall(_pkt(b"\xfe" + b"mysql_clear_password\x00", seq + 1))

        password = None
        payload, seq = _read_pkt(client_sock)
        if payload is not None:
            password = payload.rstrip(b"\x00").decode("utf-8", errors="replace")

        if password:
            log_event(client_ip, MYSQL_PORT, "MYSQL", "credential",
                      {"username": username, "password": password})
            send_alert("MYSQL", client_ip,
                       f"Login attempt: `{username}` / `{password}`", alert_type="credential")
        else:
            # Client refused the switch — keep the username and the scramble anyway.
            log_event(client_ip, MYSQL_PORT, "MYSQL", "credential",
                      {"username": username, "password": "", "scramble": scramble})
            send_alert("MYSQL", client_ip,
                       f"Login attempt: `{username}` (no cleartext)", alert_type="credential")

        client_sock.sendall(
            _error(f"Access denied for user '{username}'@'{client_ip}' "
                   f"(using password: YES)", seq + 1)
        )
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        ratelimit.release()

def start_mysql_server():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", MYSQL_PORT))
            sock.listen(100)
            print(f"[MYSQL] Listening on port {MYSQL_PORT}")
            while True:
                client, addr = sock.accept()
                if not ratelimit.check_and_acquire(addr[0]):
                    client.close()
                    log_event(addr[0], MYSQL_PORT, "MYSQL", "rate_limited")
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[MYSQL] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
