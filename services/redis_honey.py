import socket
import threading
import time
import traceback
import uuid
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import REDIS_PORT
from payloads import save_payload

# Real commands this honeypot cares about (AUTH, CONFIG SET, the SET/EVAL
# payload itself) are tiny. socket.recv(n) pre-allocates an n-byte buffer
# before the syscall runs, so an unbounded attacker-supplied $<len> header
# (e.g. "*1\r\n$2000000000\r\n") is a memory-exhaustion DoS otherwise —
# confirmed live as a real gap, not hypothetical.
_MAX_BULK_LEN = 1024 * 1024  # 1 MB


def _parse_resp(sock):
    """Simple RESP parser (supports inline and arrays)."""
    line = b""
    while True:
        char = sock.recv(1)
        if not char: return None
        if char == b"\r":
            sock.recv(1) # consume \n
            break
        line += char

    if not line: return []

    if line.startswith(b"*"):
        # Array: *<num_elements>\r\n$<len>\r\n<data>\r\n...
        try:
            num_elements = min(int(line[1:]), 128)
            elements = []
            for _ in range(num_elements):
                # Read bulk string header
                header = b""
                while True:
                    c = sock.recv(1)
                    if not c: return None
                    if c == b"\r":
                        sock.recv(1)
                        break
                    header += c
                if not header.startswith(b"$"): return None
                bulk_len = int(header[1:])
                if bulk_len < 0 or bulk_len > _MAX_BULK_LEN:
                    return None
                # Looped, not a single recv(bulk_len): a bulk string spanning
                # more than one TCP read was previously silently truncated,
                # and the trailing recv(2) then consumed leftover payload
                # bytes instead of the real \r\n — desyncing the rest of the
                # connection's parsing.
                data = b""
                while len(data) < bulk_len:
                    chunk = sock.recv(min(4096, bulk_len - len(data)))
                    if not chunk: return None
                    data += chunk
                sock.recv(2) # consume \r\n
                elements.append(data.decode("utf-8", errors="replace"))
            return elements
        except Exception:
            return None
    else:
        # Inline command
        return line.decode("utf-8", errors="replace").split()

def _handle_client(client_sock, client_addr):
    client_ip = client_addr[0]
    # Threaded through every log_event call below so the dashboard's Sessions tab
    # can group one connection's full command sequence into a readable transcript
    # instead of isolated rows scattered through the Events tab — see app.py's
    # /api/redis-sessions and the events.connection_id column (logger.py).
    connection_id = uuid.uuid4().hex
    try:
        log_event(client_ip, REDIS_PORT, "REDIS", "connect", connection_id=connection_id)
        send_alert("REDIS", client_ip, "New connection", alert_type="connect")

        client_sock.settimeout(30)
        
        while True:
            parts = _parse_resp(client_sock)
            if parts is None or not parts:
                break
                
            cmd = parts[0].upper()
            
            if cmd == "PING":
                client_sock.sendall(b"+PONG\r\n")
            elif cmd == "AUTH":
                password = parts[1] if len(parts) > 1 else ""
                log_event(client_ip, REDIS_PORT, "REDIS", "credential", {"password": password},
                          connection_id=connection_id)
                send_alert("REDIS", client_ip, f"Login attempt: `{password}`", alert_type="credential")
                client_sock.sendall(b"+OK\r\n")
            elif cmd == "INFO":
                info = (
                    "# Server\r\n"
                    "redis_version:7.0.0\r\n"
                    "os:Linux 5.15.0-76-generic x86_64\r\n"
                    "arch_bits:64\r\n"
                    "tcp_port:6379\r\n"
                    "uptime_in_seconds:3600\r\n"
                    "# Clients\r\n"
                    "connected_clients:1\r\n"
                    "# Memory\r\n"
                    "used_memory:1048576\r\n"
                )
                client_sock.sendall(f"${len(info)}\r\n{info}\r\n".encode())
            elif cmd == "CONFIG":
                # Previously not logged at all despite being the identifying
                # step of the classic webshell-via-RDB-overwrite chain
                # (CONFIG SET dir / CONFIG SET dbfilename / SET / SAVE) — real
                # data shows 266 SAVE + 422 SET but zero CONFIG rows, strongly
                # implying this step was happening invisibly. CONFIG GET dir
                # returning a real Redis-on-Debian default (rather than empty)
                # lets a scripted exploit believe it worked and proceed to the
                # SET/SAVE steps we already capture, instead of bailing here.
                args_str = " ".join(parts[1:])
                log_event(client_ip, REDIS_PORT, "REDIS", "config_attempt", {"args": args_str},
                          connection_id=connection_id)
                subcmd = parts[1].upper() if len(parts) > 1 else ""
                if subcmd == "GET" and len(parts) > 2:
                    key = parts[2]
                    fake_values = {"dir": "/var/lib/redis", "dbfilename": "dump.rdb"}
                    value = fake_values.get(key.lower(), "")
                    resp = f"*2\r\n${len(key)}\r\n{key}\r\n${len(value)}\r\n{value}\r\n"
                    client_sock.sendall(resp.encode())
                else:
                    client_sock.sendall(b"*0\r\n")
            elif cmd in ("SLAVEOF", "REPLICAOF"):
                # Rogue-replication RCE technique — confirmed live as a real,
                # complete attack chain on this box (SLAVEOF <attacker-ip> ->
                # MODULE LOAD of a pushed .so -> SYSTEM.EXEC reverse shell),
                # previously logged identically to any other unrecognized
                # command and lost among port-scan noise.
                target = " ".join(parts[1:])
                event = log_event(client_ip, REDIS_PORT, "REDIS", "replication_attempt", {"target": target},
                                   connection_id=connection_id)
                send_alert("REDIS", client_ip, f"Rogue replication attempt: `{cmd} {target}`", alert_type="replication_attempt")
                client_sock.sendall(b"+OK\r\n")
            elif cmd == "MODULE":
                # Loading an attacker-supplied .so is the RCE step of the same
                # chain SLAVEOF sets up — confirmed live (MODULE LOAD /tmp/exp.so).
                args_str = " ".join(parts[1:])
                event = log_event(client_ip, REDIS_PORT, "REDIS", "module_attempt", {"args": args_str},
                                   connection_id=connection_id)
                save_payload(client_ip, "REDIS", args_str.encode("utf-8", errors="replace"),
                             event_id=event.get("rowid"))
                send_alert("REDIS", client_ip, f"Module load attempt (likely RCE): `{args_str}`", alert_type="module_attempt")
                client_sock.sendall(b"+OK\r\n")
            elif cmd == "CLUSTER":
                args_str = " ".join(parts[1:])
                log_event(client_ip, REDIS_PORT, "REDIS", "cluster_attempt", {"args": args_str},
                          connection_id=connection_id)
                client_sock.sendall(b"*0\r\n")
            elif cmd == "KEYS":
                client_sock.sendall(b"*0\r\n")
            elif cmd == "DBSIZE":
                client_sock.sendall(b":0\r\n")
            elif cmd == "SELECT":
                client_sock.sendall(b"+OK\r\n")
            elif cmd in ("COMMAND", "CAPABILITY"):
                # Modern clients send these on connect
                client_sock.sendall(b"*0\r\n")
            elif cmd == "SET":
                key = parts[1] if len(parts) > 1 else ""
                value = parts[2] if len(parts) > 2 else ""
                event = log_event(client_ip, REDIS_PORT, "REDIS", "set_attempt",
                                  {"key": key, "value": value[:200]}, connection_id=connection_id)
                if value:
                    save_payload(client_ip, "REDIS", value.encode("utf-8", errors="replace"),
                                 event_id=event.get("rowid"))
                client_sock.sendall(b"+OK\r\n")
            elif cmd == "EVAL":
                script = parts[1] if len(parts) > 1 else ""
                event = log_event(client_ip, REDIS_PORT, "REDIS", "eval_attempt",
                                  {"script": script[:200]}, connection_id=connection_id)
                if script:
                    save_payload(client_ip, "REDIS", script.encode("utf-8", errors="replace"),
                                 event_id=event.get("rowid"))
                client_sock.sendall(b"$-1\r\n")
            elif cmd == "QUIT":
                client_sock.sendall(b"+OK\r\n")
                break
            else:
                # Log unknown commands as potentially malicious
                raw_cmd = " ".join(parts)
                event = log_event(client_ip, REDIS_PORT, "REDIS", "command", {"cmd": raw_cmd},
                                   connection_id=connection_id)
                save_payload(client_ip, "REDIS", raw_cmd.encode("utf-8", errors="replace"),
                             event_id=event.get("rowid"))
                client_sock.sendall(b"+OK\r\n") # Never return -ERR
                
    except Exception:
        # traceback.print_exc()
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        ratelimit.release()

def start_redis_server():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", REDIS_PORT))
            sock.listen(100)
            print(f"[REDIS] Listening on port {REDIS_PORT}")
            while True:
                client, addr = sock.accept()
                if not ratelimit.check_and_acquire(addr[0]):
                    client.close()
                    log_event(addr[0], REDIS_PORT, "REDIS", "rate_limited")
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[REDIS] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
