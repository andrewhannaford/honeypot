import socket
import threading
import time
import traceback
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import REDIS_PORT

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
            num_elements = int(line[1:])
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
                data = sock.recv(bulk_len)
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
    try:
        log_event(client_ip, REDIS_PORT, "REDIS", "connect")
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
                log_event(client_ip, REDIS_PORT, "REDIS", "credential", {"password": password})
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
                client_sock.sendall(b"*0\r\n") # Empty array
            elif cmd == "KEYS":
                client_sock.sendall(b"*0\r\n")
            elif cmd == "DBSIZE":
                client_sock.sendall(b":0\r\n")
            elif cmd == "SELECT":
                client_sock.sendall(b"+OK\r\n")
            elif cmd in ("COMMAND", "CAPABILITY"):
                # Modern clients send these on connect
                client_sock.sendall(b"*0\r\n")
            elif cmd == "QUIT":
                client_sock.sendall(b"+OK\r\n")
                break
            else:
                # Log unknown commands as potentially malicious
                log_event(client_ip, REDIS_PORT, "REDIS", "command", {"cmd": " ".join(parts)})
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
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[REDIS] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
