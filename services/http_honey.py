import socket
import threading
import time
import traceback
from datetime import datetime, timezone
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import HTTP_PORT, HTTP_SERVER_HEADER

_FAKE_HTML = b"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Apache2 Ubuntu Default Page</title></head>
<body>
<h1>Apache2 Ubuntu Default Page</h1>
<p>It works!</p>
<p>This is the default welcome page used to test the correct operation of the Apache2 server
after installation on Ubuntu systems. It is based on the equivalent page on Debian.</p>
</body>
</html>"""

_MAX_HEADER_BYTES = 16384  # 16 KB ceiling for request headers


def _build_response(status="200 OK", body=_FAKE_HTML, content_type="text/html"):
    date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    header = (
        f"HTTP/1.1 {status}\r\n"
        f"Server: {HTTP_SERVER_HEADER}\r\n"
        f"Date: {date}\r\n"
        f"Content-Type: {content_type}; charset=UTF-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    return header + body


def _handle_client(client_sock, client_addr):
    client_ip = client_addr[0]
    try:
        log_event(client_ip, HTTP_PORT, "HTTP", "connect")
        # HTTP connect alerts suppressed intentionally — scanners generate extreme volume

        client_sock.settimeout(30)

        # Read until we have a complete HTTP header block (\r\n\r\n).
        # A single recv() may not contain the full headers if TCP splits the data.
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = client_sock.recv(4096)
            if not chunk:
                return
            raw += chunk
            if len(raw) > _MAX_HEADER_BYTES:
                break  # Oversized request — log what we have and respond

        raw_str = raw.decode("utf-8", errors="ignore")
        lines = raw_str.split("\r\n")
        request_line = lines[0] if lines else ""

        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k] = v

        parts = raw_str.split("\r\n\r\n", 1)
        body = parts[1] if len(parts) > 1 else ""

        log_event(client_ip, HTTP_PORT, "HTTP", "request", {
            "request": request_line,
            "user_agent": headers.get("User-Agent", ""),
            "host": headers.get("Host", ""),
            "body": body[:512],
        })
        send_alert("HTTP", client_ip, f"Request: `{request_line}`", alert_type="connect")

        client_sock.sendall(_build_response())
    except Exception:
        traceback.print_exc()
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        ratelimit.release()


def start_http_server():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", HTTP_PORT))
            sock.listen(100)
            print(f"[HTTP] Listening on port {HTTP_PORT}")
            while True:
                client, addr = sock.accept()
                if not ratelimit.check_and_acquire(addr[0]):
                    client.close()
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[HTTP] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
