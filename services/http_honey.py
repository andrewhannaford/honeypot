import socket
import threading
import time
import traceback
import urllib.parse
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

_WP_LOGIN_FORM = b"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Log In &lsaquo; WordPress</title></head>
<body class="login">
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
    <p><label for="user_login">Username or Email Address<br />
    <input type="text" name="log" id="user_login" class="input" value="" size="20" /></label></p>
    <p><label for="user_pass">Password<br />
    <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" /></label></p>
    <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary" value="Log In" /></p>
</form>
</div>
</body>
</html>"""

_FAKE_ENV = b"""APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:7p+N9p8Sj7Xk4f6R8d2G6H4J2L5N8P0R2T4V6X8Z0B2=
APP_DEBUG=false
APP_URL=http://localhost

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=forge
DB_USERNAME=forge
DB_PASSWORD=secret_password_123

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

_MAX_HEADER_BYTES = 16384  # 16 KB ceiling for request headers


def _build_response(status="200 OK", body=_FAKE_HTML, content_type="text/html", location=None):
    date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    header_lines = [
        f"HTTP/1.1 {status}",
        f"Server: {HTTP_SERVER_HEADER}",
        f"Date: {date}",
        f"Content-Type: {content_type}; charset=UTF-8",
        f"Content-Length: {len(body)}",
        f"Connection: close",
    ]
    if location:
        header_lines.append(f"Location: {location}")
    
    header = ("\r\n".join(header_lines) + "\r\n\r\n").encode()
    return header + body


def _handle_client(client_sock, client_addr):
    client_ip = client_addr[0]
    try:
        log_event(client_ip, HTTP_PORT, "HTTP", "connect")
        client_sock.settimeout(30)

        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = client_sock.recv(4096)
            if not chunk:
                return
            raw += chunk
            if len(raw) > _MAX_HEADER_BYTES:
                break

        raw_str = raw.decode("utf-8", errors="ignore")
        lines = raw_str.split("\r\n")
        request_line = lines[0] if lines else ""
        if not request_line:
            return

        method, full_path, _ = (request_line + "   ").split(" ", 2)
        
        # Normalize path
        parsed_url = urllib.parse.urlparse(full_path)
        path = parsed_url.path.lower().rstrip("/")
        if not path:
            path = "/"

        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k] = v

        body_pos = raw_str.find("\r\n\r\n")
        body = raw_str[body_pos+4:] if body_pos != -1 else ""

        # Dispatch traps
        if path == "/wp-login.php":
            if method.upper() == "POST":
                # Extract credentials
                params = urllib.parse.parse_qs(body)
                user = params.get("log", [""])[0]
                pw = params.get("pwd", [""])[0]
                log_event(client_ip, HTTP_PORT, "HTTP", "credential", {"username": user, "password": pw, "path": path})
                send_alert("HTTP", client_ip, f"Login (WP): `{user}` / `{pw}`", alert_type="credential")
                client_sock.sendall(_build_response(status="200 OK", body=b"Login failed"))
            else:
                log_event(client_ip, HTTP_PORT, "HTTP", "trap_hit", {"path": path})
                client_sock.sendall(_build_response(status="200 OK", body=_WP_LOGIN_FORM))
        elif path == "/wp-admin":
            log_event(client_ip, HTTP_PORT, "HTTP", "trap_hit", {"path": path})
            client_sock.sendall(_build_response(status="301 Moved Permanently", body=b"", location="/wp-login.php"))
        elif path == "/.env":
            log_event(client_ip, HTTP_PORT, "HTTP", "trap_hit", {"path": path})
            client_sock.sendall(_build_response(status="200 OK", body=_FAKE_ENV, content_type="text/plain"))
        else:
            # Default response
            log_event(client_ip, HTTP_PORT, "HTTP", "request", {
                "method": method,
                "path": full_path,
                "user_agent": headers.get("User-Agent", ""),
                "host": headers.get("Host", ""),
                "body": body[:512],
            })
            # No alert for standard requests to avoid flooding
            client_sock.sendall(_build_response())

    except Exception:
        # traceback.print_exc()
        pass
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
