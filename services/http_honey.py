import socket
import threading
import time
import traceback
import urllib.parse
from datetime import datetime, timezone
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import HTTP_PORT, HTTP_SERVER_HEADER, TRUSTED_PROXIES

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

# Bait for the paths that actually get probed here, ranked from Traefik's access log:
# /sdk (626 hits), /.env (106), /.git/config (90), /.aws/credentials (35),
# /config.json (33), /actuator/env (27), /.vscode/sftp.json (24).
#
# Every credential below is a deliberate canary: AWS's documented EXAMPLE keys, or
# passwords carrying a marker string. They authenticate nothing — but if one ever shows
# up in a log or a breach dump, it can only have come from this honeypot.
_CANARY = "hp7f3a"

_FAKE_GIT_CONFIG = f"""[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://deploy-bot:gh0st_{_CANARY}_tok3n@github.com/internal-ops/billing-api.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
""".encode()

_FAKE_AWS_CREDENTIALS = f"""[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[deploy]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
region = us-west-2
""".encode()

_FAKE_CONFIG_JSON = f"""{{
  "environment": "production",
  "database": {{
    "host": "10.0.4.19",
    "port": 5432,
    "name": "billing",
    "user": "svc_billing",
    "password": "Wint3r_{_CANARY}_2024!"
  }},
  "redis": {{ "host": "10.0.4.22", "port": 6379, "password": "r3dis_{_CANARY}" }},
  "jwt_secret": "eyJhbGciOiJIUzI1NiJ9.{_CANARY}.s1gn1ng_k3y",
  "smtp": {{ "host": "smtp.internal", "user": "noreply@internal", "password": "M@il_{_CANARY}" }}
}}""".encode()

_FAKE_SFTP_JSON = f"""{{
  "name": "prod-web",
  "host": "10.0.4.31",
  "protocol": "sftp",
  "port": 22,
  "username": "deploy",
  "password": "Depl0y_{_CANARY}_2024",
  "remotePath": "/var/www/html",
  "uploadOnSave": true
}}""".encode()

_FAKE_ACTUATOR_ENV = f"""{{
  "activeProfiles": ["production"],
  "propertySources": [
    {{
      "name": "systemEnvironment",
      "properties": {{
        "SPRING_DATASOURCE_URL": {{ "value": "jdbc:postgresql://10.0.4.19:5432/billing" }},
        "SPRING_DATASOURCE_USERNAME": {{ "value": "svc_billing" }},
        "SPRING_DATASOURCE_PASSWORD": {{ "value": "Spr1ng_{_CANARY}_db" }},
        "JWT_SIGNING_KEY": {{ "value": "{_CANARY}-signing-key-prod" }}
      }}
    }}
  ]
}}""".encode()

# /sdk is the single most-probed path here — vSphere/ESXi reconnaissance. Answering with
# a plausible SOAP fault keeps the scanner engaged instead of moving on immediately.
_FAKE_VSPHERE_SDK = b"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body>
<soapenv:Fault>
<faulttring>Operation not supported: expecting a SOAP request</faulttring>
<detail><NotSupportedFault xmlns="urn:vim25" xsi:type="NotSupported"/></detail>
</soapenv:Fault>
</soapenv:Body>
</soapenv:Envelope>"""

_FAKE_PHPINFO = b"""<!DOCTYPE html><html><head><title>phpinfo()</title></head>
<body><h1>PHP Version 7.4.33</h1>
<table><tr><td>System</td><td>Linux web-prod-01 5.15.0-76-generic x86_64</td></tr>
<tr><td>Server API</td><td>FPM/FastCGI</td></tr>
<tr><td>Loaded Configuration File</td><td>/etc/php/7.4/fpm/php.ini</td></tr>
<tr><td>disable_functions</td><td><i>no value</i></td></tr>
</table></body></html>"""

# path -> (body, content_type). Keys are lowercase and have any trailing slash stripped,
# matching how the request path is normalised below.
_BAIT_PATHS = {
    "/.git/config": (_FAKE_GIT_CONFIG, "text/plain"),
    "/.git/head": (b"ref: refs/heads/main\n", "text/plain"),
    "/.aws/credentials": (_FAKE_AWS_CREDENTIALS, "text/plain"),
    "/config.json": (_FAKE_CONFIG_JSON, "application/json"),
    "/api/.env": (_FAKE_ENV, "text/plain"),
    "/.vscode/sftp.json": (_FAKE_SFTP_JSON, "application/json"),
    "/actuator/env": (_FAKE_ACTUATOR_ENV, "application/json"),
    "/sdk": (_FAKE_VSPHERE_SDK, "text/xml"),
    "/info.php": (_FAKE_PHPINFO, "text/html"),
    "/phpinfo.php": (_FAKE_PHPINFO, "text/html"),
}

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


def _handle_client(client_sock, client_addr, port=HTTP_PORT, service="HTTP"):
    """Shared by the plaintext and TLS listeners — https_honey.py hands us an
    already-wrapped socket, so everything below is identical either way."""
    client_ip = client_addr[0]
    try:
        # Skip the connect log for trusted-proxy peers: the real per-request event that
        # follows carries the true X-Forwarded-For client, so logging the proxy here would
        # just pollute the source-IP stats with Traefik's address.
        if client_ip not in TRUSTED_PROXIES:
            log_event(client_ip, port, service, "connect")
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
                headers[k.lower()] = v

        body_pos = raw_str.find("\r\n\r\n")
        body = raw_str[body_pos+4:] if body_pos != -1 else ""

        # If the direct peer is a trusted reverse proxy (Traefik fronting the phantom
        # hosts), the REAL attacker IP is in X-Forwarded-For — take the left-most entry.
        # Only trusted when the peer is a known proxy, so a direct attacker cannot spoof
        # their IP with a forged header.
        proxy_ip = None
        if client_ip in TRUSTED_PROXIES:
            fwd = headers.get("x-forwarded-for") or headers.get("x-real-ip") or ""
            real = fwd.split(",")[0].strip()
            if real:
                proxy_ip, client_ip = client_ip, real

        # Common metadata on every trap event: the Host header tells us WHICH (phantom)
        # hostname a probe targeted — the key signal once Traefik routes junk subdomains
        # here — and the User-Agent fingerprints the scanner.
        meta = {
            "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", ""),
        }
        if proxy_ip:
            meta["via_proxy"] = proxy_ip

        # Dispatch traps
        if path == "/wp-login.php":
            if method.upper() == "POST":
                # Extract credentials
                params = urllib.parse.parse_qs(body)
                user = params.get("log", [""])[0]
                pw = params.get("pwd", [""])[0]
                log_event(client_ip, port, service, "credential", {**meta, "username": user, "password": pw, "path": path})
                send_alert(service, client_ip, f"Login (WP): `{user}` / `{pw}`", alert_type="credential")
                client_sock.sendall(_build_response(status="200 OK", body=b"Login failed"))
            else:
                log_event(client_ip, port, service, "trap_hit", {**meta, "path": path})
                client_sock.sendall(_build_response(status="200 OK", body=_WP_LOGIN_FORM))
        elif path == "/wp-admin":
            log_event(client_ip, port, service, "trap_hit", {**meta, "path": path})
            client_sock.sendall(_build_response(status="301 Moved Permanently", body=b"", location="/wp-login.php"))
        elif path == "/.env":
            log_event(client_ip, port, service, "trap_hit", {**meta, "path": path})
            client_sock.sendall(_build_response(status="200 OK", body=_FAKE_ENV, content_type="text/plain"))
        elif path in _BAIT_PATHS:
            # Serving a canary file is the highest-signal event here: it means the
            # attacker asked for a credential store by name, not just crawled the site.
            payload, ctype = _BAIT_PATHS[path]
            log_event(client_ip, port, service, "trap_hit", {**meta, "path": path})
            send_alert(service, client_ip, f"Canary served: `{path}`", alert_type="exec_attempt")
            client_sock.sendall(_build_response(status="200 OK", body=payload, content_type=ctype))
        else:
            # Default response
            log_event(client_ip, port, service, "request", {
                **meta,
                "method": method,
                "path": full_path,
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
                    log_event(addr[0], HTTP_PORT, "HTTP", "rate_limited")
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[HTTP] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
