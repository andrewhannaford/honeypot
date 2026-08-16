import os

_OFF = frozenset({"0", "false", "no", "off"})


def _env_bool(name, default=True):
    """True unless env is set to 0/false/no/off (when default True)."""
    fallback = "1" if default else "0"
    return os.environ.get(name, fallback).strip().lower() not in _OFF


def _positive_int(name, default):
    raw = os.environ.get(name, str(default)).strip()
    try:
        v = int(raw)
        return v if v >= 0 else default
    except ValueError:
        return default


def _env_float(name, default):
    try:
        return float(os.environ.get(name, str(default)).strip())
    except ValueError:
        return float(default)


# Service ports
SSH_PORT = 22
HTTP_PORT = 80
FTP_PORT = 21
TELNET_PORT = 23
SMTP_PORT = 25
REDIS_PORT = 6379
MYSQL_PORT = 3306
POSTGRES_PORT = 5432
DASHBOARD_PORT = 8080

# HTTPS trap. Port 443 is not necessarily available on every deployment's public IP
# (a reverse proxy may already own the WAN side), so the trap binds locally on
# HTTPS_PORT and gets published on whatever WAN port your setup forwards to it.
HTTPS_PORT = _positive_int("HTTPS_PORT", 8443)
HTTPS_CERT_CN = os.environ.get("HTTPS_CERT_CN", "web-prod-01.internal")

# Reverse proxies whose X-Forwarded-For we trust. If phantom-host / reverse-proxied
# traffic reaches the HTTP trap through something like Traefik or nginx, without this
# every proxied attacker is logged as the proxy's own IP and geo/abuse enrichment is
# useless. Only honoured when the DIRECT peer is in this set, so a direct attacker
# cannot spoof their IP by sending a fake XFF header. Empty by default — set this to
# your reverse proxy's IP(s) if you put one in front of the honeypot.
TRUSTED_PROXIES = set(
    p.strip() for p in os.environ.get("TRUSTED_PROXIES", "").split(",") if p.strip()
)

# Banners for the database traps. Pick versions old enough to look neglected and
# worth attacking, but not so old they read as obviously fake.
MYSQL_VERSION = os.environ.get("MYSQL_VERSION", "5.7.44-log")
POSTGRES_VERSION = os.environ.get("POSTGRES_VERSION", "13.11")

# Logging
LOG_DIR = "logs"
DATA_DIR = "data"           # persisted Docker volume — holds DB and SSH key
DB_PATH = "data/honeypot.db"

# The Discord webhook URL deliberately does not live here.
#
# A honeypot is designed to be compromised, so by default it should make no outbound
# HTTPS calls and hold no webhook secret of its own. alerts/discord.py queues
# formatted alerts into a local `alert_outbox` table instead of calling Discord
# directly; something on your trusted network (not this host) should poll
# /api/alerts/pending, deliver them, and POST /api/alerts/ack. See README.md.
#
# Max rows kept in alert_outbox. If nothing is draining it, oldest alerts are dropped
# rather than letting the table grow without bound.
ALERT_OUTBOX_MAX = _positive_int("ALERT_OUTBOX_MAX", 5000)

# Shared token guarding the outbox endpoints on the dashboard. Empty = those endpoints
# refuse every request (fail closed).
OUTBOX_TOKEN = os.environ.get("OUTBOX_TOKEN", "")

# AbuseIPDB API key — set via environment variable
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# VirusTotal API key for payload analysis
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

# Alert toggles (env: 1/true vs 0/false/no/off)
ALERT_ON_CONNECT = _env_bool("ALERT_ON_CONNECT", True)
ALERT_ON_CREDENTIAL = _env_bool("ALERT_ON_CREDENTIAL", True)
ALERT_ON_EXEC = _env_bool("ALERT_ON_EXEC", True)
ALERT_ON_DOWNLOAD = _env_bool("ALERT_ON_DOWNLOAD", True)

# Discord: min seconds between alerts for the same IP + alert type (invalid → 60)
DISCORD_ALERT_COOLDOWN = _positive_int("DISCORD_ALERT_COOLDOWN", 60)

# "Victim" coordinates for attack-map arcs (honeypot server location)
def _resolve_server_coords():
    """Return (lat, lon) from env vars if set, else auto-detect via public IP geo-lookup.

    Deployments that don't want this host making an outbound call on startup (or don't
    want their real location on the map) should always set SERVER_LAT/SERVER_LON
    explicitly — then this function never reaches the ipinfo.io lookup below.
    """
    lat_env = os.environ.get("SERVER_LAT", "").strip()
    lon_env = os.environ.get("SERVER_LON", "").strip()
    if lat_env and lon_env:
        try:
            return float(lat_env), float(lon_env)
        except ValueError:
            pass
    try:
        import urllib.request, json
        with urllib.request.urlopen("https://ipinfo.io/json", timeout=5) as resp:
            data = json.loads(resp.read().decode())
        loc = data.get("loc", "")  # "lat,lon"
        if loc:
            lat, lon = map(float, loc.split(","))
            print(f"[*] Server location auto-detected: {lat}, {lon} (IP: {data.get('ip', '?')})")
            return lat, lon
        print(f"[!] ipinfo.io returned no loc field: {data}")
    except Exception as e:
        print(f"[!] Server location auto-detect failed: {e}")
    return 51.5074, -0.1278  # fallback: London

SERVER_LAT, SERVER_LON = _resolve_server_coords()

# Rate limiting
MAX_CONCURRENT_CONNECTIONS = 200   # global cap across all services
RATE_LIMIT_WINDOW = 60             # seconds per window
RATE_LIMIT_MAX_PER_IP = 20         # max new connections per IP per window

# Lure rates (1-in-N logins are accepted)
SSH_ACCEPT_RATE = _positive_int("SSH_ACCEPT_RATE", 5)
TELNET_ACCEPT_RATE = _positive_int("TELNET_ACCEPT_RATE", 3)

# Banners shown to attackers (mimic real services)
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
FTP_BANNER = "220 (vsFTPd 3.0.5)"
TELNET_BANNER = "Ubuntu 22.04.3 LTS"
HTTP_SERVER_HEADER = "Apache/2.4.41 (Ubuntu)"
