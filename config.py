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
DASHBOARD_PORT = 8080

# Logging
LOG_DIR = "logs"
DATA_DIR = "data"           # persisted Docker volume — holds DB and SSH key
DB_PATH = "data/honeypot.db"

# Discord webhook URL — set via environment variable or paste directly
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")

# AbuseIPDB API key — set via environment variable
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# Gemini API key for LLM-enhanced fake shell
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# VirusTotal API key for payload analysis
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

# Alert toggles (env: 1/true vs 0/false/no/off)
ALERT_ON_CONNECT = _env_bool("ALERT_ON_CONNECT", True)
ALERT_ON_CREDENTIAL = _env_bool("ALERT_ON_CREDENTIAL", True)
ALERT_ON_EXEC = _env_bool("ALERT_ON_EXEC", True)
ALERT_ON_DOWNLOAD = _env_bool("ALERT_ON_DOWNLOAD", True)

# Discord: min seconds between alerts for the same IP + alert type (invalid → 60)
DISCORD_ALERT_COOLDOWN = _positive_int("DISCORD_ALERT_COOLDOWN", 60)

# “Victim” coordinates for attack-map arcs (honeypot server location)
SERVER_LAT = _env_float("SERVER_LAT", 51.5074)
SERVER_LON = _env_float("SERVER_LON", -0.1278)

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
