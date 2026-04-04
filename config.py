import os

# Service ports
SSH_PORT = 22
HTTP_PORT = 80
FTP_PORT = 21
TELNET_PORT = 23
DASHBOARD_PORT = 8080

# Logging
LOG_DIR = "logs"
DATA_DIR = "data"           # persisted Docker volume — holds DB and SSH key
DB_PATH = "data/honeypot.db"

# Discord webhook URL — set via environment variable or paste directly
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")

# Alert toggles
ALERT_ON_CONNECT = True
ALERT_ON_CREDENTIAL = True

# Rate limiting
MAX_CONCURRENT_CONNECTIONS = 200   # global cap across all services
RATE_LIMIT_WINDOW = 60             # seconds per window
RATE_LIMIT_MAX_PER_IP = 20         # max new connections per IP per window

# Dashboard authentication token — set via env var or a random one is printed at startup
DASHBOARD_TOKEN = os.environ.get("DASHBOARD_TOKEN", "")

# Banners shown to attackers (mimic real services)
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
FTP_BANNER = "220 (vsFTPd 3.0.5)"
TELNET_BANNER = "Ubuntu 22.04.3 LTS"
HTTP_SERVER_HEADER = "Apache/2.4.41 (Ubuntu)"
