import threading
import sys
import signal
from logger import init_db
from services.ssh_honey import start_ssh_server
from services.http_honey import start_http_server
from services.ftp_honey import start_ftp_server
from services.telnet_honey import start_telnet_server
from dashboard.app import start_dashboard
from config import (
    DASHBOARD_PORT,
    MAX_CONCURRENT_CONNECTIONS,
    RATE_LIMIT_WINDOW,
    RATE_LIMIT_MAX_PER_IP,
)
import ratelimit

SERVICES = [
    ("SSH",       start_ssh_server),
    ("HTTP",      start_http_server),
    ("FTP",       start_ftp_server),
    ("TELNET",    start_telnet_server),
    ("Dashboard", start_dashboard),
]


def _handle_sigterm(signum, frame):
    print("\n[*] Received SIGTERM — shutting down.")
    sys.exit(0)


def main():
    signal.signal(signal.SIGTERM, _handle_sigterm)

    print("=" * 50)
    print("  Honeypot starting up")
    print("=" * 50)

    # Initialise DB before any service thread can call log_event
    init_db()

    # Configure rate limiter
    ratelimit.configure(MAX_CONCURRENT_CONNECTIONS, RATE_LIMIT_WINDOW, RATE_LIMIT_MAX_PER_IP)

    threads = []
    for name, func in SERVICES:
        t = threading.Thread(target=func, name=name, daemon=True)
        t.start()
        threads.append(t)

    print(f"\n  Dashboard: http://0.0.0.0:{DASHBOARD_PORT}")
    print("  Press Ctrl+C to stop.\n")

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot.")
        sys.exit(0)


if __name__ == "__main__":
    main()
