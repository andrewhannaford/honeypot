import threading
import time
from services.ssh_honey import start_ssh_server
from services.http_honey import start_http_server
from services.ftp_honey import start_ftp_server
from services.telnet_honey import start_telnet_server
from services.smtp_honey import start_smtp_server
from services.redis_honey import start_redis_server
from dashboard.app import start_dashboard
from logger import init_db, register_event_callback
from threat_intel import enrich_event

SERVICES = [
    ("SSH", start_ssh_server),
    ("HTTP", start_http_server),
    ("FTP", start_ftp_server),
    ("TELNET", start_telnet_server),
    ("SMTP", start_smtp_server),
    ("REDIS", start_redis_server),
    ("Dashboard", start_dashboard),
]

def main():
    print("--- Starting Honeypot ---")
    init_db()
    
    # Register Threat Intel callback
    register_event_callback(enrich_event)
    
    threads = []
    for name, func in SERVICES:
        t = threading.Thread(target=func, name=name, daemon=True)
        t.start()
        threads.append(t)
        print(f"[*] {name} service started")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n--- Stopping Honeypot ---")

if __name__ == "__main__":
    main()
