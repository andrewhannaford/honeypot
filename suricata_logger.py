import json
import sqlite3
import threading
import time
import os
from config import DB_PATH

EVE_JSON_PATH = "logs/suricata/eve.json"

def _ingest_eve():
    if not os.path.exists(EVE_JSON_PATH):
        # Create empty log file if missing
        os.makedirs(os.path.dirname(EVE_JSON_PATH), exist_ok=True)
        with open(EVE_JSON_PATH, 'w') as f:
            pass

    with open(EVE_JSON_PATH, "r") as f:
        # Seek to end
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            
            try:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    _save_alert(data)
            except Exception as e:
                print(f"[SuricataLogger] Error: {e}")

def _save_alert(data):
    alert = data.get("alert", {})
    timestamp = data.get("timestamp")
    src_ip = data.get("src_ip")
    src_port = data.get("src_port")
    dst_port = data.get("dest_port")
    proto = data.get("proto")
    alert_sig = alert.get("signature")
    category = alert.get("category")
    severity = alert.get("severity")
    raw = json.dumps(data)
    
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """INSERT INTO suricata_alerts (timestamp, src_ip, src_port, dst_port, proto, alert_sig, category, severity, raw)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, src_ip, src_port, dst_port, proto, alert_sig, category, severity, raw)
        )
        conn.commit()
    finally:
        conn.close()

def start_suricata_logger():
    t = threading.Thread(target=_ingest_eve, daemon=True)
    t.start()
    print("[*] Suricata log ingestion started")
