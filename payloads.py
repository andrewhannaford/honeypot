import os
import hashlib
import sqlite3
import datetime
from config import DB_PATH, DATA_DIR
from vt_intel import enrich_payload

PAYLOAD_DIR = os.path.join(DATA_DIR, "payloads")
os.makedirs(PAYLOAD_DIR, exist_ok=True)

def save_payload(ip, service, data, filename=None, event_id=None):
    """
    Saves binary data as a payload file and logs it to the DB.
    Returns the payload record ID.
    """
    if not data:
        return None

    # Use SHA256 of data as filename if not provided to avoid duplicates
    sha256_hash = hashlib.sha256(data).hexdigest()
    md5_hash = hashlib.md5(data).hexdigest()
    
    if not filename:
        filename = sha256_hash[:16]

    local_filename = f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
    local_path = os.path.join(PAYLOAD_DIR, local_filename)
    
    # Save file
    with open(local_path, "wb") as f:
        f.write(data)
        
    # Attempt to get MIME type
    mime_type = "application/octet-stream"
    try:
        import magic
        mime_type = magic.from_buffer(data, mime=True)
    except Exception:
        pass

    # Log to DB
    conn = sqlite3.connect(DB_PATH)
    try:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO payloads (timestamp, event_id, ip, service, filename, local_path, file_size, md5, sha256, mime_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, event_id, ip, service, filename, local_path, len(data), md5_hash, sha256_hash, mime_type))
        conn.commit()
        payload_id = cur.lastrowid
        
        # Trigger VT lookup
        enrich_payload(payload_id, sha256_hash)
        
        return payload_id
    finally:
        conn.close()
