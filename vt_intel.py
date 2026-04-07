import atexit
import threading
import requests
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from config import DB_PATH, VIRUSTOTAL_API_KEY

_executor = ThreadPoolExecutor(max_workers=2)
atexit.register(_executor.shutdown, wait=False)
_cache = {}
_cache_lock = threading.Lock()

def _update_payload_vt(payload_id, score_str):
    try:
        conn = sqlite3.connect(DB_PATH)
        with conn:
            conn.execute("UPDATE payloads SET vt_score = ? WHERE id = ?", (score_str, payload_id))
        conn.close()
    except Exception as e:
        print(f"[VTIntel] DB update failed: {e}")

def _vt_lookup_task(sha256, payload_id):
    if not VIRUSTOTAL_API_KEY:
        return

    with _cache_lock:
        if sha256 in _cache:
            _update_payload_vt(payload_id, _cache[sha256])
            return

    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            score_str = f"{malicious}/{total}"
            
            with _cache_lock:
                _cache[sha256] = score_str
            
            _update_payload_vt(payload_id, score_str)
        elif response.status_code == 404:
            # File never seen by VT
            _update_payload_vt(payload_id, "0/0 (New)")
        else:
            print(f"[VTIntel] VT API returned {response.status_code}")
    except Exception as e:
        print(f"[VTIntel] Lookup failed for {sha256}: {e}")

def enrich_payload(payload_id, sha256):
    if not VIRUSTOTAL_API_KEY or not sha256:
        return
    _executor.submit(_vt_lookup_task, sha256, payload_id)
