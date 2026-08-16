import threading
import time
import sqlite3
import requests
from concurrent.futures import ThreadPoolExecutor
from config import DB_PATH, ABUSEIPDB_API_KEY
import risk_score

# Cache: ip -> (score, timestamp)
_cache = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 86400  # 24 hours

# Thread pool for non-blocking lookups
_executor = ThreadPoolExecutor(max_workers=4)

def _update_db(rowid, score):
    """Updates abuse_score for a specific event row, then recomputes risk_score now
    that the AbuseIPDB component of it is actually known (it was 0/unscored on that
    axis at insert time, since this lookup is async and only fires for a subset of
    event types — see enrich_event())."""
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            with conn:
                conn.execute("UPDATE events SET abuse_score = ? WHERE id = ?", (score, rowid))
            row = conn.execute(
                "SELECT ip, event_type FROM events WHERE id = ?", (rowid,)
            ).fetchone()
            if row:
                risk_score.score_and_store(rowid, row[0], row[1], conn=conn)
                conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[ThreatIntel] DB update failed: {e}")

def _lookup_task(ip, rowid):
    """Worker task to call AbuseIPDB and update DB."""
    if not ABUSEIPDB_API_KEY:
        return

    # Check cache
    now = time.time()
    with _cache_lock:
        if ip in _cache:
            score, ts = _cache[ip]
            if now - ts < _CACHE_TTL:
                _update_db(rowid, score)
                return

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        
        response = requests.get(url, params=params, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            score = data["data"]["abuseConfidenceScore"]
            
            # Update cache
            with _cache_lock:
                _cache[ip] = (score, now)
            
            _update_db(rowid, score)
        elif response.status_code == 429:
            print("[ThreatIntel] Rate limit hit (429)")
            # Could implement a backoff here
        else:
            print(f"[ThreatIntel] API returned {response.status_code}")
    except Exception as e:
        print(f"[ThreatIntel] Lookup failed for {ip}: {e}")

def enrich_event(event_dict):
    """Callback for logger to enrich high-value events."""
    if not ABUSEIPDB_API_KEY:
        return

    # Only enrich high-signal events to save quota. Widened from just
    # credential/download_attempt: exec_attempt/eval_attempt/set_attempt are active
    # code-execution attempts and arguably more severe than either of those.
    if event_dict["event_type"] not in (
        "credential", "download_attempt", "exec_attempt", "eval_attempt", "set_attempt",
    ):
        return

    rowid = event_dict.get("rowid")
    ip = event_dict.get("ip")
    if not rowid or not ip:
        return

    # Don't lookup private IPs
    if ip.startswith(("10.", "192.168.", "127.", "172.16.")):
        return

    _executor.submit(_lookup_task, ip, rowid)
