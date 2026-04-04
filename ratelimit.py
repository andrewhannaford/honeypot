import threading
import time
from collections import defaultdict

_lock = threading.Lock()
_ip_timestamps = defaultdict(list)
_active_count = 0

_max_concurrent = 200
_rate_window = 60
_rate_max = 20


def configure(max_concurrent, rate_window, rate_max):
    global _max_concurrent, _rate_window, _rate_max
    _max_concurrent = max_concurrent
    _rate_window = rate_window
    _rate_max = rate_max


_PRUNE_INTERVAL = 300  # prune stale IP entries every 5 minutes
_last_prune = time.monotonic()


def _prune_stale_entries(now):
    """Remove expired timestamp lists for IPs that are no longer active.
    Must be called with _lock held."""
    global _last_prune
    if now - _last_prune < _PRUNE_INTERVAL:
        return
    _last_prune = now
    stale = [ip for ip, ts in _ip_timestamps.items()
             if not any(now - t < _rate_window for t in ts)]
    for ip in stale:
        del _ip_timestamps[ip]


def check_and_acquire(ip):
    """Return True and increment the active counter if the connection is allowed.
    Return False (and do NOT increment) if the IP is rate-limited or the global
    cap is reached — the caller must close the socket without spawning a thread."""
    global _active_count
    now = time.monotonic()
    with _lock:
        _prune_stale_entries(now)
        if _active_count >= _max_concurrent:
            return False
        _ip_timestamps[ip] = [t for t in _ip_timestamps[ip] if now - t < _rate_window]
        if len(_ip_timestamps[ip]) >= _rate_max:
            return False
        _ip_timestamps[ip].append(now)
        _active_count += 1
        return True


def release():
    """Must be called exactly once per successful check_and_acquire, in a finally block."""
    global _active_count
    with _lock:
        _active_count -= 1
