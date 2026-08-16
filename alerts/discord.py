import json
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from config import (
    DB_PATH,
    ALERT_OUTBOX_MAX,
    ALERT_ON_CONNECT,
    ALERT_ON_CREDENTIAL,
    ALERT_ON_EXEC,
    ALERT_ON_DOWNLOAD,
    DISCORD_ALERT_COOLDOWN,
)

_ALLOWED_ALERT_TYPES = frozenset(
    {"connect", "credential", "exec_attempt", "download_attempt"}
)
# ip:alert_type -> unix time of last webhook
_cooldown_last_sent = {}
# Bound memory if many unique IPs hit the webhook cooldown map
_COOLDOWN_MAP_MAX = 8000


def _prune_stale_cooldown_entries(now):
    if len(_cooldown_last_sent) < _COOLDOWN_MAP_MAX:
        return
    # Drop entries that cannot affect the next cooldown window
    max_age = max(86400, DISCORD_ALERT_COOLDOWN * 120)
    cutoff = now - max_age
    for k in list(_cooldown_last_sent.keys()):
        if _cooldown_last_sent[k] < cutoff:
            del _cooldown_last_sent[k]


def _post(payload):
    """Queue a formatted alert locally instead of calling Discord directly.

    This host is designed to be compromised, so it holds no webhook secret and makes
    no outbound HTTPS. The forwarder on docker-svc drains `alert_outbox` through the
    dashboard API and posts to Discord from the trusted side.

    Failures are swallowed and logged: an alert is never worth taking a trap down for.
    """
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        try:
            conn.execute(
                "INSERT INTO alert_outbox (created, payload) VALUES (?, ?)",
                (datetime.now(timezone.utc).isoformat(), json.dumps(payload)),
            )
            # Drop oldest first if the forwarder has been down for a long time.
            conn.execute(
                "DELETE FROM alert_outbox WHERE id <= "
                "(SELECT MAX(id) FROM alert_outbox) - ?",
                (ALERT_OUTBOX_MAX,),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[Discord] Failed to queue alert: {e}", file=sys.stderr)


def send_alert(service, ip, message, alert_type="connect"):
    """Queue a Discord alert for the trusted-side forwarder to deliver.

    alert_type: connect | credential | exec_attempt | download_attempt
    Unknown types are dropped. Cooldown applies per (ip, alert_type).

    Alert *policy* (toggles, cooldown, formatting) stays here; only delivery moved.
    There is deliberately no webhook-URL check — that secret lives on docker-svc now,
    and gating on it here would silently suppress every alert.
    """
    if alert_type not in _ALLOWED_ALERT_TYPES:
        print(f"[Discord] Unknown alert_type {alert_type!r} from {service}, dropping alert", file=sys.stderr)
        return
    if alert_type == "credential" and not ALERT_ON_CREDENTIAL:
        return
    if alert_type == "connect" and not ALERT_ON_CONNECT:
        return
    if alert_type == "exec_attempt" and not ALERT_ON_EXEC:
        return
    if alert_type == "download_attempt" and not ALERT_ON_DOWNLOAD:
        return

    key = f"{ip}:{alert_type}"
    now = time.time()
    _prune_stale_cooldown_entries(now)

    last = _cooldown_last_sent.get(key, 0)
    if now - last < DISCORD_ALERT_COOLDOWN:
        return
    _cooldown_last_sent[key] = now

    color = 0xFF4444 if alert_type == "credential" else 0xFFA500

    payload = {
        "embeds": [
            {
                "title": f"\U0001f6a8 Honeypot Alert \u2014 {service}",
                "description": message,
                "color": color,
                "fields": [
                    {"name": "IP Address", "value": f"`{ip}`", "inline": True},
                    {"name": "Service", "value": service, "inline": True},
                    {
                        "name": "Time (UTC)",
                        "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        "inline": False,
                    },
                ],
                "footer": {"text": "Honeypot \u2014 Home Lab"},
            }
        ]
    }

    threading.Thread(target=_post, args=(payload,), daemon=True).start()
