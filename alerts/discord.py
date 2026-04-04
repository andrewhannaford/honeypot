import sys
import threading
import requests
from datetime import datetime, timezone
from config import DISCORD_WEBHOOK_URL, ALERT_ON_CONNECT, ALERT_ON_CREDENTIAL


def _post(payload):
    try:
        r = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        if not r.ok:
            print(f"[Discord] Webhook returned {r.status_code}: {r.text[:200]}", file=sys.stderr)
    except Exception as e:
        print(f"[Discord] Failed to send alert: {e}", file=sys.stderr)


def send_alert(service, ip, message, alert_type="connect"):
    """Send a Discord alert.

    alert_type: "connect" | "credential"
    The explicit parameter replaces fragile string-matching on the message text.
    """
    if not DISCORD_WEBHOOK_URL:
        return
    if alert_type == "credential" and not ALERT_ON_CREDENTIAL:
        return
    if alert_type == "connect" and not ALERT_ON_CONNECT:
        return

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

    # Fire in a background thread so service handlers are never blocked by Discord latency
    threading.Thread(target=_post, args=(payload,), daemon=True).start()
