import os

DASHBOARD_BASE_URL = os.environ.get("SANDBOX_DASHBOARD_URL", "http://127.0.0.1:8080")
OUTBOX_TOKEN = os.environ.get("OUTBOX_TOKEN", "")

# Same relative-to-WORKDIR convention as the main honeypot app's config.py, sharing
# the honeypot-data named volume (mounted at /app/data in this container too).
DATA_DIR = "data"
DB_PATH = "data/honeypot.db"
SAMPLES_DIR = os.path.join(DATA_DIR, "sandbox_samples")

# Fetcher limits — deliberately conservative. Nothing here should be tunable by
# anything attacker-influenced; these are fixed operator constants.
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024  # 20 MB — real IoT botnet droppers are tiny
MAX_REDIRECTS = 3
FETCH_CONNECT_TIMEOUT = 8
FETCH_READ_TIMEOUT = 20
# FETCH_READ_TIMEOUT only resets on each chunk received, not a total-response
# deadline — a dropzone trickling bytes just under that gap could otherwise
# hold the fetch open indefinitely. This bounds the whole streaming download.
FETCH_TOTAL_TIMEOUT_SECONDS = 60
ALLOWED_SCHEMES = ("http", "https")
POLL_INTERVAL_SECONDS = 15
WATERMARK_PATH = os.path.join(DATA_DIR, "sandbox_fetcher_watermark")

# Retry sweep: a URL gets exactly one fetch attempt at capture time today, but a
# dropzone that's briefly rate-limiting, momentarily overloaded, or down for a
# few minutes looks identical to a permanently dead one — and 0 of ~1900 recent
# 'failed'/'dns_failed' attempts have ever been retried. Escalating backoff so a
# genuinely dead host doesn't get hammered, and a hard attempt cap so it isn't
# retried forever. 'blocked_ssrf' is deliberately excluded — that's a security
# decision, not a network hiccup, and retrying it changes nothing.
RETRYABLE_STATUSES = ("failed", "dns_failed")
MAX_FETCH_ATTEMPTS_PER_URL = 4          # original attempt + up to 3 retries
RETRY_BACKOFF_MINUTES = (10, 60, 360)   # delay before the 1st/2nd/3rd retry
RETRY_SWEEP_INTERVAL_SECONDS = 300      # how often to look for retry candidates
# Without this, the very first sweep after deploy found 189 candidates going back
# to the pipeline's first day — mostly second-stage-rescan leftovers pointing at
# ordinary third-party sites (Shopify CDN assets, a privacy-policy page, a
# scanning-research site), not malware. Repeatedly re-fetching a stranger's site
# weeks after the one attempt that happened to fail is bad citizenship and burns
# the retry budget on URLs that were never going anywhere. Scope retries to
# failures recent enough that "the dropzone might still come back" is plausible.
RETRY_MAX_AGE_HOURS = 48

# Push-notify: the main honeypot process sends a UDP nudge here the instant it
# captures an event containing a URL, so a fresh capture gets fetched right away
# instead of waiting up to POLL_INTERVAL_SECONDS for the next scheduled poll —
# the dropzone is most likely to still be alive in the seconds right after the
# attacker itself just contacted it. Loopback-only (127.0.0.1): both containers
# run with network_mode: host, so they share the host's actual loopback, and
# this is never exposed off-box regardless of what WAN ports are forwarded.
# The regular poll loop is untouched and still runs on its own schedule — this
# is purely a latency shortcut, not a replacement, so a missed/lost UDP
# datagram (e.g. fetcher mid-restart) just means "no shortcut this time," not
# a missed capture.
NOTIFY_HOST = "127.0.0.1"
NOTIFY_PORT = int(os.environ.get("SANDBOX_NOTIFY_PORT", "8091"))
