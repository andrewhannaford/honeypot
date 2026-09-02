"""Polls the dashboard for new events and fetches any URL found in them
(through ssrf_guard), storing what lands as a sandbox_samples row + a file
under data/sandbox_samples/.

Scans EVERY event's raw data for embedded URLs, not just event_type ==
'download_attempt'. That classification only exists because fake_shell.py
happens to special-case a line whose first word is literally "wget" or
"curl" — but real attackers routinely bury a download-and-execute payload
inside other event types the honeypot already captures verbatim: Redis
set_attempt/eval_attempt values ("* * * * * curl ...|sh" cron injection is
extremely common), plain command events where wget/curl isn't the first
token (chained/obfuscated commands), etc. Confirmed live against this
honeypot's own data before building this: 331 Redis set_attempt events and
201 command events contained a URL that the old download_attempt-only filter
never saw. Regex-scanning the raw JSON text directly (rather than parsing
each event type's specific field names) means this doesn't need to track
every trap service's schema, and any new trap automatically gets covered.

Every URL we look at gets a sandbox_fetch_attempts row, regardless of outcome
(new content, duplicate content, recognized-URL skip, SSRF-blocked, network
failure, empty response) — that activity log is what makes "what is this thing
actually doing" visible, rather than only ever seeing clean successes.

This is the one piece of the pipeline that makes real outbound connections to
attacker-supplied hosts — kept in its own process/container so that
capability is isolated from the dashboard's own process.
"""

import base64
import datetime
import hashlib
import os
import re
import socket
import threading
import time

import requests

import analyzer
import config
import db
import ssrf_guard

# Same pattern fake_shell.py uses for its own (narrower) detection.
URL_REGEX = re.compile(r"https?://\S+")

# Second-stage re-scan guards (see _process_url). Confirmed live this was a
# real gap, the hard way: a backfill retry against a URL that used to be dead
# turned out to now serve an ordinary WordPress/Shopify storefront's HTML —
# not malware, correctly discarded — but the unbounded re-scan then followed
# every asset link on that ONE page (fonts, CSS, JS, CDN bundles) and stored
# 92 of them as "samples" before this existed. A real stager script (the
# thing this recursion exists to catch) is a small downloader, categorically
# different in size from a rendered webpage — the byte cap alone would have
# prevented the whole incident. The URL-count cap is defense in depth for
# anything that's small but still link-dense.
_SECOND_STAGE_MAX_CONTENT_BYTES = 8192
_SECOND_STAGE_MAX_URLS = 5

# Real Redis cron-injection payloads frequently wrap the actual download
# command in `echo <b64> | base64 -d | bash` to dodge naive string matching —
# confirmed live: 78 of 414 (19%) real set_attempt rows use this pattern,
# roughly comparable in scale to everything caught in plaintext. Only even
# attempted when the literal string "base64" appears, to avoid wastefully
# trying to base64-decode arbitrary text on every single event.
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Bash's /dev/tcp/HOST/PORT pseudo-device is a raw-socket fetch mechanism with
# no http:// substring at all — confirmed live: 3 real payloads use
# `exec 6<>/dev/tcp/host/port && echo -n 'GET ...' >&6 && cat 0<&6` to fetch
# over a raw socket. Best-effort: assumes HTTP, matching what the observed
# payloads actually did.
_DEV_TCP_RE = re.compile(r"/dev/tcp/([\w.-]+)/(\d+)")

# Trailing shell/JSON punctuation that ends up glued to a URL depending on
# where it was captured from — a trailing ';' from a shell command (confirmed
# live: "http://31.77.227.121/satan_x86_64;"), or trailing '"', ']', '}', ','
# from matching inside a raw JSON blob (e.g. ...,"urls":["http://x/y"]} would
# otherwise leave `]}` stuck to the end).
_TRAILING_PUNCT_RE = re.compile(r'[;&|)\]}"\'>,.]+$')


def _extract_urls_from_base64(raw):
    if "base64" not in raw:
        return []
    found = []
    for blob in _BASE64_BLOB_RE.findall(raw):
        padded = blob + "=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
        except Exception:
            continue
        found.extend(URL_REGEX.findall(decoded))
    return found


def _extract_dev_tcp_urls(raw):
    return [f"http://{host}:{port}/" for host, port in _DEV_TCP_RE.findall(raw)]


def _clean_url(raw_url):
    return _TRAILING_PUNCT_RE.sub("", raw_url.strip())


def _load_watermark():
    try:
        with open(config.WATERMARK_PATH) as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def _save_watermark(event_id):
    os.makedirs(os.path.dirname(config.WATERMARK_PATH), exist_ok=True)
    with open(config.WATERMARK_PATH, "w") as f:
        f.write(str(event_id))


def _fetch_events(since_id):
    """Returns ALL events in the batch, not just download_attempt ones — the
    watermark must advance based on everything we looked at, not just what we
    acted on, or a sparse batch (no download_attempt events at all) can never
    move forward. (This bit us for real: 5 hours stuck re-polling one empty
    window before this was fixed.)"""
    resp = requests.get(
        f"{config.DASHBOARD_BASE_URL}/api/events/since",
        params={"id": since_id, "limit": 500},
        headers={"X-Outbox-Token": config.OUTBOX_TOKEN},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


# HTTP request/trap_hit events are excluded from the generic scan: confirmed
# live that this event data includes the User-Agent header verbatim, and
# search-engine/AI-crawler bots routinely put their own policy-page URL in
# their UA string (Amazonbot, GPTBot, PerplexityBot, Googlebot, Bingbot,
# MJ12bot, YandexBot, ...). None of that is attacker-supplied malware — it's
# passive request metadata — and scanning it just fetches random legitimate
# webpages and dilutes the sample list. The validated high-value sources
# (command, set_attempt, eval_attempt, exec_attempt, download_attempt) are all
# event types where the data is something an attacker actually typed/sent as
# code, not passive connection metadata.
_EXCLUDED_EVENT_TYPES = {"request", "trap_hit"}


def _extract_urls(event):
    """Regex-scans the event's raw data text directly rather than parsing a
    specific field — this is what lets one code path cover download_attempt's
    {"urls": [...]}, Redis's {"value": "...curl ...|sh..."}, plain command
    events, and anything else, uniformly. Also tries the base64-wrapped and
    /dev/tcp raw-socket variants, both confirmed present in real traffic."""
    if event.get("event_type") in _EXCLUDED_EVENT_TYPES:
        return []
    raw = event.get("data") or ""
    urls = [_clean_url(u) for u in URL_REGEX.findall(raw) if u]
    urls += [_clean_url(u) for u in _extract_urls_from_base64(raw) if u]
    urls += _extract_dev_tcp_urls(raw)
    return urls


def _process_url(url, event, depth=0):
    start = time.time()
    source_event_id = event["id"]
    source_ip = event.get("ip")

    def record(status, error=None, sample_id=None):
        duration_ms = int((time.time() - start) * 1000)
        db.insert_fetch_attempt(url, source_event_id, source_ip, status, error, sample_id, duration_ms)

    known_sample_id = db.find_sample_id_for_known_url(url)
    if known_sample_id is not None:
        print(f"[fetcher] dedup_url: {url!r} already known -> sample {known_sample_id}")
        record("dedup_url", sample_id=known_sample_id)
        return

    # Everything below makes a real outbound connection to an attacker-chosen
    # host and then parses whatever it sends back — this whole block is one
    # try so ANY exception anywhere in it (not just the fetch itself) is
    # guaranteed to end in a recorded "failed" attempt, never an uncaught
    # propagation. That distinction mattered live: an uncaught exception here
    # used to escape run_forever's per-event loop (or _run_retry_sweep's
    # per-candidate loop) BEFORE the watermark was saved, so the same
    # poisoned event/URL got re-processed and re-crashed every single poll
    # forever — silently blocking every newer event behind it, with no
    # sandbox_fetch_attempts row ever written for it. One malformed URL (see
    # ssrf_guard.py's port-parsing fix) was enough to trigger this live.
    try:
        _fetch_and_store(url, event, depth, record)
    except ssrf_guard.SSRFBlocked as e:
        print(f"[fetcher] BLOCKED {url!r}: {e}")
        record("blocked_ssrf", error=str(e))
    except ssrf_guard.DNSResolutionFailed as e:
        # Not a security block — genuinely just doesn't resolve (dead/sinkholed
        # C2, typo, or an obfuscation ssrf_guard's backslash-strip fallback
        # couldn't undo). Kept distinct from blocked_ssrf so the dashboard
        # doesn't misreport "we deliberately refused this for safety" for
        # something that was never reachable in the first place.
        print(f"[fetcher] DNS FAILED {url!r}: {e}")
        record("dns_failed", error=str(e))
    except requests.RequestException as e:
        print(f"[fetcher] FAILED {url!r}: {e}")
        record("failed", error=str(e))
    except Exception as e:  # noqa: BLE001 — backstop, see the comment above.
        print(f"[fetcher] UNEXPECTED {url!r}: {e}")
        record("failed", error=f"unexpected: {e}")


def _fetch_and_store(url, event, depth, record):
    final_url, content = ssrf_guard.safe_get(url, config.MAX_DOWNLOAD_BYTES)

    if not content:
        print(f"[fetcher] EMPTY {url!r}: zero bytes returned")
        record("empty")
        return

    sha256 = hashlib.sha256(content).hexdigest()
    existing = db.get_sample_by_sha256(sha256)
    if existing:
        print(f"[fetcher] dedup_content: {url!r} -> already have sha256 {sha256[:16]}")
        record("dedup_content", sample_id=existing["id"])
        return

    md5 = hashlib.md5(content).hexdigest()
    mime_type = analyzer.detect_mime(content)
    architecture = analyzer.detect_elf_architecture(content)
    # final_url (post-redirect), not the original url — that's where these
    # bytes actually came from, and what a .css/.js-extension check should
    # judge against.
    is_malware = analyzer.looks_like_malware(mime_type, architecture, url=final_url)

    sample_id = None
    if is_malware:
        os.makedirs(config.SAMPLES_DIR, exist_ok=True)
        local_path = os.path.join(config.SAMPLES_DIR, sha256)
        with open(local_path, "wb") as f:
            f.write(content)

        sample_id = db.insert_sample(
            sha256=sha256, md5=md5, file_size=len(content),
            mime_type=mime_type, architecture=architecture, local_path=local_path,
        )
        print(f"[fetcher] fetched sha256={sha256[:16]} size={len(content)} arch={architecture} from {url!r}")
        record("fetched", sample_id=sample_id)
    else:
        # A URL embedded in attacker input pointing at an ordinary web page,
        # image, or JSON API response is common and not what this pipeline
        # exists to collect (confirmed live: 3 of the first 5 samples ever
        # stored were exactly this — 2 HTML pages, 1 tiny JSON blob). Still
        # gets a fetch_attempts row — the point of that log is showing every
        # attempt, not just the ones that turned into a kept sample — just
        # never written to disk or given a sandbox_samples row. The
        # second-stage re-scan below still runs on it, though: a compromised
        # website's HTML is exactly the kind of "not malware itself" content
        # that can legitimately link to the real payload.
        print(f"[fetcher] NOT MALWARE {url!r}: mime={mime_type} arch={architecture}, discarding")
        record("not_malware")

    # Second-stage re-scan: stager->real-payload chains are common (a small
    # script that itself fetches the actual malware), and were previously
    # invisible past stage 1 — confirmed absent by design, not by evidence of
    # a miss, since we'd never looked before. Capped at depth 2 total to bound
    # runaway recursion on a self-referential or circular chain. Only text
    # content is worth re-scanning; a real ELF binary's raw bytes won't
    # usefully regex-match as URLs. Also bounded by size and URL count — see
    # _SECOND_STAGE_MAX_* above for why.
    if (depth < 2 and architecture in ("not_elf", None)
            and len(content) <= _SECOND_STAGE_MAX_CONTENT_BYTES):
        try:
            text = content.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        if text:
            stage2 = {_clean_url(u) for u in URL_REGEX.findall(text) if u}
            stage2 |= {_clean_url(u) for u in _extract_urls_from_base64(text) if u}
            stage2 |= set(_extract_dev_tcp_urls(text))
            stage2.discard(url)
            for u2 in sorted(stage2)[:_SECOND_STAGE_MAX_URLS]:
                print(f"[fetcher] second-stage URL in sha256={sha256[:16]}: {u2!r}")
                _process_url(u2, event, depth=depth + 1)


def _parse_attempted_at(ts):
    # db.py's _now() format: "%Y-%m-%dT%H:%M:%S.%f" + "Z", always UTC.
    return datetime.datetime.strptime(ts.rstrip("Z"), "%Y-%m-%dT%H:%M:%S.%f").replace(
        tzinfo=datetime.timezone.utc
    )


def _run_retry_sweep():
    """Re-attempts URLs whose most recent try was 'failed'/'dns_failed', on an
    escalating backoff, up to config.MAX_FETCH_ATTEMPTS_PER_URL total tries.
    Catches dropzones that were only briefly down/rate-limited at capture
    time — see the config.py comment for why this exists."""
    candidates = db.find_retryable_urls(
        config.RETRYABLE_STATUSES, config.MAX_FETCH_ATTEMPTS_PER_URL, config.RETRY_MAX_AGE_HOURS
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    retried = 0
    for row in candidates:
        # attempt_count so far == how many tries already happened, so this
        # would be retry number attempt_count (1st retry when attempt_count
        # is 1, i.e. only the original attempt has happened so far).
        backoff_idx = min(row["attempt_count"] - 1, len(config.RETRY_BACKOFF_MINUTES) - 1)
        backoff = datetime.timedelta(minutes=config.RETRY_BACKOFF_MINUTES[backoff_idx])
        try:
            last_attempt_at = _parse_attempted_at(row["attempted_at"])
        except ValueError:
            continue
        if now - last_attempt_at < backoff:
            continue

        event = {"id": row["source_event_id"], "ip": row["source_ip"]}
        print(f"[fetcher] retrying {row['url']!r} (attempt {row['attempt_count'] + 1}/"
              f"{config.MAX_FETCH_ATTEMPTS_PER_URL})")
        _process_url(row["url"], event)
        retried += 1

    if retried:
        print(f"[fetcher] retry sweep: retried {retried} url(s)")


_wake_event = threading.Event()


def _notify_listener():
    """Background thread: blocks on recvfrom, sets _wake_event on any datagram.
    Content is never inspected — receiving anything at all just means "something
    worth looking at landed, poll now instead of waiting out the timer." A
    malformed or spoofed local packet has the same effect as a real one (an
    early, harmless, no-op-if-nothing-new poll), so there's nothing to validate."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((config.NOTIFY_HOST, config.NOTIFY_PORT))
    except OSError as e:
        print(f"[fetcher] notify listener failed to bind {config.NOTIFY_HOST}:"
              f"{config.NOTIFY_PORT}: {e} — push-notify disabled, polling only")
        return
    print(f"[fetcher] notify listener on {config.NOTIFY_HOST}:{config.NOTIFY_PORT}")
    while True:
        try:
            sock.recvfrom(64)
            _wake_event.set()
        except Exception:
            pass


_HEARTBEAT_INTERVAL_SECONDS = 10 * 60


def run_forever():
    db.init_sandbox_db()
    since_id = _load_watermark()
    print(f"[fetcher] starting from watermark id={since_id}")
    # Wall-clock, not a loop-iteration counter: push-notify (below) can wake
    # this loop far more often than POLL_INTERVAL_SECONDS under bursty
    # traffic, so counting iterations would make the heartbeat/retry-sweep
    # cadence drift from what their own "every ~10 min" / "every N seconds"
    # comments say — the backoff math in _run_retry_sweep already uses real
    # timestamps and was unaffected, but this drift was still real.
    last_heartbeat = time.monotonic()
    last_retry_sweep = time.monotonic()

    threading.Thread(target=_notify_listener, daemon=True).start()

    while True:
        try:
            events = _fetch_events(since_id)
            url_events = 0
            for event in events:
                urls = _extract_urls(event)
                if urls:
                    url_events += 1
                for url in urls:
                    _process_url(url, event)

            if events:
                since_id = max(since_id, max(e["id"] for e in events))
                _save_watermark(since_id)
                print(f"[fetcher] polled {len(events)} events (id<={since_id}), "
                      f"{url_events} contained a URL")

            now = time.monotonic()
            if now - last_heartbeat >= _HEARTBEAT_INTERVAL_SECONDS:
                last_heartbeat = now
                print(f"[fetcher] heartbeat: alive, watermark={since_id}")
            if now - last_retry_sweep >= config.RETRY_SWEEP_INTERVAL_SECONDS:
                last_retry_sweep = now
                _run_retry_sweep()
        except requests.RequestException as e:
            print(f"[fetcher] poll error: {e}")
        except Exception as e:  # noqa: BLE001 — this loop must never die silently
            print(f"[fetcher] unexpected error: {e}")

        # Woken early by a push-notify datagram, or falls through at the normal
        # interval either way — see NOTIFY_PORT's config.py comment.
        _wake_event.wait(timeout=config.POLL_INTERVAL_SECONDS)
        _wake_event.clear()


if __name__ == "__main__":
    run_forever()
