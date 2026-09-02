# Malware Sandbox

Fetches the URLs attackers try to `wget`/`curl` in the fake shell traps and
statically analyzes what comes back. This is a deliberate reversal of the main
honeypot's "never fetch attacker URLs" design principle (see `config.py`'s
comment about the Discord webhook).

## Scope: fetch + static analysis only. No execution, no VirusTotal.

**What's running:**
- `fetcher` service (docker-compose.yml) — polls the dashboard's
  `/api/events/since` outbox endpoint, scans every event's raw data for
  embedded URLs (not just `download_attempt` events — see `fetcher.py`'s
  module docstring), sanitizes and SSRF-checks them (`ssrf_guard.py`),
  downloads with a hard size cap, and statically analyzes what it gets
  (`analyzer.py`: MIME type, ELF architecture, a keep/discard filter tuned
  against this honeypot's own real captured traffic).
- Results land in the `sandbox_samples` / `sandbox_fetch_attempts` tables
  (schema created by the main honeypot app on startup, in `logger.py`) and
  are visible in the dashboard's "Malware Samples" tab.
- **Nothing is ever executed.** Every kept file just sits in
  `data/sandbox_samples/` as bytes on disk, for you to pull down and analyze
  yourself.

**Detonation (real execution in an isolated runtime) was deliberately never
built and isn't planned** — the original risk discussion (an unpatched ESXi
hypervisor shared with production sites made first-real-execution the single
highest-consequence step available on this host) is why fetch-only was chosen
in the first place. A `sandbox_detonations` table and `DETONATION_ENABLED`
flag existed for a while as a placeholder for that path; both were removed
(2026-08-28) since they only ever produced a permanently-empty "not queued"
column in the UI — clutter for a feature that was never going to ship, not an
in-progress one.

**VirusTotal hash-lookup enrichment was removed the same day**, for the same
reason: no API key was ever configured, so the "VT" column in every view that
had one was permanently "Pending…". If you want that back, it needs a real
`VIRUSTOTAL_API_KEY` — otherwise the UI is more honest without a column that
never resolves.

## Why fetching real attacker-supplied files runs on this host at all

Short version: DMZ VLAN firewall rules already restrict this VM's egress to
DNS/NTP/HTTP/HTTPS and block lateral movement into other VLANs, so a fetch
gone wrong stays contained to "talked to a URL on the open internet" — the
same exposure the box already has just doing DNS lookups. The `ssrf_guard.py`
module exists specifically to stop that URL from ever being able to point
*back* at internal infrastructure (`10.20.0.193`, cloud metadata IPs, etc.)
instead of the attacker's own malware host. TLS certificate verification is
deliberately disabled for these fetches (bulletproof/malware-hosting infra
routinely runs self-signed certs) — safe here specifically because nothing
downstream trusts this content with anything; it's hashed and stored, never
executed or rendered.

## Operational notes

- **Watermark**: `data/sandbox_fetcher_watermark` tracks the last processed
  event id (same pattern as `honeypot-event-puller` on docker-svc). Delete it
  to reprocess from scratch; edit it directly to skip/rewind.
- **Dedup**: by URL first (skip anything already fetched), then by sha256 of
  the actual content (two different URLs serving the same bytes only get
  analyzed once).
- **Second-stage re-scan**: a fetched non-ELF sample gets re-scanned for
  embedded URLs one level deep (stager-fetches-real-payload chains), but only
  if it's small (≤8KB) and capped at 5 follow-up URLs — a real webpage
  swept up this way once produced 92 unrelated "samples" (CDN JS/CSS) before
  those caps existed.
- **No dashboard restart needed for fetcher-only changes** — unlike
  `dashboard/`, `sandbox/` is its own image; `docker compose build fetcher &&
  docker compose up -d fetcher` picks up changes without touching the main
  honeypot container.
