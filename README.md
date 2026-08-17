# Honeypot

A low-interaction honeypot emulating SSH, FTP, Telnet, HTTP, HTTPS, SMTP, Redis, MySQL,
and PostgreSQL. It logs every connection attempt, captured credential, and downloaded
payload to SQLite (with **GeoIP** country enrichment via `geoip2fast`), streams **JSONL**
logs, optionally correlates with **Suricata** IDS alerts, and exposes a web dashboard —
live interactive attack map, a SIEM-style log search screen, captured payloads (with
optional VirusTotal lookups), and a MITRE ATT&CK-mapped detections view.

## Services

| Service   | Port | What it captures                              |
|-----------|------|------------------------------------------------|
| SSH       | 22   | Username/password, public-key, and exec/shell commands (saved as payloads) |
| FTP       | 21   | Username/password attempts                      |
| Telnet    | 23   | Username/password attempts, interactive shell commands |
| HTTP      | 80   | Full request line, headers, POST bodies (saved as payloads), canary bait files |
| HTTPS     | 8443 | Same as HTTP, over a self-signed TLS cert       |
| SMTP      | 25   | AUTH credentials, full message bodies (saved as payloads) |
| Redis     | 6379 | AUTH password, SET/EVAL/unknown commands (saved as payloads) |
| MySQL     | 3306 | Client handshake credentials                    |
| PostgreSQL| 5432 | Startup-message credentials                     |
| Dashboard | 8080 | Web UI (see security note below)                |

## Testing

From the project root:

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/ -v
```

Phase-focused runs and markers are documented in `tests/conftest.py`. Run the **full**
suite before opening a PR.

## Requirements

- An Ubuntu VM (22.04 or 24.04 recommended)
- The VM should be reachable from wherever you want to attract traffic (a WAN-exposed
  host if you want real internet scanners, an internal segment if you're just testing)
- Optional: something on a trusted network to drain alerts/events from this box (see
  "Alerting" below) — this honeypot does not call out anywhere on its own

## Quick Start (Ubuntu VM)

### 1. Copy the project to the VM

```bash
scp -r honeypot/ user@<vm-ip>:~/honeypot
```

### 2. Configure

```bash
cp ~/honeypot/.env.example ~/honeypot/.env
nano ~/honeypot/.env
```

At minimum, set `OUTBOX_TOKEN` to something random if you plan to drain alerts (see
below), and `SURICATA_IFACE` to your real network interface (`ip link show`) if you
want the Suricata sidecar to actually capture anything — its default is almost
certainly wrong for your host.

### 3. Run the setup script

```bash
cd ~/honeypot
chmod +x setup.sh
sudo ./setup.sh
```

The script will:
- Install Docker via the official Debian repository
- Move the VM's SSH daemon to port **2222** so the honeypot can own port 22
- Copy the project to `/opt/honeypot`
- Build and start the Docker containers (honeypot + Suricata)

> **Important:** After the script runs, reconnect to the VM on port 2222:
> ```bash
> ssh user@<vm-ip> -p 2222
> ```

## Alerting

This honeypot is designed to be compromised, so by default **it makes no outbound
HTTPS calls and holds no webhook secret**. `alerts/discord.py` queues fully-formatted
alert payloads into a local `alert_outbox` table instead of calling Discord directly.

To actually deliver them, run something on a trusted network (not this host) that:
1. Polls `GET /api/alerts/pending` (header `X-Outbox-Token: <your OUTBOX_TOKEN>`)
2. Posts each payload to your real Discord webhook (or wherever you want alerts)
3. Reports success with `POST /api/alerts/ack {"ids": [...]}`

`GET /api/events/since?id=<last_id>` works the same way if you want to mirror raw
events out — into a SIEM, an IDS's own log ingestion, whatever — without this host
reaching out itself.

All of this is only reachable with a valid `OUTBOX_TOKEN` — leaving it unset fails
closed (every request to these three endpoints gets a 403).

## Security: non-root user

The container runs as a fixed non-root user (uid/gid `10001`), not root — `CAP_NET_BIND_SERVICE`
(already in `docker-compose.yml`) is what actually lets it bind the low ports (21/22/23/25/80)
without needing root.

**Fresh deployment:** nothing to do — the Dockerfile chowns `/app` before switching to
that user, and Docker copies that ownership into `data`/`logs` the first time it
creates those volumes/mounts.

**Existing deployment upgrading from an older, root-running image:** the running
container has already been writing files as root, so you need to fix ownership on the
existing data before switching, or the app will get permission-denied trying to read
its own SSH host key / write its own database:

```bash
docker compose down
sudo chown -R 10001:10001 "$(docker volume inspect -f '{{ .Mountpoint }}' honeypot_honeypot-data)"
sudo chown 10001:10001 ./logs ./logs/honeypot.jsonl   # not -R: leaves logs/suricata/
                                                        # (owned by the suricata
                                                        # container's own user) alone
docker compose up -d --build
```

## Security: dashboard and logs

- The Flask dashboard listens on **`0.0.0.0:8080`** by default — any host that can
  reach that port can read the API (events, captured credentials, payloads). There is
  **no authentication** on the dashboard itself.
- **Do not** expose `8080` to the public internet unless you add your own protection
  (reverse proxy + auth, VPN-only network, or bind to `127.0.0.1` and tunnel).
- Events are stored in SQLite under `data/` and appended to `logs/honeypot.jsonl`.
  Captured payload files live under `data/payloads/`. Treat all of it as sensitive —
  it's real captured attacker data, including credentials attackers typed believing
  they were real.

## Accessing the Dashboard

On a typical VM you should **not** rely on "localhost only": the app binds all
interfaces. Prefer locking down the firewall and using an SSH tunnel from your machine:

```bash
ssh -p 2222 -L 8080:127.0.0.1:8080 user@<vm-ip>
```

Then open [http://localhost:8080](http://localhost:8080) in your browser.

## Managing the Containers

```bash
cd /opt/honeypot

# View live logs
docker compose logs -f

# Stop everything
docker compose down

# Rebuild and restart (after config or code changes)
docker compose up -d --build
```

## Data Persistence

| Location                  | Contents                                          | Persistence |
|----------------------------|----------------------------------------------------|-------------|
| `honeypot-data` (named volume) | SQLite database, SSH host key, captured payload files | Survives rebuilds |
| `./logs`                  | `honeypot.jsonl`, `logs/suricata/eve.json`         | Host bind mount — shared between the honeypot and Suricata containers so the honeypot can tail Suricata's alerts; also survives rebuilds |

## Configuration

Most settings are environment variables (see `.env.example`); a few (ports, banners)
live directly in `config.py`. Either way, rebuild after changing anything:

```bash
docker compose up -d --build
```

Key settings:

| Setting / env var       | Default    | Description                          |
|--------------------------|------------|---------------------------------------|
| `OUTBOX_TOKEN`           | *(empty)*  | Required to use `/api/alerts/*` and `/api/events/since` — see "Alerting" above |
| `ALERT_ON_CONNECT`       | on (`1`)   | Set to `0`/`false`/`no`/`off` to disable |
| `ALERT_ON_CREDENTIAL`    | on (`1`)   | Same |
| `ALERT_ON_EXEC`          | on (`1`)   | SSH/shell exec-style alerts |
| `ALERT_ON_DOWNLOAD`      | on (`1`)   | wget/curl-style download alerts |
| `DISCORD_ALERT_COOLDOWN` | `60`       | Seconds between duplicate alerts per IP + type |
| `ABUSEIPDB_API_KEY`      | *(empty)*  | Enables abuse-score enrichment on captured IPs; no-op if unset |
| `VIRUSTOTAL_API_KEY`     | *(empty)*  | Enables VT lookups on captured payloads; no-op if unset |
| `TRUSTED_PROXIES`        | *(empty)*  | Comma-separated IPs of reverse proxies whose X-Forwarded-For should be trusted for the HTTP/HTTPS traps |
| `SERVER_LAT`/`SERVER_LON`| auto-detected via ipinfo.io | "Victim" pin on the attack map — set explicitly to skip the outbound lookup or hide your real location |
| `SURICATA_IFACE`         | `ens33`    | Network interface Suricata sniffs — almost certainly needs changing |
| `SSH_BANNER`             | OpenSSH 8.2 | Banner shown to connecting clients (`config.py`) |
| `HTTP_SERVER_HEADER`     | Apache 2.4 | `Server:` header in HTTP responses (`config.py`) |

## Project Structure

```
honeypot/
├── main.py                  # Entry point — starts all services in threads
├── config.py                # Central configuration
├── logger.py                # SQLite + JSONL + event callbacks
├── payloads.py               # Saves captured files/commands, triggers VT lookup
├── vt_intel.py                # VirusTotal enrichment (no-op without VIRUSTOTAL_API_KEY)
├── threat_intel.py            # AbuseIPDB enrichment (no-op without ABUSEIPDB_API_KEY)
├── geoip.py                   # Country lookup + country-centroid fallback for the map
├── country_centroids.py       # Static per-country (lat, lon) table
├── suricata_logger.py         # Tails Suricata's eve.json into suricata_alerts
├── suricata.yaml / suricata.rules
├── ratelimit.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── setup.sh                  # One-shot Debian/Ubuntu installer
├── .env.example
├── alerts/
│   └── discord.py            # Alert policy + outbox queueing (see "Alerting")
├── services/
│   ├── ssh_honey.py
│   ├── ftp_honey.py
│   ├── telnet_honey.py
│   ├── fake_shell.py         # Shared interactive fake-shell used by SSH/Telnet
│   ├── http_honey.py
│   ├── https_honey.py
│   ├── smtp_honey.py
│   ├── redis_honey.py
│   ├── mysql_honey.py
│   └── postgres_honey.py
└── dashboard/
    ├── app.py                # Flask API
    └── templates/
        └── index.html        # Dashboard UI — Overview/map, Events/search, IDS, Payloads, Detections
```
