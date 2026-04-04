# Honeypot

A low-interaction honeypot that emulates SSH, FTP, Telnet, and HTTP services. It logs all connection attempts and captured credentials to SQLite, sends Discord alerts, and exposes a web dashboard.

## Services

| Service  | Port | What it captures                     |
|----------|------|---------------------------------------|
| SSH      | 22   | Username/password and public key attempts |
| FTP      | 21   | Username/password attempts            |
| Telnet   | 23   | Username/password attempts            |
| HTTP     | 80   | Full request line and headers         |
| Dashboard| 8080 | Web UI (localhost only)               |

## Requirements

- An Ubuntu VM (22.04 or 24.04 recommended) with internet access
- The VM should be reachable from your home network
- A Discord webhook URL (optional, for alerts)

## Quick Start (Ubuntu VM)

### 1. Copy the project to the VM

From your local machine:

```bash
scp -r honeypot/ user@<vm-ip>:~/honeypot
```

### 2. (Optional) Configure Discord alerts

On the VM, before running the setup script:

```bash
nano ~/honeypot/.env
```

Add your webhook URL:

```
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

Leave the value blank to disable Discord alerts entirely.

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
- Build and start the Docker container

> **Important:** After the script runs, reconnect to the VM on port 2222:
> ```bash
> ssh user@<vm-ip> -p 2222
> ```

## Accessing the Dashboard

The dashboard is bound to `127.0.0.1:8080` inside the VM (not exposed on the LAN). Access it via an SSH tunnel from your local machine:

```bash
ssh -p 2222 -L 8080:127.0.0.1:8080 user@<vm-ip>
```

Then open [http://localhost:8080](http://localhost:8080) in your browser.

## Managing the Container

```bash
cd /opt/honeypot

# View live logs
docker compose logs -f

# Stop the honeypot
docker compose down

# Rebuild and restart (after config changes)
docker compose up -d --build
```

## Data Persistence

All runtime data is stored in Docker named volumes and survives container restarts and rebuilds:

| Volume          | Contents                          |
|-----------------|-----------------------------------|
| `honeypot-data` | SQLite database, SSH host key     |
| `honeypot-logs` | Plain-text log file               |

## Configuration

Edit `config.py` to change ports, service banners, or alert toggles, then rebuild the container:

```bash
docker compose up -d --build
```

Key settings:

| Setting              | Default | Description                          |
|----------------------|---------|--------------------------------------|
| `ALERT_ON_CONNECT`   | `True`  | Send Discord alert on every new connection |
| `ALERT_ON_CREDENTIAL`| `True`  | Send Discord alert on every credential capture |
| `SSH_BANNER`         | OpenSSH 8.2 | Banner shown to connecting clients |
| `HTTP_SERVER_HEADER` | Apache 2.4  | `Server:` header in HTTP responses |

## Project Structure

```
honeypot/
├── main.py                  # Entry point — starts all services in threads
├── config.py                # Central configuration
├── logger.py                # SQLite + file logging
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── setup.sh                 # One-shot Debian 12 installer
├── .env.example             # Copy to .env and add webhook URL
├── alerts/
│   └── discord.py           # Discord webhook alerting
├── services/
│   ├── ssh_honey.py
│   ├── ftp_honey.py
│   ├── telnet_honey.py
│   └── http_honey.py
└── dashboard/
    ├── app.py               # Flask API
    └── templates/
        └── index.html       # Dashboard UI
```
