#!/bin/bash
# Run on a fresh Ubuntu VM as root.
# Installs Docker, copies the project, and starts the honeypot.
# Safe to run multiple times.
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (use sudo)." >&2
    exit 1
fi

echo "[*] Updating packages..."
apt-get update -qq
apt-get install -y ca-certificates curl

echo "[*] Installing Docker..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Always write the correct Ubuntu repo (fixes stale/wrong entries)
. /etc/os-release
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -qq
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Reset failed units and ensure Docker is running cleanly
systemctl reset-failed docker.socket docker.service 2>/dev/null || true
systemctl enable docker
systemctl start docker.socket
systemctl start docker

echo ""
echo "[*] Docker installed: $(docker --version)"
echo ""

# Move host SSH off port 22 so the honeypot can own it
echo "[*] Moving host SSH daemon to port 2222..."

# Install openssh-server if not present
if ! dpkg -l openssh-server 2>/dev/null | grep -q '^ii'; then
    echo "    openssh-server not found, installing..."
    apt-get install -y openssh-server
fi

if [ -f /etc/ssh/sshd_config ]; then
    # Update sshd_config port
    if grep -qE '^#?[[:space:]]*Port ' /etc/ssh/sshd_config; then
        sed -i -E 's/^#?[[:space:]]*Port .*/Port 2222/' /etc/ssh/sshd_config
    else
        echo "Port 2222" >> /etc/ssh/sshd_config
    fi

    # Ubuntu 24.04 uses socket activation — ssh.socket hardcodes port 22
    # and overrides sshd_config, so we must override the socket unit too.
    if systemctl list-unit-files ssh.socket &>/dev/null; then
        mkdir -p /etc/systemd/system/ssh.socket.d
        cat > /etc/systemd/system/ssh.socket.d/override.conf << 'EOF'
[Socket]
ListenStream=
ListenStream=0.0.0.0:2222
ListenStream=[::]:2222
EOF
        systemctl daemon-reload
        systemctl restart ssh.socket
        echo "    Host SSH socket moved to port 2222."
    fi

    # Restart the service (covers both socket-activated and classic setups)
    if ! systemctl restart ssh 2>/dev/null && ! systemctl restart sshd 2>/dev/null; then
        echo "    Warning: could not restart SSH service, continuing anyway."
    else
        echo "    Host SSH is now on port 2222. Reconnect using: ssh user@<ip> -p 2222"
    fi
else
    echo "    Warning: /etc/ssh/sshd_config not found, skipping SSH port change."
fi
echo ""

# Copy project files
DEST=/opt/honeypot
SCRIPT_DIR="$(realpath "$(dirname "$0")")"
mkdir -p "$DEST"
if [ "$(realpath "$SCRIPT_DIR")" != "$(realpath "$DEST")" ]; then
    cp -r "$SCRIPT_DIR/." "$DEST"
fi
cd "$DEST"

# Set up .env
if [ ! -f .env ]; then
    cp .env.example .env
    echo ""
    echo "  Edit /opt/honeypot/.env to add your Discord webhook URL (optional)."
    echo "  Press Enter to continue without it, or Ctrl+C to edit first."
    read -r
fi

echo "[*] Building and starting honeypot..."
docker compose down 2>/dev/null || true
docker compose up -d --build

echo ""
echo "  Honeypot is running."
echo "  Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "  Useful commands:"
echo "    docker compose logs -f          # live logs"
echo "    docker compose down             # stop"
echo "    docker compose up -d --build    # rebuild and restart"
