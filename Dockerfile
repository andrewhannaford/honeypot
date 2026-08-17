FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p logs data

# Run as non-root. CAP_NET_BIND_SERVICE (granted in docker-compose.yml) lets this user
# bind the low ports (21/22/23/25/80) without needing root — a honeypot is designed to
# be attacked, so if there's ever an RCE in this app itself (not the emulated traps,
# the real Python process), root-in-container vs. a capability-scoped unprivileged user
# is the difference between "attacker has this container" and "attacker has root in
# this container", which matters a lot more given container-escape is the actual
# residual risk on this host (see the ESXi patch-gap note in the ops docs).
#
# Fixed UID/GID (not just a name) because both /app/data (named volume) and /app/logs
# (bind mount) are real host-persisted paths whose ownership has to be set to match
# from the deploy side — see README.md's "Non-root user" note.
RUN groupadd --system --gid 10001 honeypot && \
    useradd --system --uid 10001 --gid honeypot --no-create-home --shell /usr/sbin/nologin honeypot && \
    chown -R honeypot:honeypot /app
USER honeypot

# EXPOSE all service ports
EXPOSE 22 21 23 25 80 443 3306 5432 6379 8080 8443
CMD ["python", "main.py"]
