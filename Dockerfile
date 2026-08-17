FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 libcap2-bin && \
    rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p logs data

# Run as non-root. A honeypot is designed to be attacked, so if there's ever an RCE in
# this app itself (not the emulated traps, the real Python process), root-in-container
# vs. a capability-scoped unprivileged user is the difference between "attacker has
# this container" and "attacker has root in this container", which matters a lot more
# given container-escape is the actual residual risk on this host (see the ESXi
# patch-gap note in the ops docs).
#
# Fixed UID/GID (not just a name) because both /app/data (named volume) and /app/logs
# (bind mount) are real host-persisted paths whose ownership has to be set to match
# from the deploy side — see README.md's "Non-root user" note.
#
# docker-compose.yml's cap_add: [NET_BIND_SERVICE] alone is NOT enough here: it puts
# the capability in the container's bounding set, but Linux drops a process's effective
# capabilities on any exec() that changes UID away from 0 unless the capability is
# ambient — and Docker does not promote cap_add capabilities to ambient for you. The
# standard fix is a file capability on the actual interpreter binary, which survives
# the UID change because it's granted at exec() time regardless of who's running it.
# (Confirmed the failure mode directly: CapBnd included NET_BIND_SERVICE, CapEff was
# all-zero, every port <1024 failed with EACCES.)
# Supplementary group 998 matches the jasonish/suricata image's internal "suricata"
# service account (confirmed empirically: `docker exec <suricata container> id
# suricata` → uid=998(suricata) gid=998(suricata)). Suricata's entrypoint chowns
# /var/run/suricata to suricata:suricata on every boot and creates its control socket
# owned by that account at mode 0660 (group-readable/writable, not world) — a
# deliberate Suricata security default, not something to loosen. Joining that GID here
# is how rule_builder.py's reload_suricata() gets to actually use the socket without
# widening its permissions. Tied to that image's specific internal GID, which is a
# real (if unlikely) fragility if the upstream image ever changes it — but
# reload_suricata() already treats "can't reach the socket" as a non-fatal, clearly
# reported failure (the rule still saves either way), so this breaking degrades
# gracefully rather than taking anything down.
RUN groupadd --gid 10001 honeypot && \
    groupadd --gid 998 suricata-shared && \
    useradd --uid 10001 --gid honeypot --groups suricata-shared --no-create-home --shell /usr/sbin/nologin honeypot && \
    chown -R honeypot:honeypot /app && \
    setcap 'cap_net_bind_service=+ep' "$(readlink -f "$(command -v python3)")"
USER honeypot

# EXPOSE all service ports
EXPOSE 22 21 23 25 80 443 3306 5432 6379 8080 8443
CMD ["python", "main.py"]
