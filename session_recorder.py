import json
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
import config

# One .cast file per session, named by a random uuid rather than DB id — the
# file has to exist before the DB row does (we write it in finalize(), then
# insert), so there's no id to name it after yet.
SESSIONS_DIR = os.path.join(config.DATA_DIR, "sessions")


class SessionRecorder:
    """Captures every byte an interactive fake-shell session writes to its
    client as an asciinema v2 .cast stream, so the session can be replayed
    later exactly as the attacker's terminal saw it.

    Recording covers only the "dropped into a shell" portion of a
    connection — from services/fake_shell.run_shell's first prompt to exit —
    not the SSH/Telnet auth phase before it. For SSH, auth is opaque binary
    protocol with nothing terminal-shaped to record anyway. For Telnet it
    would technically be recordable (plaintext login/password prompts), but
    Telnet is by far the highest-volume trap here (see CLAUDE.md) and the
    overwhelming majority of hits are single-shot credential-stuffing bots
    that never reach an interactive shell — recording from connect would
    turn "Sessions" into mostly-noise. Only real callers construct one of
    these (see ssh_honey.py / telnet_honey.py), and only once a shell is
    actually about to start.

    Output-only ("o" events) is sufficient to reconstruct the full terminal
    verbatim: both real command output and character-echo from the recv
    loops are written through the same wrapped send_fn, so keystrokes
    (including backspace corrections) show up in the replay exactly as they
    appeared live.
    """

    def __init__(self, ip, port, service, username=None):
        self.ip = ip
        self.port = port
        self.service = service
        self.username = username
        # Generated upfront (not just at finalize time) so callers — fake_shell.py's
        # run_shell, specifically — can tag each "command" event's connection_id with
        # this same value while the session is still live. That's what lets the
        # Events tab cross-link a command straight to its session replay, the same
        # way it already does for Redis/SMTP/FTP/MySQL/Postgres via connection_id.
        self.session_uuid = uuid.uuid4().hex
        self._t0 = time.monotonic()
        self._started_at = datetime.now(timezone.utc)
        self._events = []
        self._command_count = 0
        self._closed = False

    def wrap(self, raw_send_fn):
        """Returns a send_fn that records then forwards. Callers must build
        this *before* constructing their echo-handling recv_line_fn (see
        ssh_honey.py) so keystroke echo is captured too, not just command
        output."""
        def recording_send(text):
            if text:
                self._events.append((time.monotonic() - self._t0, text))
            raw_send_fn(text)
        return recording_send

    def record_command(self):
        self._command_count += 1

    def finalize(self):
        """Idempotent — safe to call from a finally block even if the shell
        never produced any output (e.g. instantly-dropped connection)."""
        if self._closed:
            return
        self._closed = True
        if not self._events:
            return
        duration = time.monotonic() - self._t0

        os.makedirs(SESSIONS_DIR, exist_ok=True)
        cast_path = os.path.join(SESSIONS_DIR, f"{self.session_uuid}.cast")
        header = {
            "version": 2,
            "width": 80,
            "height": 24,
            "timestamp": int(self._started_at.timestamp()),
            "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
            "title": f"{self.service} {self.ip} ({self.username or 'unknown'})",
        }
        with open(cast_path, "w") as f:
            f.write(json.dumps(header) + "\n")
            for offset, text in self._events:
                f.write(json.dumps([round(offset, 6), "o", text]) + "\n")

        conn = sqlite3.connect(config.DB_PATH)
        try:
            conn.execute(
                "INSERT INTO shell_sessions (session_uuid, ip, port, service, username, "
                "started_at, duration_s, event_count, command_count, cast_path) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (self.session_uuid, self.ip, self.port, self.service, self.username,
                 self._started_at.isoformat(), duration, len(self._events),
                 self._command_count, cast_path),
            )
            conn.commit()
        finally:
            conn.close()
