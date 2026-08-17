"""
Dashboard-driven Suricata rule builder.

Rules created through the UI are stored in the `custom_suricata_rules` table (source
of truth for the Detections tab's list/toggle/delete UI), then rendered out to
custom.rules — a file Suricata already includes via its `rule-files:` list, separate
from the hand-authored suricata.rules so this never touches/risks that file — and a
live "reload-rules" is issued over Suricata's unix-command control socket so it takes
effect immediately, no container restart (which would briefly drop af-packet capture).

SIDs auto-assigned starting at 2000000, well clear of the hand-authored rules'
1000001-1000041 range, so the two can never collide.
"""

import json
import os
import socket
import sqlite3

from config import DB_PATH, CUSTOM_RULES_PATH, SURICATA_SOCKET_PATH

_SID_START = 2000000

# Suricata's standard classification types — restricting to these (rather than letting
# a user type anything) keeps generated rules valid and keeps alert categorization
# consistent with the hand-authored ruleset.
ALLOWED_CLASSTYPES = [
    "attempted-recon", "attempted-admin", "attempted-user",
    "web-application-attack", "shellcode-detect", "policy-violation",
    "trojan-activity", "successful-recon-limited", "bad-unknown",
]

ALLOWED_PROTOCOLS = ["tcp", "udp", "http"]

# Where HTTP content matches apply — only meaningful when protocol == "http".
ALLOWED_HTTP_FIELDS = ["http.uri", "http.request_body", ""]


class RuleError(ValueError):
    """Raised on invalid rule fields. Message is safe to show to the user."""


def _validate_port(value, field_name):
    if value in (None, "", "any"):
        return "any"
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise RuleError(f"{field_name} must be a port number or 'any', got {value!r}")
    if not (1 <= port <= 65535):
        raise RuleError(f"{field_name} must be between 1 and 65535, got {port}")
    return str(port)


def validate_fields(fields):
    """Raises RuleError on anything that would produce an invalid/dangerous rule.
    Returns a normalized copy of fields."""
    out = dict(fields)

    message = (out.get("message") or "").strip()
    if not message:
        raise RuleError("message is required")
    if '"' in message:
        raise RuleError('message cannot contain a literal " character')
    out["message"] = message

    protocol = (out.get("protocol") or "").strip().lower()
    if protocol not in ALLOWED_PROTOCOLS:
        raise RuleError(f"protocol must be one of {ALLOWED_PROTOCOLS}, got {protocol!r}")
    out["protocol"] = protocol

    out["dest_port"] = _validate_port(out.get("dest_port"), "dest_port")

    classtype = (out.get("classtype") or "").strip()
    if classtype not in ALLOWED_CLASSTYPES:
        raise RuleError(f"classtype must be one of {ALLOWED_CLASSTYPES}, got {classtype!r}")
    out["classtype"] = classtype

    http_field = (out.get("http_field") or "").strip()
    if http_field not in ALLOWED_HTTP_FIELDS:
        raise RuleError(f"http_field must be one of {ALLOWED_HTTP_FIELDS!r}, got {http_field!r}")
    if http_field and protocol != "http":
        raise RuleError("http_field only applies when protocol is 'http'")
    out["http_field"] = http_field

    contents = out.get("contents") or []
    if not isinstance(contents, list):
        raise RuleError("contents must be a list of strings")
    contents = [c.strip() for c in contents if c and c.strip()]
    for c in contents:
        if '"' in c:
            raise RuleError(f'content match cannot contain a literal " character: {c!r}')
    out["contents"] = contents

    threshold = out.get("threshold") or None
    if threshold:
        try:
            count = int(threshold.get("count"))
            seconds = int(threshold.get("seconds"))
        except (TypeError, ValueError, AttributeError):
            raise RuleError("threshold.count and threshold.seconds must be integers")
        if count < 1 or seconds < 1:
            raise RuleError("threshold.count and threshold.seconds must both be >= 1")
        out["threshold"] = {"count": count, "seconds": seconds}
    else:
        out["threshold"] = None

    if not contents and not threshold and protocol != "http":
        # A bare "any -> any port" rule with no content and no threshold would fire on
        # every single packet — almost certainly not what was intended.
        raise RuleError(
            "add at least one content match, or a threshold, or use protocol http "
            "(matches on HTTP transactions specifically) — otherwise this would alert "
            "on every packet to this port"
        )

    return out


def build_rule_text(sid, fields):
    """fields must already be validate_fields()-normalized."""
    proto = fields["protocol"]
    dest_port = fields["dest_port"]
    message = fields["message"]
    classtype = fields["classtype"]
    http_field = fields["http_field"]
    contents = fields["contents"]
    threshold = fields["threshold"]

    header = f'{proto} any any -> any {dest_port}'

    options = [f'msg:"{message}"']

    if not contents and not threshold and proto != "http":
        # Guarded against in validate_fields(), but never emit an always-fire rule.
        raise RuleError("refusing to build a content-less, threshold-less non-HTTP rule")

    if not contents and not threshold:
        # protocol http with no content match at all: flag every HTTP transaction to
        # this port/host — same SYN-based "connection attempt" style as the
        # hand-authored port-scan rules, just for HTTP transactions specifically.
        options.append("flags:S")

    for c in contents:
        if http_field:
            options.append(f'{http_field}; content:"{c}"; nocase')
        else:
            options.append(f'content:"{c}"; nocase')

    if threshold:
        options.append(
            f'threshold:type both, count {threshold["count"]}, '
            f'seconds {threshold["seconds"]}, track by_src'
        )

    options.append(f'classtype:{classtype}')
    options.append(f'sid:{sid}')
    options.append('rev:1')

    return f'alert {header} ({"; ".join(options)};)'


def _next_sid(conn):
    row = conn.execute("SELECT MAX(sid) FROM custom_suricata_rules").fetchone()
    return max(_SID_START, (row[0] or 0) + 1)


def create_rule(fields):
    """Validates, assigns a SID, stores in the DB, regenerates custom.rules, and
    attempts a live reload. Returns (rule_dict, reload_ok, reload_message)."""
    normalized = validate_fields(fields)

    conn = sqlite3.connect(DB_PATH)
    try:
        sid = _next_sid(conn)
        rule_text = build_rule_text(sid, normalized)
        cur = conn.execute(
            """INSERT INTO custom_suricata_rules
               (sid, message, protocol, dest_port, contents, http_field, classtype,
                threshold_count, threshold_seconds, rule_text, enabled, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, datetime('now'))""",
            (
                sid, normalized["message"], normalized["protocol"], normalized["dest_port"],
                json.dumps(normalized["contents"]), normalized["http_field"], normalized["classtype"],
                (normalized["threshold"] or {}).get("count"),
                (normalized["threshold"] or {}).get("seconds"),
                rule_text,
            ),
        )
        conn.commit()
        rule_id = cur.lastrowid
        regenerate_custom_rules_file(conn)
    finally:
        conn.close()

    ok, msg = reload_suricata()
    return {"id": rule_id, "sid": sid, "rule_text": rule_text}, ok, msg


def list_rules():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM custom_suricata_rules ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def set_enabled(rule_id, enabled):
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "UPDATE custom_suricata_rules SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, rule_id),
        )
        conn.commit()
        regenerate_custom_rules_file(conn)
    finally:
        conn.close()
    return reload_suricata()


def delete_rule(rule_id):
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("DELETE FROM custom_suricata_rules WHERE id = ?", (rule_id,))
        conn.commit()
        regenerate_custom_rules_file(conn)
    finally:
        conn.close()
    return reload_suricata()


def regenerate_custom_rules_file(conn):
    """Writes every *enabled* rule out to CUSTOM_RULES_PATH.

    Writes in place rather than write-temp-then-os.replace(): CUSTOM_RULES_PATH is a
    Docker bind-mounted *file*, shared into both the honeypot and suricata containers,
    and a bind mount is tied to a specific inode. os.replace() can't retarget that
    inode — it fails with "OSError: [Errno 16] Device or resource busy" (confirmed
    live). An in-place write loses true atomicity, but the exposure is negligible: this
    only runs when a rule is added/toggled/deleted via the UI (not per-event), the file
    is a handful of short lines, and Suricata's rule loader just skips/logs a malformed
    line rather than crashing, so a reload racing a write mid-line self-corrects on the
    next reload.
    """
    rows = conn.execute(
        "SELECT rule_text FROM custom_suricata_rules WHERE enabled = 1 ORDER BY id"
    ).fetchall()

    lines = [
        "# Rules added via the dashboard's Detections tab rule builder. Managed",
        "# automatically — hand-edits here will be overwritten the next time a rule",
        "# is added/removed/toggled through the UI. See rule_builder.py.",
        "",
    ]
    lines.extend(r[0] for r in rows)
    content = "\n".join(lines) + "\n"

    with open(CUSTOM_RULES_PATH, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())


def reload_suricata(timeout=10):
    """Best-effort live reload over Suricata's unix-command socket. Returns
    (ok: bool, message: str) — never raises, so a reload failure (socket missing,
    Suricata down, etc.) is reported back to the caller instead of blowing up the
    request that just saved a rule. The rule is saved either way; reload just makes
    it take effect without a manual restart."""
    if not os.path.exists(SURICATA_SOCKET_PATH):
        return False, (
            "Rule saved, but the Suricata control socket isn't there — "
            "restart the suricata container to pick it up."
        )
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(SURICATA_SOCKET_PATH)
        s.sendall(json.dumps({"version": "0.2"}).encode() + b"\n")
        hello = json.loads(s.recv(4096).decode())
        if hello.get("return") != "OK":
            return False, f"Rule saved, but Suricata handshake failed: {hello}"

        s.sendall(json.dumps({"command": "reload-rules"}).encode() + b"\n")
        reply = json.loads(s.recv(65536).decode())
        s.close()

        if reply.get("return") == "OK":
            return True, "Reloaded live."
        return False, f"Rule saved, but Suricata reload reported an error: {reply}"
    except Exception as e:
        return False, f"Rule saved, but live reload failed ({e}) — restart the suricata container to apply."
