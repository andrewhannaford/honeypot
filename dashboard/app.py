import hmac
import json
import queue
import sqlite3
import threading
import csv
import io
from datetime import datetime, timedelta, timezone, date
from flask import Flask, Response, jsonify, render_template, stream_with_context, request, send_file
import config
import query_lang
import rule_builder
from logger import register_event_callback
from mitre_map import lookup as mitre_lookup
import re
import os

app = Flask(__name__)

_client_queues: list = []
_client_lock = threading.Lock()
_SSE_QUEUE_MAX = 100

def _get_db():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _int_param(args, key, default, cap=None):
    """Parse an integer query parameter safely, returning default on bad input."""
    try:
        val = int(args.get(key, default))
    except (ValueError, TypeError):
        val = int(default)
    return min(val, cap) if cap is not None else val


def _hex_dump(data, width=16):
    """Classic hexdump -C style: offset, hex bytes, printable-ASCII gutter."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)

def publish_attack_event(event_dict):
    """Push geo-tagged events to all connected SSE clients (logger callback)."""
    lat = event_dict.get("lat")
    lon = event_dict.get("lon")
    if lat is None or lon is None:
        return
    payload = {
        "src_lat": lat,
        "src_lon": lon,
        "dst_lat": config.SERVER_LAT,
        "dst_lon": config.SERVER_LON,
        "service": event_dict.get("service"),
        "country": event_dict.get("country"),
        "ip": event_dict.get("ip"),
        # risk_score (see risk_score.py), not abuse_score: it's computed synchronously
        # at insert time, so it's actually populated here. abuse_score comes from an
        # async AbuseIPDB lookup that hasn't necessarily returned yet when this event
        # is published — it would always read as 0 on live events even once enriched.
        "risk_score": event_dict.get("risk_score", 0)
    }
    line = json.dumps(payload, separators=(",", ":")) + "\n"
    with _client_lock:
        clients = list(_client_queues)
    for q in clients:
        try:
            q.put_nowait(line)
        except queue.Full:
            pass

register_event_callback(publish_attack_event)

_DETECTION_CONFIG = [
    {
        "service": "SSH", "port": 22, "banner": "OpenSSH 8.2p1 Ubuntu-4ubuntu0.5",
        "detections": [
            {
                "event_type": "credential", "label": "Password Brute Force",
                "desc": "Every username/password attempt logged",
                "mitre_id": "T1110", "mitre_technique": "Brute Force",
                "mitre_tactic": "Credential Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1110/",
            },
            {
                "event_type": "pubkey_attempt", "label": "Public Key Probe",
                "desc": "Key type and username recorded",
                "mitre_id": "T1110.001", "mitre_technique": "Password Guessing",
                "mitre_tactic": "Credential Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1110/001/",
            },
            {
                "event_type": "exec_attempt", "label": "Exec Command",
                "desc": "Non-interactive SSH exec — saved as payload",
                "mitre_id": "T1059.004", "mitre_technique": "Unix Shell",
                "mitre_tactic": "Execution",
                "mitre_url": "https://attack.mitre.org/techniques/T1059/004/",
            },
            {
                "event_type": "download_attempt", "label": "Download Attempt",
                "desc": "wget/curl in shell — command saved as payload",
                "mitre_id": "T1105", "mitre_technique": "Ingress Tool Transfer",
                "mitre_tactic": "Command and Control",
                "mitre_url": "https://attack.mitre.org/techniques/T1105/",
            },
            {
                "event_type": "command", "label": "Shell Commands",
                "desc": "All commands typed in fake interactive shell",
                "mitre_id": "T1059.004", "mitre_technique": "Unix Shell",
                "mitre_tactic": "Execution",
                "mitre_url": "https://attack.mitre.org/techniques/T1059/004/",
            },
        ],
    },
    {
        "service": "HTTP", "port": 80, "banner": "Apache/2.4.41 (Ubuntu)",
        "detections": [
            {
                "event_type": "trap_hit", "label": "Trap Hit",
                "desc": "/wp-login.php, /wp-admin, /.env probed",
                "mitre_id": "T1190", "mitre_technique": "Exploit Public-Facing Application",
                "mitre_tactic": "Initial Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1190/",
            },
            {
                "event_type": "credential", "label": "WordPress Login",
                "desc": "Credentials harvested from wp-login.php POST",
                "mitre_id": "T1110", "mitre_technique": "Brute Force",
                "mitre_tactic": "Credential Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1110/",
            },
            {
                "event_type": "request", "label": "HTTP Request",
                "desc": "Method, path, user-agent, POST body saved as payload",
                "mitre_id": "T1190", "mitre_technique": "Exploit Public-Facing Application",
                "mitre_tactic": "Initial Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1190/",
            },
        ],
    },
    {
        "service": "HTTPS", "port": 8443, "banner": "Apache/2.4.41 (Ubuntu) + TLS",
        "detections": [
            {
                "event_type": "connect", "label": "TLS Connection",
                "desc": "TLS handshake completed or failed against the HTTPS trap",
                "mitre_id": "T1190", "mitre_technique": "Exploit Public-Facing Application",
                "mitre_tactic": "Initial Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1190/",
            },
        ],
    },
    {
        "service": "FTP", "port": 21, "banner": "vsFTPd 3.0.5",
        "detections": [
            {
                "event_type": "credential", "label": "Login Attempt",
                "desc": "FTP username and password captured",
                "mitre_id": "T1110", "mitre_technique": "Brute Force",
                "mitre_tactic": "Credential Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1110/",
            },
        ],
    },
    {
        "service": "TELNET", "port": 23, "banner": "Ubuntu 22.04.3 LTS",
        "detections": [
            {
                "event_type": "credential", "label": "Login Attempt",
                "desc": "Telnet username and password captured",
                "mitre_id": "T1110", "mitre_technique": "Brute Force",
                "mitre_tactic": "Credential Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1110/",
            },
            {
                "event_type": "download_attempt", "label": "Download Attempt",
                "desc": "wget/curl in shell — command saved as payload",
                "mitre_id": "T1105", "mitre_technique": "Ingress Tool Transfer",
                "mitre_tactic": "Command and Control",
                "mitre_url": "https://attack.mitre.org/techniques/T1105/",
            },
            {
                "event_type": "command", "label": "Shell Commands",
                "desc": "All commands in fake interactive shell",
                "mitre_id": "T1059.004", "mitre_technique": "Unix Shell",
                "mitre_tactic": "Execution",
                "mitre_url": "https://attack.mitre.org/techniques/T1059/004/",
            },
        ],
    },
    {
        "service": "SMTP", "port": 25, "banner": "Postfix ESMTP (Ubuntu)",
        "detections": [
            {
                "event_type": "credential", "label": "AUTH Capture",
                "desc": "PLAIN and LOGIN SMTP auth decoded and logged",
                "mitre_id": "T1078", "mitre_technique": "Valid Accounts",
                "mitre_tactic": "Defense Evasion",
                "mitre_url": "https://attack.mitre.org/techniques/T1078/",
            },
            {
                "event_type": "email_attempt", "label": "Email Capture",
                "desc": "Full email body saved as payload on DATA termination",
                "mitre_id": "T1566", "mitre_technique": "Phishing",
                "mitre_tactic": "Initial Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1566/",
            },
        ],
    },
    {
        "service": "REDIS", "port": 6379, "banner": "Redis 7.0.0",
        "detections": [
            {
                "event_type": "credential", "label": "AUTH Attempt",
                "desc": "Redis AUTH password captured",
                "mitre_id": "T1110", "mitre_technique": "Brute Force",
                "mitre_tactic": "Credential Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1110/",
            },
            {
                "event_type": "command", "label": "Commands",
                "desc": "Commands issued after connecting, logged and saved as payload",
                "mitre_id": "T1210", "mitre_technique": "Exploitation of Remote Services",
                "mitre_tactic": "Lateral Movement",
                "mitre_url": "https://attack.mitre.org/techniques/T1210/",
            },
        ],
    },
    {
        "service": "MYSQL", "port": 3306, "banner": "MySQL 5.7.44-log",
        "detections": [
            {
                "event_type": "credential", "label": "Login Attempt",
                "desc": "MySQL client handshake credentials captured",
                "mitre_id": "T1110", "mitre_technique": "Brute Force",
                "mitre_tactic": "Credential Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1110/",
            },
        ],
    },
    {
        "service": "POSTGRES", "port": 5432, "banner": "PostgreSQL 13.11",
        "detections": [
            {
                "event_type": "credential", "label": "Login Attempt",
                "desc": "Postgres startup-message credentials captured",
                "mitre_id": "T1110", "mitre_technique": "Brute Force",
                "mitre_tactic": "Credential Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1110/",
            },
        ],
    },
]


@app.route("/api/detections", methods=["GET"])
def get_detections():
    conn = _get_db()
    try:
        result = []
        svc_index = {}  # uppercase service name → index in result

        for svc_cfg in _DETECTION_CONFIG:
            svc = svc_cfg["service"]
            detections = []
            for d in svc_cfg["detections"]:
                row = conn.execute(
                    "SELECT COUNT(*) as c FROM events WHERE service = ? AND event_type = ?",
                    (svc, d["event_type"]),
                ).fetchone()
                detections.append({**d, "count": row["c"], "custom": False})
            total = conn.execute(
                "SELECT COUNT(*) as c FROM events WHERE service = ?", (svc,)
            ).fetchone()["c"]
            result.append({
                "service": svc,
                "port": svc_cfg["port"],
                "banner": svc_cfg["banner"],
                "total_events": total,
                "detections": detections,
            })
            svc_index[svc.upper()] = len(result) - 1

        # Merge custom detections from the DB
        for row in conn.execute(
            "SELECT * FROM custom_detections ORDER BY created_at ASC"
        ).fetchall():
            d = dict(row)
            count = conn.execute(
                "SELECT COUNT(*) as c FROM events WHERE service = ? AND event_type = ?",
                (d["service"], d["event_type"]),
            ).fetchone()["c"]
            det = {
                "id": d["id"],
                "event_type": d["event_type"],
                "label": d["label"],
                "desc": d["desc"] or "",
                "query": d["query"] or "",
                "mitre_id": d["mitre_id"] or "",
                "mitre_technique": d["mitre_technique"] or "",
                "mitre_tactic": d["mitre_tactic"] or "",
                "mitre_url": d["mitre_url"] or "",
                "count": count,
                "custom": True,
            }
            key = d["service"].upper()
            if key in svc_index:
                result[svc_index[key]]["detections"].append(det)
            else:
                total = conn.execute(
                    "SELECT COUNT(*) as c FROM events WHERE service = ?", (d["service"],)
                ).fetchone()["c"]
                result.append({
                    "service": d["service"],
                    "port": d["port"],
                    "banner": f"Custom · port {d['port']}",
                    "total_events": total,
                    "detections": [det],
                })
                svc_index[key] = len(result) - 1

        return jsonify(result)
    finally:
        conn.close()


@app.route("/api/detections", methods=["POST"])
def create_detection():
    data = request.json or {}
    required = ["service", "port", "label", "event_type"]
    missing = [f for f in required if not str(data.get(f, "")).strip()]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    conn = _get_db()
    try:
        cur = conn.execute("""
            INSERT INTO custom_detections
              (service, port, label, desc, event_type,
               mitre_id, mitre_technique, mitre_tactic, mitre_url, query, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["service"].strip().upper(),
            int(data["port"]),
            data["label"].strip(),
            data.get("desc", "").strip(),
            data["event_type"].strip(),
            data.get("mitre_id", "").strip(),
            data.get("mitre_technique", "").strip(),
            data.get("mitre_tactic", "").strip(),
            data.get("mitre_url", "").strip(),
            data.get("query", "").strip(),
            datetime.now(timezone.utc).isoformat(),
        ))
        conn.commit()
        return jsonify({"id": cur.lastrowid, "status": "created"}), 201
    finally:
        conn.close()


@app.route("/api/detections/<int:det_id>", methods=["DELETE"])
def delete_detection(det_id):
    conn = _get_db()
    try:
        conn.execute("DELETE FROM custom_detections WHERE id = ?", (det_id,))
        conn.commit()
        return jsonify({"status": "deleted"})
    finally:
        conn.close()


@app.route("/api/rules", methods=["GET"])
def list_rules():
    return jsonify(rule_builder.list_rules())


@app.route("/api/rules", methods=["POST"])
def create_rule():
    """Builds and saves a real Suricata detection rule, then attempts a live reload
    over Suricata's unix-command socket (see rule_builder.py). The rule is saved even
    if the live reload fails — reload_ok/reload_message tell the caller what happened
    so a transient reload failure doesn't look like the rule silently vanished."""
    fields = request.get_json(silent=True) or {}
    try:
        rule, reload_ok, reload_message = rule_builder.create_rule(fields)
    except rule_builder.RuleError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({**rule, "reload_ok": reload_ok, "reload_message": reload_message}), 201


@app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
def toggle_rule(rule_id):
    body = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled", True))
    reload_ok, reload_message = rule_builder.set_enabled(rule_id, enabled)
    return jsonify({"status": "ok", "reload_ok": reload_ok, "reload_message": reload_message})


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    reload_ok, reload_message = rule_builder.delete_rule(rule_id)
    return jsonify({"status": "deleted", "reload_ok": reload_ok, "reload_message": reload_message})


@app.route("/api/rules/classtypes")
def rule_classtypes():
    """Feeds the rule builder form's dropdown — keeps the allowed list defined in one
    place (rule_builder.py) rather than duplicated into the frontend."""
    return jsonify({
        "classtypes": rule_builder.ALLOWED_CLASSTYPES,
        "protocols": rule_builder.ALLOWED_PROTOCOLS,
        "http_fields": [f for f in rule_builder.ALLOWED_HTTP_FIELDS if f],
    })


_RULE_LINE_RE = re.compile(
    r'sid:\s*(\d+).*?rev:\s*(\d+)'
)
_RULE_MSG_RE = re.compile(r'msg:\s*"((?:[^"\\]|\\.)*)"')
_RULE_CLASSTYPE_RE = re.compile(r'classtype:\s*([a-zA-Z0-9_-]+)')


def _parse_rule_file(path, source):
    """Extract sid/msg/classtype from each active rule line in a Suricata rules
    file. Regex-based rather than a full rule-grammar parser: good enough for our
    own straightforward rules (one alert per line, no multi-line continuations),
    and avoids adding a Suricata rule-parsing dependency for a read-only catalog view."""
    rules = []
    if not os.path.exists(path):
        return rules
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or not line.startswith("alert"):
                continue
            sid_m = _RULE_LINE_RE.search(line)
            msg_m = _RULE_MSG_RE.search(line)
            classtype_m = _RULE_CLASSTYPE_RE.search(line)
            if not sid_m or not msg_m:
                continue
            rules.append({
                "sid": int(sid_m.group(1)),
                "rev": int(sid_m.group(2)),
                "msg": msg_m.group(1),
                "classtype": classtype_m.group(1) if classtype_m else None,
                "source": source,
                "rule_text": line,
            })
    return rules


@app.route("/api/signatures")
def get_signatures():
    """Catalog of every Suricata detection signature we have — baseline
    (suricata.rules) plus anything added through the dashboard's rule builder
    (custom.rules) — each with its MITRE ATT&CK tag and live hit count. This is
    the network-layer counterpart to /api/detections (the app-layer protocol
    catalog): that one shows what the honeypot's own trap code instruments,
    this one shows what Suricata is watching for on the wire."""
    rules = (
        _parse_rule_file(config.SURICATA_RULES_PATH, "baseline")
        + _parse_rule_file(config.CUSTOM_RULES_PATH, "custom")
    )

    conn = _get_db()
    try:
        hit_rows = conn.execute(
            "SELECT sid, COUNT(*) as hits, MAX(timestamp) as last_seen "
            "FROM suricata_alerts WHERE sid IS NOT NULL GROUP BY sid"
        ).fetchall()
    finally:
        conn.close()
    hits_by_sid = {r["sid"]: {"hits": r["hits"], "last_seen": r["last_seen"]} for r in hit_rows}

    # Custom (dashboard-created) rules carry their own per-rule MITRE tags —
    # entered at creation time, since mitre_map.py can only know the fixed set of
    # baseline signature strings, not arbitrary user-authored ones.
    custom_mitre_by_sid = {
        cr["sid"]: {
            "mitre_tactic": cr.get("mitre_tactic"),
            "mitre_technique": cr.get("mitre_technique"),
            "mitre_technique_name": cr.get("mitre_technique_name"),
            "mitre_url": cr.get("mitre_url"),
        }
        for cr in rule_builder.list_rules()
    }

    result = []
    for r in rules:
        if r["source"] == "custom" and r["sid"] in custom_mitre_by_sid:
            m = custom_mitre_by_sid[r["sid"]]
            if not m["mitre_tactic"]:
                m = mitre_lookup(r["msg"])
        else:
            m = mitre_lookup(r["msg"])
        hit_info = hits_by_sid.get(r["sid"], {"hits": 0, "last_seen": None})
        result.append({
            **r,
            **m,
            "hits": hit_info["hits"],
            "last_seen": hit_info["last_seen"],
        })

    result.sort(key=lambda r: r["sid"])
    return jsonify(result)


@app.route("/api/sandbox/samples")
def get_sandbox_samples():
    """Unique fetched-content inventory. first_url/first_source_ip/attempt_count
    come from sandbox_fetch_attempts — a sample itself no longer carries
    per-attempt provenance (see sandbox/db.py's module docstring for why that
    split exists)."""
    limit = _int_param(request.args, "limit", 100, cap=500)
    offset = _int_param(request.args, "offset", 0)
    conn = _get_db()
    try:
        rows = conn.execute(
            """SELECT s.id, s.sha256, s.md5, s.file_size, s.mime_type, s.architecture,
                      s.first_seen_at,
                      (SELECT url FROM sandbox_fetch_attempts WHERE sample_id = s.id ORDER BY id ASC LIMIT 1) AS first_url,
                      (SELECT source_ip FROM sandbox_fetch_attempts WHERE sample_id = s.id ORDER BY id ASC LIMIT 1) AS first_source_ip,
                      (SELECT COUNT(*) FROM sandbox_fetch_attempts WHERE sample_id = s.id) AS attempt_count
               FROM sandbox_samples s
               ORDER BY s.id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/sandbox/samples/<int:sample_id>")
def get_sandbox_sample_detail(sample_id):
    conn = _get_db()
    try:
        sample = conn.execute("SELECT * FROM sandbox_samples WHERE id = ?", (sample_id,)).fetchone()
        if not sample:
            return jsonify({"error": "not found"}), 404

        attempts = conn.execute(
            "SELECT * FROM sandbox_fetch_attempts WHERE sample_id = ? ORDER BY id DESC", (sample_id,)
        ).fetchall()

        result = dict(sample)
        result["attempts"] = [dict(a) for a in attempts]
        return jsonify(result)
    finally:
        conn.close()


@app.route("/api/sandbox/samples/<int:sample_id>/download")
def download_sandbox_sample(sample_id):
    """Serves the raw fetched bytes. Always application/octet-stream and
    always as_attachment — this content is untrusted by definition, so the
    browser must never be given a chance to sniff/render it inline (a
    malicious HTML/SVG/JS sample rendered inline would be a stored-XSS vector
    against the dashboard's own origin)."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT sha256, local_path FROM sandbox_samples WHERE id = ?", (sample_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    if not row["local_path"]:
        return jsonify({"error": "file missing on disk"}), 404
    # Flask/Werkzeug's send_file resolves a *relative* path against app.root_path
    # (here /app/dashboard, since that's where this module lives) rather than the
    # process cwd (/app) — a different resolution rule than plain os.path.exists()
    # or sqlite3.connect() use, both of which are cwd-relative. local_path is
    # stored cwd-relative ("data/sandbox_samples/<sha256>"), so send_file was
    # silently looking in /app/dashboard/data/... and 500ing with FileNotFoundError
    # (confirmed live). Resolving to an absolute path once, up front, sidesteps
    # the inconsistency entirely regardless of which resolution rule is used downstream.
    abs_path = os.path.abspath(row["local_path"])
    if not os.path.exists(abs_path):
        return jsonify({"error": "file missing on disk"}), 404
    return send_file(
        abs_path,
        as_attachment=True,
        download_name=f"{row['sha256']}.bin",
        mimetype="application/octet-stream",
    )


@app.route("/api/sandbox/samples/<int:sample_id>/content")
def get_sandbox_sample_content(sample_id):
    """View-only preview of a fetched sample's bytes — same 4KB-cap posture
    as get_payload_content, but hex-dumped instead of text-decoded when the
    content is actually binary (a real ELF, or anything with a null byte),
    since that's most of what lands here — unlike payloads, which skew
    text/shell. JSON response only, never send_file: this is rendered into a
    <pre> via textContent on the frontend, not served as a navigable
    resource, so there's no risk of a browser being handed attacker content
    with a content-type that invites it to do anything other than display
    text."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT local_path, sha256, mime_type, architecture FROM sandbox_samples WHERE id = ?",
            (sample_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    if not row["local_path"]:
        return jsonify({"error": "file missing on disk"}), 404

    # Same cwd-vs-app.root_path resolution gotcha as the download route.
    abs_path = os.path.abspath(row["local_path"])
    if not os.path.exists(abs_path):
        return jsonify({"error": "file missing on disk"}), 404

    file_size = os.path.getsize(abs_path)
    with open(abs_path, "rb") as f:
        data = f.read(4096)  # cap preview at 4 KB, same as payload preview

    is_binary = row["architecture"] not in (None, "not_elf") or b"\x00" in data
    if is_binary:
        preview = _hex_dump(data)
        mode = "hex"
    else:
        preview = data.decode("utf-8", errors="replace")
        mode = "text"

    return jsonify({
        "preview": preview,
        "mode": mode,
        "truncated": file_size > 4096,
        "file_size": file_size,
    })


@app.route("/api/sandbox/attempts")
def get_sandbox_attempts():
    """Every URL the fetcher has ever looked at, in order, regardless of
    outcome — the activity log. This is what makes dedup skips, SSRF blocks,
    and failed connections visible instead of silent."""
    limit = _int_param(request.args, "limit", 200, cap=1000)
    offset = _int_param(request.args, "offset", 0)
    conn = _get_db()
    try:
        rows = conn.execute(
            """SELECT a.*, s.sha256 AS sample_sha256
               FROM sandbox_fetch_attempts a
               LEFT JOIN sandbox_samples s ON s.id = a.sample_id
               ORDER BY a.id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/sessions")
def get_sessions():
    """Recorded interactive fake-shell drop-ins (SSH/Telnet) — see
    session_recorder.py. Metadata only; the replay itself is fetched
    separately via /api/sessions/<id>/cast."""
    limit = _int_param(request.args, "limit", 100, cap=500)
    offset = _int_param(request.args, "offset", 0)
    conn = _get_db()
    try:
        rows = conn.execute(
            """SELECT id, session_uuid, ip, port, service, username, started_at,
                      duration_s, event_count, command_count
               FROM shell_sessions ORDER BY id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/sessions/by-uuid/<session_uuid>")
def get_session_id_by_uuid(session_uuid):
    """Lets an Events-tab row (which only carries events.connection_id, not
    the shell_sessions integer id) jump straight to its replay — the id is
    what /api/sessions/<id>/cast and the replay modal actually need."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT id FROM shell_sessions WHERE session_uuid = ?", (session_uuid,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row["id"]})


@app.route("/api/sessions/<int:session_id>/cast")
def get_session_cast(session_id):
    """Serves the raw asciinema .cast file for the dashboard's embedded
    player. text/plain, not an attachment — this is our own generated replay
    data (terminal I/O the honeypot itself wrote), not attacker-supplied
    binary content, so there's no download_sandbox_sample-style inline-render
    risk here; asciinema-player parses it as text/NDJSON into a terminal
    emulator, never as HTML."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT cast_path FROM shell_sessions WHERE id = ?", (session_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    # Same cwd-vs-app.root_path gotcha as download_sandbox_sample — cast_path is
    # stored cwd-relative, send_file resolves relative paths against app.root_path.
    abs_path = os.path.abspath(row["cast_path"])
    if not os.path.exists(abs_path):
        return jsonify({"error": "recording missing on disk"}), 404
    return send_file(abs_path, mimetype="text/plain")


def _grouped_connection_sessions(service):
    """Groups events.connection_id (see logger.py / each services/*_honey.py
    handler) into one row per connection for a given protocol, so a full
    interaction — e.g. Redis's SLAVEOF -> MODULE LOAD RCE chain, or an SMTP
    conversation's HELO -> MAIL -> RCPT -> DATA — can be read as a narrative
    instead of scattered rows in the Events tab. Live GROUP BY, not a
    separate summary table per protocol: unlike shell_sessions (which points
    at a binary .cast blob on disk), everything here already lives in the
    events table."""
    limit = _int_param(request.args, "limit", 100, cap=500)
    offset = _int_param(request.args, "offset", 0)
    conn = _get_db()
    try:
        rows = conn.execute(
            """SELECT connection_id, ip,
                      MIN(timestamp) AS started_at, MAX(timestamp) AS ended_at,
                      COUNT(*) AS event_count
               FROM events
               WHERE service = ? AND connection_id IS NOT NULL
               GROUP BY connection_id
               ORDER BY started_at DESC LIMIT ? OFFSET ?""",
            (service, limit, offset),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


def _connection_transcript(service, connection_id):
    conn = _get_db()
    try:
        rows = conn.execute(
            """SELECT id, timestamp, event_type, data FROM events
               WHERE service = ? AND connection_id = ? ORDER BY id ASC""",
            (service, connection_id),
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        return jsonify({"error": "not found"}), 404
    return jsonify([dict(r) for r in rows])


@app.route("/api/redis-sessions")
def get_redis_sessions():
    return _grouped_connection_sessions("REDIS")


@app.route("/api/redis-sessions/<connection_id>")
def get_redis_session_transcript(connection_id):
    return _connection_transcript("REDIS", connection_id)


@app.route("/api/smtp-sessions")
def get_smtp_sessions():
    return _grouped_connection_sessions("SMTP")


@app.route("/api/smtp-sessions/<connection_id>")
def get_smtp_session_transcript(connection_id):
    return _connection_transcript("SMTP", connection_id)


@app.route("/api/ftp-sessions")
def get_ftp_sessions():
    return _grouped_connection_sessions("FTP")


@app.route("/api/ftp-sessions/<connection_id>")
def get_ftp_session_transcript(connection_id):
    return _connection_transcript("FTP", connection_id)


@app.route("/api/mysql-sessions")
def get_mysql_sessions():
    return _grouped_connection_sessions("MYSQL")


@app.route("/api/mysql-sessions/<connection_id>")
def get_mysql_session_transcript(connection_id):
    return _connection_transcript("MYSQL", connection_id)


@app.route("/api/postgres-sessions")
def get_postgres_sessions():
    return _grouped_connection_sessions("POSTGRES")


@app.route("/api/postgres-sessions/<connection_id>")
def get_postgres_session_transcript(connection_id):
    return _connection_transcript("POSTGRES", connection_id)


@app.route("/api/search")
def search_logs():
    """SIEM-style search. `q` is a full query_lang.py expression — see that module's
    docstring for the grammar (field:value, >/>=/</<=, AND/OR/NOT, "-" negation,
    parentheses, quoted phrases). from_date/to_date stay separate query params (they
    drive the time-range buttons in the UI, not the query text)."""
    q = request.args.get("q", "")
    from_date = request.args.get("from_date", "")
    to_date = request.args.get("to_date", "")
    limit = _int_param(request.args, "limit", 100, cap=500)
    offset = _int_param(request.args, "offset", 0)

    try:
        where, params = query_lang.compile_query(q)
    except query_lang.QueryError as e:
        return jsonify({"error": str(e)}), 400

    conditions = [where]
    params = list(params)

    if from_date:
        conditions.append("timestamp >= ?")
        params.append(from_date)
    if to_date:
        conditions.append("timestamp <= ?")
        params.append(to_date + "T23:59:59")

    where_clause = " AND ".join(conditions)
    conn = _get_db()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) as c FROM events WHERE {where_clause}", params
        ).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM events WHERE {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        return jsonify({"total": total, "results": [dict(r) for r in rows]})
    finally:
        conn.close()


@app.route("/api/events/<int:event_id>/review", methods=["POST"])
def set_event_reviewed(event_id):
    body = request.get_json(silent=True) or {}
    reviewed = 1 if body.get("reviewed") else 0
    conn = _get_db()
    try:
        cur = conn.execute("UPDATE events SET reviewed = ? WHERE id = ?", (reviewed, event_id))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
        return jsonify({"id": event_id, "reviewed": bool(reviewed)})
    finally:
        conn.close()


@app.route("/")
def index():
    return render_template(
        "index.html", server_lat=config.SERVER_LAT, server_lon=config.SERVER_LON
    )


@app.route("/api/events/export.csv")
def export_events_csv():
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT id, timestamp, ip, port, service, event_type, data, "
            "country, city, lat, lon, abuse_score, risk_score FROM events ORDER BY timestamp DESC"
        ).fetchall()
        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows([dict(r) for r in rows])
        return Response(
            buf.getvalue(),
            status=200,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=honeypot_events.csv"},
        )
    finally:
        conn.close()


@app.route("/api/stats")
def get_stats():
    """from_date/to_date are optional and scope every figure below to that window
    (same inclusive convention as /api/search — to_date gets T23:59:59 appended).
    Omitting both preserves the original all-time behavior for anything hitting
    this route directly."""
    from_date = request.args.get("from_date", "").strip()
    to_date = request.args.get("to_date", "").strip()

    ts_conditions = []
    ts_params: list = []
    if from_date:
        ts_conditions.append("timestamp >= ?")
        ts_params.append(from_date)
    if to_date:
        ts_conditions.append("timestamp <= ?")
        ts_params.append(to_date + "T23:59:59")
    ts_where = (" AND " + " AND ".join(ts_conditions)) if ts_conditions else ""

    conn = _get_db()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) as c FROM events WHERE 1=1{ts_where}", ts_params
        ).fetchone()["c"]

        by_service = conn.execute(
            f"SELECT service, COUNT(*) as count FROM events WHERE 1=1{ts_where} "
            "GROUP BY service ORDER BY count DESC", ts_params
        ).fetchall()

        top_ips = conn.execute(
            f"SELECT ip, COUNT(*) as count, MAX(risk_score) as max_score FROM events "
            f"WHERE 1=1{ts_where} GROUP BY ip ORDER BY count DESC LIMIT 10", ts_params
        ).fetchall()

        # High-risk IPs, ranked by the local composite risk_score (severity + volume +
        # diversity + AbuseIPDB reputation — see risk_score.py), not raw abuse_score
        # alone: that only covers a couple of event types and misses IPs AbuseIPDB
        # simply hasn't seen yet. Raw abuse_score is still surfaced alongside it.
        high_risk = conn.execute(
            f"SELECT ip, MAX(risk_score) as score, MAX(abuse_score) as abuse_score, "
            f"COUNT(*) as count FROM events WHERE risk_score > 0{ts_where} "
            "GROUP BY ip ORDER BY score DESC LIMIT 10", ts_params
        ).fetchall()

        credential_count = conn.execute(
            f"SELECT COUNT(*) as c FROM events WHERE event_type='credential'{ts_where}", ts_params
        ).fetchone()["c"]

        recent_creds = conn.execute(
            f"SELECT * FROM events WHERE event_type='credential'{ts_where} "
            "ORDER BY timestamp DESC LIMIT 50", ts_params
        ).fetchall()

        payload_count = conn.execute(
            f"SELECT COUNT(*) as c FROM payloads WHERE 1=1{ts_where}", ts_params
        ).fetchone()["c"]

        return jsonify({
            "total": total,
            "by_service": [dict(r) for r in by_service],
            "top_ips": [dict(r) for r in top_ips],
            "high_risk_ips": [dict(r) for r in high_risk],
            "credential_count": credential_count,
            "recent_credentials": [dict(r) for r in recent_creds],
            "payload_count": payload_count,
        })
    finally:
        conn.close()

@app.route("/api/payloads")
def get_payloads():
    limit = _int_param(request.args, "limit", 100, cap=500)
    offset = _int_param(request.args, "offset", 0)
    svc = request.args.get("service")
    conn = _get_db()
    try:
        query = "SELECT id, timestamp, ip, service, filename, file_size, md5, sha256, mime_type, local_path FROM payloads WHERE 1=1"
        params = []
        if svc:
            query += " AND service = ?"
            params.append(svc)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/payloads/<int:payload_id>/content")
def get_payload_content(payload_id):
    """Same text-vs-hex-dump posture as get_sandbox_sample_content. This used
    to have a `except Exception: preview = data.hex()` fallback that was
    actually dead code — str.decode(errors="replace") never raises — so
    binary payloads rendered as replacement-character soup instead of a
    readable hex dump. No architecture column here (that's sandbox-specific
    ELF detection), so the null-byte check is the only binary signal."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT local_path FROM payloads WHERE id = ?", (payload_id,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "not found"}), 404

    local_path = row["local_path"]
    if not os.path.exists(local_path):
        return jsonify({"error": "file missing"}), 404

    file_size = os.path.getsize(local_path)
    with open(local_path, "rb") as f:
        data = f.read(4096)  # cap preview at 4 KB

    if b"\x00" in data:
        preview = _hex_dump(data)
        mode = "hex"
    else:
        preview = data.decode("utf-8", errors="replace")
        mode = "text"

    return jsonify({"preview": preview, "mode": mode, "truncated": file_size > 4096})


@app.route("/api/ids-alerts")
def get_ids_alerts():
    """Dedicated filter params rather than routing through query_lang.py —
    suricata_alerts is a different table with a different, smaller column
    set than events, so reusing the generic query parser would mean either
    teaching it a second schema or silently pretending the two are the same
    shape. A plain filter form gets this tab search parity with Events
    without that risk."""
    limit = min(int(request.args.get("limit", 100)), 500)
    q = request.args.get("q", "").strip()
    severity = request.args.get("severity", "").strip()
    tactic = request.args.get("mitre_tactic", "").strip()
    from_date = request.args.get("from_date", "").strip()
    to_date = request.args.get("to_date", "").strip()
    unreviewed_only = request.args.get("unreviewed_only", "").strip()

    query = "SELECT * FROM suricata_alerts WHERE 1=1"
    params = []
    if q:
        like = f"%{q}%"
        query += " AND (alert_sig LIKE ? OR src_ip LIKE ? OR category LIKE ?)"
        params += [like, like, like]
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if tactic:
        query += " AND mitre_tactic = ?"
        params.append(tactic)
    if unreviewed_only:
        query += " AND reviewed = 0"
    if from_date:
        query += " AND timestamp >= ?"
        params.append(from_date)
    if to_date:
        query += " AND timestamp <= ?"
        params.append(to_date + "T23:59:59")
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    conn = _get_db()
    try:
        rows = conn.execute(query, params).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/ids-alerts/<int:alert_id>")
def get_ids_alert_detail(alert_id):
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM suricata_alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404

        alert = dict(row)
        try:
            alert["raw_parsed"] = json.loads(alert["raw"]) if alert.get("raw") else None
        except (TypeError, ValueError):
            alert["raw_parsed"] = None
        return jsonify(alert)
    finally:
        conn.close()


@app.route("/api/ids-alerts/<int:alert_id>/review", methods=["POST"])
def set_ids_alert_reviewed(alert_id):
    body = request.get_json(silent=True) or {}
    reviewed = 1 if body.get("reviewed") else 0
    conn = _get_db()
    try:
        cur = conn.execute("UPDATE suricata_alerts SET reviewed = ? WHERE id = ?", (reviewed, alert_id))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
        return jsonify({"id": alert_id, "reviewed": bool(reviewed)})
    finally:
        conn.close()


@app.route("/api/ip/<ip>")
def get_ip_profile(ip):
    """Everything the DB knows about one IP: events, IDS alerts, payloads it
    triggered, plus a rollup summary. Powers the click-through "IP profile" view."""
    conn = _get_db()
    try:
        summary = conn.execute(
            "SELECT COUNT(*) as total_events, MIN(timestamp) as first_seen, "
            "MAX(timestamp) as last_seen, MAX(risk_score) as risk_score, "
            "MAX(abuse_score) as abuse_score, COUNT(DISTINCT service) as service_count "
            "FROM events WHERE ip = ?", (ip,)
        ).fetchone()

        geo = conn.execute(
            "SELECT country, city, lat, lon FROM events WHERE ip = ? AND country IS NOT NULL "
            "ORDER BY timestamp DESC LIMIT 1", (ip,)
        ).fetchone()

        services = conn.execute(
            "SELECT service, COUNT(*) as count FROM events WHERE ip = ? "
            "GROUP BY service ORDER BY count DESC", (ip,)
        ).fetchall()

        events = conn.execute(
            "SELECT * FROM events WHERE ip = ? ORDER BY timestamp DESC LIMIT 200", (ip,)
        ).fetchall()

        ids_alerts = conn.execute(
            "SELECT * FROM suricata_alerts WHERE src_ip = ? ORDER BY timestamp DESC LIMIT 100",
            (ip,)
        ).fetchall()

        payloads = conn.execute(
            "SELECT * FROM payloads WHERE ip = ? ORDER BY timestamp DESC LIMIT 100", (ip,)
        ).fetchall()

        return jsonify({
            "ip": ip,
            "total_events": summary["total_events"],
            "first_seen": summary["first_seen"],
            "last_seen": summary["last_seen"],
            "risk_score": summary["risk_score"],
            "abuse_score": summary["abuse_score"],
            "service_count": summary["service_count"],
            "country": geo["country"] if geo else None,
            "city": geo["city"] if geo else None,
            "lat": geo["lat"] if geo else None,
            "lon": geo["lon"] if geo else None,
            "services": [dict(r) for r in services],
            "events": [dict(r) for r in events],
            "ids_alerts": [dict(r) for r in ids_alerts],
            "payloads": [dict(r) for r in payloads],
        })
    finally:
        conn.close()

@app.route("/api/timeline")
def get_timeline():
    """from_date/to_date match /api/stats' convention; omitting from_date preserves
    the original last-24h behavior. Bucket granularity is adaptive: hourly buckets
    ("YYYY-MM-DDTHH") stay readable up to a few days, but a 30-day/all-time range
    would render hundreds of unreadable hour-bars, so anything spanning more than
    3 days buckets by day ("YYYY-MM-DD") instead — same substr trick, shorter slice."""
    from_date = request.args.get("from_date", "").strip()
    to_date = request.args.get("to_date", "").strip()

    if from_date:
        start_ts = from_date
        try:
            span_days = (date.today() - date.fromisoformat(from_date)).days
        except ValueError:
            span_days = 0
        bucket_len = 10 if span_days > 3 else 13
    else:
        start_ts = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        bucket_len = 13

    conditions = ["timestamp >= ?"]
    params: list = [start_ts]
    if to_date:
        conditions.append("timestamp <= ?")
        params.append(to_date + "T23:59:59")
    where = " AND ".join(conditions)

    conn = _get_db()
    try:
        rows = conn.execute(f"""
            SELECT substr(timestamp, 1, {bucket_len}) as hour, COUNT(*) as count
            FROM events
            WHERE {where}
            GROUP BY hour
            ORDER BY hour ASC
        """, params).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()

@app.route("/api/geo-stats")
def get_geo_stats():
    from_date = request.args.get("from_date", "").strip()
    to_date = request.args.get("to_date", "").strip()

    conditions = ["country IS NOT NULL"]
    params: list = []
    if from_date:
        conditions.append("timestamp >= ?")
        params.append(from_date)
    if to_date:
        conditions.append("timestamp <= ?")
        params.append(to_date + "T23:59:59")
    where = " AND ".join(conditions)

    conn = _get_db()
    try:
        rows = conn.execute(f"""
            SELECT country, COUNT(*) as count
            FROM events
            WHERE {where}
            GROUP BY country
            ORDER BY count DESC
            LIMIT 20
        """, params).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()

@app.route("/api/attack-stream")
def attack_stream():
    def generate():
        q: queue.Queue = queue.Queue(maxsize=_SSE_QUEUE_MAX)
        with _client_lock:
            _client_queues.append(q)
        try:
            while True:
                try:
                    msg = q.get(timeout=30)
                    yield f"data: {msg.strip()}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            with _client_lock:
                try:
                    _client_queues.remove(q)
                except ValueError:
                    pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


def _outbox_authorised():
    """Constant-time check of the shared outbox token. Fails closed when unset.

    Guards the endpoints below, which let something on your trusted network drain
    alerts and events from this host without it ever having to call out. See
    config.py and README.md.
    """
    if not config.OUTBOX_TOKEN:
        return False
    return hmac.compare_digest(request.headers.get("X-Outbox-Token", ""), config.OUTBOX_TOKEN)


@app.route("/api/alerts/pending")
def alerts_pending():
    """Alerts waiting to be delivered, oldest first.

    Meant to be drained by something on your trusted network that owns the actual
    Discord webhook (or other notifier) — this host never talks out to Discord itself.
    """
    if not _outbox_authorised():
        return jsonify({"error": "forbidden"}), 403

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except ValueError:
        limit = 50

    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT id, created, payload FROM alert_outbox ORDER BY id ASC LIMIT ?",
            (limit,),
        ).fetchall()
        return jsonify([
            {"id": r["id"], "created": r["created"], "payload": json.loads(r["payload"])}
            for r in rows
        ])
    finally:
        conn.close()


@app.route("/api/events/since")
def events_since():
    """Events with id greater than `id`, oldest first — incremental tail.

    Useful for something on your trusted network that wants to mirror events out
    (e.g. into an IDS/IPS's own log ingestion) without this host reaching out itself.

    Ordered by id, not timestamp: id is monotonic, timestamps are not guaranteed to
    be, and a puller relying on a strict watermark needs that guarantee to avoid
    re-sending or skipping.
    """
    if not _outbox_authorised():
        return jsonify({"error": "forbidden"}), 403

    try:
        since_id = int(request.args.get("id", 0))
    except ValueError:
        since_id = 0
    try:
        limit = min(int(request.args.get("limit", 500)), 2000)
    except ValueError:
        limit = 500

    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
            (since_id, limit),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/alerts/ack", methods=["POST"])
def alerts_ack():
    """Delete alerts that have been successfully delivered elsewhere."""
    if not _outbox_authorised():
        return jsonify({"error": "forbidden"}), 403

    body = request.get_json(silent=True) or {}
    ids = body.get("ids") or []
    # Only accept ints, so the ids can never be used to shape the SQL.
    ids = [int(i) for i in ids if isinstance(i, int) or str(i).isdigit()]
    if not ids:
        return jsonify({"deleted": 0})

    conn = _get_db()
    try:
        placeholders = ",".join("?" * len(ids))
        cur = conn.execute(
            f"DELETE FROM alert_outbox WHERE id IN ({placeholders})", ids
        )
        conn.commit()
        return jsonify({"deleted": cur.rowcount})
    finally:
        conn.close()


def start_dashboard():
    app.run(
        host="0.0.0.0",
        port=config.DASHBOARD_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
    )
