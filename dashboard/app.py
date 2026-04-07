import json
import queue
import sqlite3
import threading
import csv
import io
import os
from datetime import datetime, timedelta, timezone
from flask import Flask, Response, jsonify, render_template, stream_with_context, request
import config
from logger import register_event_callback

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
        "abuse_score": event_dict.get("abuse_score", 0)
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
                "event_type": "set_attempt", "label": "SET Payload",
                "desc": "Value written via SET saved as payload (cron/key injection)",
                "mitre_id": "T1053.003", "mitre_technique": "Scheduled Task: Cron",
                "mitre_tactic": "Persistence",
                "mitre_url": "https://attack.mitre.org/techniques/T1053/003/",
            },
            {
                "event_type": "eval_attempt", "label": "EVAL Script",
                "desc": "Lua script via EVAL captured as payload",
                "mitre_id": "T1059", "mitre_technique": "Command and Scripting Interpreter",
                "mitre_tactic": "Execution",
                "mitre_url": "https://attack.mitre.org/techniques/T1059/",
            },
            {
                "event_type": "command", "label": "Unknown Command",
                "desc": "Unrecognised commands logged and saved as payload",
                "mitre_id": "T1210", "mitre_technique": "Exploitation of Remote Services",
                "mitre_tactic": "Lateral Movement",
                "mitre_url": "https://attack.mitre.org/techniques/T1210/",
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


@app.route("/api/search")
def search_logs():
    q = request.args.get("q", "").strip()
    svc = request.args.get("service", "")
    etype = request.args.get("event_type", "")
    ip_filter = request.args.get("ip", "").strip()
    from_date = request.args.get("from_date", "")
    to_date = request.args.get("to_date", "")
    limit = _int_param(request.args, "limit", 100, cap=500)
    offset = _int_param(request.args, "offset", 0)

    conditions = ["1=1"]
    params = []

    if q:
        conditions.append("(ip LIKE ? OR data LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    if ip_filter:
        conditions.append("ip LIKE ?")
        params.append(ip_filter.replace("*", "%"))
    if svc:
        conditions.append("service = ?")
        params.append(svc)
    if etype:
        conditions.append("event_type = ?")
        params.append(etype)
    if from_date:
        conditions.append("timestamp >= ?")
        params.append(from_date)
    if to_date:
        conditions.append("timestamp <= ?")
        params.append(to_date + "T23:59:59")

    where = " AND ".join(conditions)
    conn = _get_db()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) as c FROM events WHERE {where}", params
        ).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        return jsonify({"total": total, "results": [dict(r) for r in rows]})
    finally:
        conn.close()


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/config", methods=["GET", "POST"])
def manage_config():
    if request.method == "POST":
        data = request.json or {}
        # Update .env file (simplified version)
        env_updates = {
            "DISCORD_WEBHOOK_URL": data.get("discord_webhook_url"),
            "ABUSEIPDB_API_KEY": data.get("abuseipdb_api_key"),
            "GEMINI_API_KEY": data.get("gemini_api_key"),
            "VIRUSTOTAL_API_KEY": data.get("virustotal_api_key"),
            "ALERT_ON_CONNECT": "1" if data.get("alerts", {}).get("on_connect") else "0",
            "ALERT_ON_CREDENTIAL": "1" if data.get("alerts", {}).get("on_credential") else "0",
            "ALERT_ON_EXEC": "1" if data.get("alerts", {}).get("on_exec") else "0",
            "ALERT_ON_DOWNLOAD": "1" if data.get("alerts", {}).get("on_download") else "0",
        }
        
        try:
            # Read existing .env
            lines = []
            if os.path.exists(".env"):
                with open(".env", "r") as f:
                    lines = f.readlines()
            
            # Update or append
            for key, val in env_updates.items():
                if val is None: continue
                found = False
                for i, line in enumerate(lines):
                    if line.startswith(f"{key}="):
                        lines[i] = f"{key}={val}\n"
                        found = True
                        break
                if not found:
                    lines.append(f"{key}={val}\n")
            
            with open(".env", "w") as f:
                f.writelines(lines)
                
            return jsonify({"status": "success", "message": "Settings saved. Restart container to apply."})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({
        "discord_webhook_url": config.DISCORD_WEBHOOK_URL,
        "abuseipdb_api_key": config.ABUSEIPDB_API_KEY,
        "gemini_api_key": config.GEMINI_API_KEY,
        "virustotal_api_key": config.VIRUSTOTAL_API_KEY,
        "alerts": {
            "on_connect": config.ALERT_ON_CONNECT,
            "on_credential": config.ALERT_ON_CREDENTIAL,
            "on_exec": config.ALERT_ON_EXEC,
            "on_download": config.ALERT_ON_DOWNLOAD
        },
        "server_location": {"lat": config.SERVER_LAT, "lon": config.SERVER_LON}
    })

@app.route("/api/events")
def get_events():
    svc = request.args.get("service")
    etype = request.args.get("event_type")
    search = request.args.get("search")
    limit = _int_param(request.args, "limit", 200, cap=1000)
    offset = _int_param(request.args, "offset", 0)

    query = "SELECT * FROM events WHERE 1=1"
    params = []

    if svc:
        query += " AND service = ?"
        params.append(svc)
    if etype:
        query += " AND event_type = ?"
        params.append(etype)
    if search:
        query += " AND ip LIKE ?"
        params.append(f"{search}%")

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    conn = _get_db()
    try:
        rows = conn.execute(query, params).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/events/export.csv")
def export_events_csv():
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT id, timestamp, ip, port, service, event_type, data, "
            "country, city, lat, lon, abuse_score FROM events ORDER BY timestamp DESC"
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
    conn = _get_db()
    try:
        total = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]

        by_service = conn.execute(
            "SELECT service, COUNT(*) as count FROM events GROUP BY service ORDER BY count DESC"
        ).fetchall()

        top_ips = conn.execute(
            "SELECT ip, COUNT(*) as count, MAX(abuse_score) as max_score FROM events GROUP BY ip ORDER BY count DESC LIMIT 10"
        ).fetchall()

        # High-risk IPs (Top Abuse Scores)
        high_risk = conn.execute(
            "SELECT ip, MAX(abuse_score) as score, COUNT(*) as count FROM events WHERE abuse_score > 0 GROUP BY ip ORDER BY score DESC LIMIT 10"
        ).fetchall()

        credential_count = conn.execute(
            "SELECT COUNT(*) as c FROM events WHERE event_type='credential'"
        ).fetchone()["c"]

        recent_creds = conn.execute(
            "SELECT * FROM events WHERE event_type='credential' ORDER BY timestamp DESC LIMIT 50"
        ).fetchall()

        payload_count = conn.execute("SELECT COUNT(*) as c FROM payloads").fetchone()["c"]

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
        query = "SELECT id, timestamp, ip, service, filename, file_size, md5, sha256, mime_type, local_path, vt_score FROM payloads WHERE 1=1"
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
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT local_path, mime_type FROM payloads WHERE id = ?", (payload_id,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "not found"}), 404

    import os
    local_path = row["local_path"]
    if not os.path.exists(local_path):
        return jsonify({"error": "file missing"}), 404

    with open(local_path, "rb") as f:
        data = f.read(4096)  # cap preview at 4 KB

    try:
        preview = data.decode("utf-8", errors="replace")
    except Exception:
        preview = data.hex()

    return jsonify({"preview": preview, "truncated": os.path.getsize(local_path) > 4096})


@app.route("/api/ids-alerts")
def get_ids_alerts():
    limit = min(int(request.args.get("limit", 100)), 500)
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM suricata_alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()

@app.route("/api/timeline")
def get_timeline():
    conn = _get_db()
    try:
        rows = conn.execute("""
            SELECT substr(timestamp, 1, 13) as hour, COUNT(*) as count
            FROM events
            WHERE timestamp > ?
            GROUP BY hour
            ORDER BY hour ASC
        """, ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),)).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()

@app.route("/api/geo-stats")
def get_geo_stats():
    conn = _get_db()
    try:
        rows = conn.execute("""
            SELECT country, COUNT(*) as count
            FROM events
            WHERE country IS NOT NULL
            GROUP BY country
            ORDER BY count DESC
            LIMIT 20
        """).fetchall()
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

def start_dashboard():
    app.run(
        host="0.0.0.0",
        port=config.DASHBOARD_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
    )
