import json
import queue
import sqlite3
import threading
import csv
import io
from datetime import datetime, timedelta, timezone
from flask import Flask, Response, jsonify, render_template, stream_with_context, request
from config import DB_PATH, DASHBOARD_PORT, SERVER_LAT, SERVER_LON
from logger import register_event_callback

app = Flask(__name__)

_client_queues: list = []
_client_lock = threading.Lock()
_SSE_QUEUE_MAX = 100


def _get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def publish_attack_event(event_dict):
    """Push geo-tagged events to all connected SSE clients (logger callback)."""
    lat = event_dict.get("lat")
    lon = event_dict.get("lon")
    if lat is None or lon is None:
        return
    payload = {
        "src_lat": lat,
        "src_lon": lon,
        "dst_lat": SERVER_LAT,
        "dst_lon": SERVER_LON,
        "service": event_dict.get("service"),
        "country": event_dict.get("country"),
        "ip": event_dict.get("ip"),
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


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def get_events():
    svc = request.args.get("service")
    etype = request.args.get("event_type")
    search = request.args.get("search")
    limit = min(int(request.args.get("limit", 200)), 1000)
    offset = int(request.args.get("offset", 0))

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
def export_csv():
    def generate():
        conn = _get_db()
        # Use a separate cursor for streaming
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events ORDER BY timestamp DESC")
        
        # Write header
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Get column names from description
        header = [column[0] for column in cursor.description]
        writer.writerow(header)
        yield output.getvalue()
        output.truncate(0)
        output.seek(0)

        while True:
            rows = cursor.fetchmany(100)
            if not rows:
                break
            for row in rows:
                writer.writerow(row)
            yield output.getvalue()
            output.truncate(0)
            output.seek(0)
        conn.close()

    return Response(
        stream_with_context(generate()),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=honeypot_events.csv"}
    )


@app.route("/api/stats")
def get_stats():
    conn = _get_db()
    try:
        total = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]

        by_service = conn.execute(
            "SELECT service, COUNT(*) as count FROM events GROUP BY service ORDER BY count DESC"
        ).fetchall()

        top_ips = conn.execute(
            "SELECT ip, COUNT(*) as count FROM events GROUP BY ip ORDER BY count DESC LIMIT 10"
        ).fetchall()

        credential_count = conn.execute(
            "SELECT COUNT(*) as c FROM events WHERE event_type='credential'"
        ).fetchone()["c"]

        # Recent high-value events
        recent_creds = conn.execute(
            "SELECT * FROM events WHERE event_type='credential' ORDER BY timestamp DESC LIMIT 50"
        ).fetchall()

        return jsonify({
            "total": total,
            "by_service": [dict(r) for r in by_service],
            "top_ips": [dict(r) for r in top_ips],
            "credential_count": credential_count,
            "recent_credentials": [dict(r) for r in recent_creds],
        })
    finally:
        conn.close()


@app.route("/api/timeline")
def get_timeline():
    # Last 24 hours timeline
    conn = _get_db()
    try:
        # SQLite substr(timestamp, 1, 13) gets YYYY-MM-DDTHH
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
        port=DASHBOARD_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
    )
