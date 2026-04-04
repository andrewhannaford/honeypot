import sqlite3
from flask import Flask, render_template, jsonify
from config import DB_PATH, DASHBOARD_PORT

app = Flask(__name__)


def _get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def get_events():
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT 200"
        ).fetchall()
        return jsonify([dict(r) for r in rows])
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
            "SELECT ip, COUNT(*) as count FROM events GROUP BY ip ORDER BY count DESC LIMIT 10"
        ).fetchall()

        credential_count = conn.execute(
            "SELECT COUNT(*) as c FROM events WHERE event_type='credential'"
        ).fetchone()["c"]

        credentials = conn.execute(
            "SELECT * FROM events WHERE event_type='credential' ORDER BY timestamp DESC LIMIT 100"
        ).fetchall()

        return jsonify({
            "total": total,
            "by_service": [dict(r) for r in by_service],
            "top_ips": [dict(r) for r in top_ips],
            "credential_count": credential_count,
            "credentials": [dict(r) for r in credentials],
        })
    finally:
        conn.close()


def start_dashboard():
    app.run(host="0.0.0.0", port=DASHBOARD_PORT, debug=False, use_reloader=False)
