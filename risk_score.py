"""
Locally-computed composite risk score (0-100) for each event.

Unlike abuse_score (AbuseIPDB's global reputation number — see threat_intel.py), this
runs entirely on data already in this honeypot's own database: no API call, no quota,
no new egress. It blends four signals:

  - severity  — how dangerous is *this event's type* (a bare connect vs. an actual
                exec/eval attempt)
  - volume    — how much activity has this IP generated against this honeypot,
                log-scaled so the 500th hit doesn't count 500x a first hit
  - diversity — how many distinct services has this IP touched (broad recon across
                SSH+HTTP+Redis is a different class of actor than one hitting a
                single port)
  - abuse     — AbuseIPDB's reputation for this IP, if we have it (0 if not — an
                unknown-to-AbuseIPDB IP is not assumed innocent, just unscored on
                that axis)

Computed once per event, at the values true *at that moment* — earlier events from an
IP keep the (lower) score they had before a pattern was established, rather than being
rewritten after the fact. That's a feature: the score history shows the honeypot's
assessment evolving as an IP's behavior accumulates, the way a human analyst's would.
"""

import math
import sqlite3
from config import DB_PATH

_EVENT_SEVERITY = {
    "rate_limited": 5,
    "connect": 10,
    "request": 15,
    "trap_hit": 20,
    "email_attempt": 35,
    "pubkey_attempt": 40,
    "credential": 45,
    "command": 55,
    "set_attempt": 70,
    "exec_attempt": 80,
    "download_attempt": 85,
    "eval_attempt": 85,
}
_DEFAULT_SEVERITY = 20

_W_SEVERITY = 0.30
_W_VOLUME = 0.20
_W_DIVERSITY = 0.20
_W_ABUSE = 0.30


def _volume_component(ip_event_count):
    # log-scaled: 1 hit -> 0, ~10 -> ~40, ~100 -> ~80, saturates approaching 100
    return max(0.0, min(100.0, 40 * math.log10(ip_event_count + 1)))


def _diversity_component(distinct_service_count):
    # 1 service -> 0, 2 -> 25, 3 -> 50, 4 -> 75, 5+ -> 100
    return max(0.0, min(100.0, (distinct_service_count - 1) * 25))


def compute_risk_score(event_type, ip_event_count, ip_service_count, abuse_score):
    severity = _EVENT_SEVERITY.get(event_type, _DEFAULT_SEVERITY)
    volume = _volume_component(ip_event_count)
    diversity = _diversity_component(ip_service_count)
    abuse = abuse_score if abuse_score is not None else 0

    score = (
        _W_SEVERITY * severity
        + _W_VOLUME * volume
        + _W_DIVERSITY * diversity
        + _W_ABUSE * abuse
    )
    return round(max(0, min(100, score)))


def score_and_store(rowid, ip, event_type, conn=None):
    """Compute risk_score for one event row and write it. Reuses a caller-supplied
    connection when given (log_event already has one open); opens its own otherwise
    (threat_intel.py calls this from a background thread after an async AbuseIPDB
    lookup completes, well after the original connection is closed).
    """
    owns_conn = conn is None
    if owns_conn:
        conn = sqlite3.connect(DB_PATH)
    try:
        ip_event_count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE ip = ?", (ip,)
        ).fetchone()[0]
        ip_service_count = conn.execute(
            "SELECT COUNT(DISTINCT service) FROM events WHERE ip = ?", (ip,)
        ).fetchone()[0]
        # Most recent known AbuseIPDB score for this IP, if any event has one yet.
        row = conn.execute(
            "SELECT abuse_score FROM events WHERE ip = ? AND abuse_score IS NOT NULL "
            "ORDER BY id DESC LIMIT 1",
            (ip,),
        ).fetchone()
        abuse_score = row[0] if row else None

        score = compute_risk_score(event_type, ip_event_count, ip_service_count, abuse_score)
        conn.execute("UPDATE events SET risk_score = ? WHERE id = ?", (score, rowid))
        if owns_conn:
            conn.commit()
        return score
    finally:
        if owns_conn:
            conn.close()
