import os
import json
import sqlite3
import urllib.request
import logging
from datetime import datetime, timezone
from pathlib import Path

# Load env variables (if dotenv is installed, prioritize that)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("alerter")

DB_PATH = "dwtis.db"
ALERTS_JSONL_PATH = "critical_alerts.jsonl"
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

def push_webhook(payload: dict):
    if not WEBHOOK_URL:
        return
    try:
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "DWTIS-Alerter"}
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        log.error(f"Failed to push to webhook: {e}")

def dump_file(payload: dict):
    try:
        with open(ALERTS_JSONL_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception as e:
        log.error(f"Failed to write to {ALERTS_JSONL_PATH}: {e}")

def pull_and_dispatch_alerts(db_path: str = DB_PATH):
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    dispatched = 0

    # 1. P1/P2 Standard NLP Alerts
    try:
        standard_alerts = conn.execute(
            "SELECT id, severity, score, message, source, timestamp FROM alerts WHERE seen = 0 AND severity IN ('P1', 'P2') ORDER BY score DESC"
        ).fetchall()

        for a_id, severity, score, message, source, timestamp in standard_alerts:
            payload = {
                "alert_type": "standard",
                "severity": severity,
                "score": float(f"{score:.3f}"),
                "source": source,
                "timestamp": timestamp,
                "message": message,
                "dispatched_at": datetime.now(timezone.utc).isoformat()
            }
            dump_file(payload)
            push_webhook(payload)
            conn.execute("UPDATE alerts SET seen = 1 WHERE id = ?", (a_id,))
            dispatched += 1
            
        if standard_alerts:
            conn.commit()
    except Exception as e:
        log.error(f"Error dispatching standard alerts: {e}")

    # 2. Correlation Alerts
    try:
        corr_alerts = conn.execute(
            "SELECT id, org, severity, message, timestamp FROM correlation_events WHERE seen = 0"
        ).fetchall()

        for c_id, org, severity, message, timestamp in corr_alerts:
            payload = {
                "alert_type": "cross_source_correlation",
                "severity": severity,
                "org": org,
                "timestamp": timestamp,
                "message": message,
                "dispatched_at": datetime.now(timezone.utc).isoformat()
            }
            dump_file(payload)
            push_webhook(payload)
            conn.execute("UPDATE correlation_events SET seen = 1 WHERE id = ?", (c_id,))
            dispatched += 1

        if corr_alerts:
            conn.commit()
    except Exception as e:
        log.error(f"Error dispatching correlation alerts: {e}")

    conn.close()
    if dispatched > 0:
        log.info(f"Dispatched {dispatched} new critical alerts.")
    return dispatched

if __name__ == "__main__":
    pull_and_dispatch_alerts()
