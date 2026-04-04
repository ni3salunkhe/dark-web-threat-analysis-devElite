import asyncio
import json
import sqlite3
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

app = FastAPI(title="DWTIS Threat Alert API")

# Enable CORS for the future React frontend (can restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows any React dev server to connect
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "dwtis.db"

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = dict_factory
    return conn

@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    """
    Fetch historical P1/P2 operational alerts.
    Used by React to populate the in-app notification bell / dashboard.
    """
    conn = get_db()
    try:
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE severity IN ('P1', 'P2') ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        
        correlations = conn.execute(
            "SELECT * FROM correlation_events ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        
        return {
            "status": "success",
            "standard_alerts": alerts,
            "correlation_alerts": correlations
        }
    finally:
        conn.close()

@app.get("/api/stats")
def get_stats():
    """Returns high-level statistics for the React dashboard."""
    conn = get_db()
    try:
        total_raw = conn.execute("SELECT COUNT(*) as c FROM raw_posts").fetchone()["c"]
        total_processed = conn.execute("SELECT COUNT(*) as c FROM processed_posts").fetchone()["c"]
        total_breaches = conn.execute("SELECT COUNT(*) as c FROM breach_findings").fetchone()["c"]
        total_alerts = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]
        return {
            "status": "success",
            "stats": {
                "total_raw_collected": total_raw,
                "total_nlp_processed": total_processed,
                "total_breaches_found": total_breaches,
                "total_alerts_generated": total_alerts
            }
        }
    finally:
        conn.close()

@app.get("/api/breaches")
def get_breaches(limit: int = 50):
    """Returns the latest breach findings."""
    conn = get_db()
    try:
        breaches = conn.execute(
            "SELECT * FROM breach_findings ORDER BY discovered_at DESC LIMIT ?", (limit,)
        ).fetchall()
        # Parse JSON payload dynamically if needed
        for b in breaches:
            try:
                b["data_classes"] = json.loads(b.get("data_classes", "[]"))
                b["raw_json"] = json.loads(b.get("raw_json", "{}"))
            except Exception:
                pass
        return {"status": "success", "breaches": breaches}
    finally:
        conn.close()

@app.get("/api/threats")
def get_threats(limit: int = 50):
    """Returns all processed threat posts, including benign ones for the feed."""
    conn = get_db()
    try:
        posts = conn.execute(
            "SELECT * FROM processed_posts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        for p in posts:
            try:
                p["entities_json"] = json.loads(p.get("entities_json", "{}"))
                p["slang_json"] = json.loads(p.get("slang_json", "{}"))
                p["classification_json"] = json.loads(p.get("classification_json", "{}"))
                p["impact_json"] = json.loads(p.get("impact_json", "{}"))
            except Exception:
                pass
        return {"status": "success", "threats": posts}
    finally:
        conn.close()

@app.get("/api/alerts/stream")
async def stream_alerts(request: Request):
    """
    Server-Sent Events (SSE) stream for live push notifications.
    React connects here (e.g. via EventSource) to get live push alerts.
    """
    async def event_generator():
        last_check_id_alert = 0
        last_check_id_corr = 0
        
        # Initialize highest IDs so we don't dump the whole DB on connect
        conn = get_db()
        try:
            row_alert = conn.execute("SELECT MAX(id) as max_id FROM alerts").fetchone()
            if row_alert and row_alert["max_id"]:
                last_check_id_alert = row_alert["max_id"]
                
            row_corr = conn.execute("SELECT MAX(id) as max_id FROM correlation_events").fetchone()
            if row_corr and row_corr["max_id"]:
                last_check_id_corr = row_corr["max_id"]
        finally:
            conn.close()

        while True:
            # If client disconnects, stop sending
            if await request.is_disconnected():
                break

            conn = get_db()
            try:
                # Check for new Standard Alerts
                new_alerts = conn.execute(
                    "SELECT * FROM alerts WHERE id > ? AND severity IN ('P1', 'P2') ORDER BY id ASC",
                    (last_check_id_alert,)
                ).fetchall()
                
                for alert in new_alerts:
                    last_check_id_alert = alert["id"]
                    payload = json.dumps({"type": "standard", "data": alert})
                    yield f"data: {payload}\n\n"
                
                # Check for new Correlation Alerts
                new_corrs = conn.execute(
                    "SELECT * FROM correlation_events WHERE id > ? ORDER BY id ASC",
                    (last_check_id_corr,)
                ).fetchall()
                
                for corr in new_corrs:
                    last_check_id_corr = corr["id"]
                    payload = json.dumps({"type": "correlation", "data": corr})
                    yield f"data: {payload}\n\n"

            except sqlite3.OperationalError:
                pass  # DB might be locked occasionally during writes
            finally:
                conn.close()

            # Poll every 2 seconds
            await asyncio.sleep(2)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    print("=" * 55)
    print("  DWTIS React API Server Starting...")
    print("  - Make sure dwtis.db exists.")
    print("  - React can connect to: http://localhost:8000/api/alerts")
    print("  - SSE Stream available at: http://localhost:8000/api/alerts/stream")
    print("=" * 55)
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
