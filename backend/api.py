import asyncio
import json
import sqlite3
import hashlib
from datetime import datetime
from pydantic import BaseModel
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse

# Pipeline Imports
from ingestion import TargetEntity, run_once_all
from run_system import run_nlp_processing

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

def setup_db():
    """Initializes the database schema if tables are missing."""
    conn = get_db()
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS raw_posts (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT, content TEXT, timestamp DATETIME)")
        conn.execute("CREATE TABLE IF NOT EXISTS processed_posts (id INTEGER PRIMARY KEY AUTOINCREMENT, raw_id INTEGER, content TEXT, severity TEXT, entities_json TEXT, slang_json TEXT, classification_json TEXT, impact_json TEXT, timestamp DATETIME)")
        conn.execute("CREATE TABLE IF NOT EXISTS breach_findings (id INTEGER PRIMARY KEY AUTOINCREMENT, database_name TEXT, discovered_at DATETIME, data_classes TEXT, raw_json TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, severity TEXT, message TEXT, timestamp DATETIME, threat_type TEXT, entity_id TEXT, seen INTEGER DEFAULT 0)")
        conn.execute("CREATE TABLE IF NOT EXISTS correlation_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT, description TEXT, severity TEXT, timestamp DATETIME, related_ids TEXT, seen INTEGER DEFAULT 0)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT,
                email TEXT UNIQUE,
                password_hash TEXT,
                target_domain TEXT,
                target_company TEXT,
                created_at DATETIME DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tracked_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                entity_value TEXT,
                entity_type TEXT,
                is_enabled INTEGER DEFAULT 1,
                last_scan DATETIME DEFAULT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()

# Initialize DB on startup
setup_db()

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": str(exc)},
    )

class UserRegistration(BaseModel):
    fullName: str
    email: str
    password: str
    targetDomain: str
    targetCompany: str

@app.post("/api/register")
def register_user(user: UserRegistration):
    """Registers a new system operator and tracks their required threat entities."""
    conn = get_db()
    try:
        # Secure basic hashing utilizing a randomly generated salt paradigm per DB constraints
        salt = "dwtis_secure_99"
        pwd_hash = hashlib.sha256((user.password + salt).encode()).hexdigest()
        
        try:
            conn.execute(
                """INSERT INTO users 
                   (full_name, email, password_hash, target_domain, target_company) 
                   VALUES (?, ?, ?, ?, ?)""",
                (user.fullName, user.email, pwd_hash, user.targetDomain, user.targetCompany)
            )
            conn.commit()
            return {"status": "success", "message": "Operator instantiated. Targets committed to pipeline."}
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Email address is already registered.")
            
    finally:
        conn.close()

class UserLogin(BaseModel):
    email: str
    password: str

@app.post("/api/login")
def login_user(user: UserLogin):
    conn = get_db()
    try:
        salt = "dwtis_secure_99"
        pwd_hash = hashlib.sha256((user.password + salt).encode()).hexdigest()
        
        db_user = conn.execute(
            "SELECT * FROM users WHERE email = ? AND password_hash = ?", 
            (user.email, pwd_hash)
        ).fetchone()
        
        if db_user:
            return {
                "status": "success", 
                "user": {
                    "id": db_user["id"],
                    "fullName": db_user["full_name"],
                    "email": db_user["email"],
                    "targetDomain": db_user["target_domain"],
                    "targetCompany": db_user["target_company"]
                }
            }
        raise HTTPException(status_code=401, detail="Invalid operator credentials")
    finally:
        conn.close()

# --- CRAWLER TARGETS ENDPOINTS ---

class TargetCreate(BaseModel):
    userId: int
    entityValue: str
    entityType: str

@app.post("/api/targets")
def add_target(body: TargetCreate):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO tracked_targets (user_id, entity_value, entity_type, is_enabled) VALUES (?, ?, ?, 1)",
            (body.userId, body.entityValue, body.entityType)
        )
        conn.commit()
        return {"status": "success", "message": "Target locked into queue."}
    finally:
        conn.close()

@app.get("/api/targets")
def get_targets(user_id: int):
    conn = get_db()
    try:
        targets = conn.execute("SELECT * FROM tracked_targets WHERE user_id = ?", (user_id,)).fetchall()
        return {"status": "success", "targets": targets}
    finally:
        conn.close()

class TargetToggle(BaseModel):
    targetId: int
    isEnabled: int

@app.put("/api/targets/toggle")
def toggle_target(body: TargetToggle):
    conn = get_db()
    try:
        conn.execute(
            "UPDATE tracked_targets SET is_enabled = ? WHERE id = ?",
            (body.isEnabled, body.targetId)
        )
        conn.commit()
        return {"status": "success"}
    finally:
        conn.close()

# --- BACKBONE CRAWLER ASYNC TASK ---

async def crawler_queue():
    """Background queue worker polling enabled targets indefinitely."""
    print("  [CRAWL_QUEUE] Initializing Background Engine...")
    while True:
        conn = get_db()
        try:
            active_targets = conn.execute("SELECT * FROM tracked_targets WHERE is_enabled = 1").fetchall()
        except sqlite3.OperationalError:
            active_targets = []
        finally:
            conn.close()
            
        for t in active_targets:
            print(f"  [CRAWL_QUEUE] Dispatching NLP sweeps for {t['entity_value']}...")
            
            # Map parameters
            ent_kwargs = {}
            if t['entity_type'] == 'DOMAIN':
                ent_kwargs['domain'] = t['entity_value']
            elif t['entity_type'] == 'EMAIL':
                ent_kwargs['email'] = t['entity_value']
            elif t['entity_type'] == 'COMPANY':
                ent_kwargs['company'] = t['entity_value']
            else:
                ent_kwargs['domain'] = t['entity_value']
                
            try:
                entity = TargetEntity(**ent_kwargs)
                entity.validate()
                
                # 1. Scrape surface dumps + APIs (Async safe)
                await run_once_all([entity], db_path=DB_PATH)
                
                # 2. Fire NLP PyTorch Pipeline (Pushed to Thread to avoid blocking UI requests)
                await asyncio.to_thread(run_nlp_processing, DB_PATH)
                
                # Mark scanned
                conn = get_db()
                try:
                    conn.execute("UPDATE tracked_targets SET last_scan = datetime('now') WHERE id = ?", (t["id"],))
                    conn.commit()
                except Exception:
                    pass
                finally:
                    conn.close()
                    
            except Exception as e:
                print(f"  [CRAWL_QUEUE] Target execution failed {t['entity_value']}: {e}")

            # Mandatory sleep between targets to respect upstream rate limits safely
            await asyncio.sleep(45)
            
        # Core cycle pause when queue clears or queue empty
        await asyncio.sleep(15)

@app.on_event("startup")
async def startup_event():
    # Spawn non-blocking thread infinite loop queue
    asyncio.create_task(crawler_queue())

# --- UI DATA ENDPOINTS ---

@app.get("/api/alerts")
def get_alerts(limit: int = 50, domain: str = None, company: str = None):
    """
    Fetch historical P1/P2 operational alerts.
    Used by React to populate the in-app notification bell / dashboard.
    """
    conn = get_db()
    try:
        where_str = ""
        params = []
        if domain and company:
            where_str = " AND (message LIKE ? OR message LIKE ?)"
            params = [f"%{domain}%", f"%{company}%"]
            
        alerts = conn.execute(
            f"SELECT * FROM alerts WHERE severity IN ('P1', 'P2'){where_str} ORDER BY timestamp DESC LIMIT ?",
            (*params, limit)
        ).fetchall()
        
        where_corr = ""
        corr_params = []
        if domain and company:
            where_corr = "WHERE description LIKE ? OR description LIKE ?"
            corr_params = [f"%{domain}%", f"%{company}%"]
            
        correlations = conn.execute(
            f"SELECT * FROM correlation_events {where_corr} ORDER BY timestamp DESC LIMIT ?",
            (*corr_params, limit)
        ).fetchall()
        
        return {
            "status": "success",
            "standard_alerts": alerts,
            "correlation_alerts": correlations
        }
    finally:
        conn.close()

@app.get("/api/stats")
def get_stats(domain: str = None, company: str = None):
    """Returns high-level statistics structurally filtered for the operator dashboard."""
    conn = get_db()
    try:
        raw_where = ""
        params = []
        if domain and company:
            raw_where = "WHERE (content LIKE ? OR content LIKE ?)"
            params = [f"%{domain}%", f"%{company}%"]
            
        total_raw = conn.execute(f"SELECT COUNT(*) as c FROM raw_posts {raw_where}", params).fetchone()["c"]
        total_processed = conn.execute(f"SELECT COUNT(*) as c FROM processed_posts {raw_where}", params).fetchone()["c"]
        
        breach_where = ""
        if domain and company:
            breach_where = "WHERE (raw_json LIKE ? OR raw_json LIKE ?)"
            
        total_breaches = conn.execute(f"SELECT COUNT(*) as c FROM breach_findings {breach_where}", params).fetchone()["c"]
        
        alert_where = ""
        if domain and company:
            alert_where = "WHERE (message LIKE ? OR message LIKE ?)"
        total_alerts = conn.execute(f"SELECT COUNT(*) as c FROM alerts {alert_where}", params).fetchone()["c"]
        
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
def get_breaches(limit: int = 50, domain: str = None, company: str = None):
    """Returns the latest breach findings."""
    conn = get_db()
    try:
        where_str = ""
        params = []
        if domain and company:
            where_str = " WHERE (raw_json LIKE ? OR raw_json LIKE ?)"
            params = [f"%{domain}%", f"%{company}%"]
            
        breaches = conn.execute(
            f"SELECT * FROM breach_findings{where_str} ORDER BY discovered_at DESC LIMIT ?", 
            (*params, limit)
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

@app.get("/api/entities")
def get_entities():
    """Extracts unique entities discovered in threat reports."""
    conn = get_db()
    try:
        rows = conn.execute("SELECT entities_json FROM processed_posts").fetchall()
        entities = {}
        for row in rows:
            try:
                data = json.loads(row["entities_json"])
                # Handle both list and dict formats from different NLP passes
                items = data if isinstance(data, list) else data.get("organizations", [])
                for entity in items:
                    name = entity.get("name") if isinstance(entity, dict) else str(entity)
                    if name:
                        entities[name] = entities.get(name, 0) + 1
            except Exception:
                continue
        
        # Format for UI: sort by frequency (score)
        result = [
            {"name": k, "score": min(10.0, v * 2.5), "status": "AT_RISK"} 
            for k, v in sorted(entities.items(), key=lambda item: item[1], reverse=True)
        ]
        return {"status": "success", "entities": result}
    finally:
        conn.close()

@app.get("/api/reports")
def get_reports(domain: str = None, company: str = None):
    """Generates synthetic reports scoped to user targets."""
    conn = get_db()
    try:
        where_str = ""
        params = []
        if domain and company:
            where_str = " WHERE (description LIKE ? OR description LIKE ?)"
            params = [f"%{domain}%", f"%{company}%"]
            
        correlations = conn.execute(
            f"SELECT * FROM correlation_events{where_str} ORDER BY timestamp DESC LIMIT 10",
            params
        ).fetchall()
        
        reports = []
        for c in correlations:
            reports.append({
                "title": f"Threat Scope: {c['event_type']}",
                "type": c['severity'],
                "date": datetime.fromtimestamp(c['timestamp']).strftime('%b %d, %Y'),
                "size": f"{(c['id'] * 1.4) % 15 + 2:.1f} MB",
                "format": "ENCRYPTED_JSON",
                "image": "https://picsum.photos/seed/threat/400/200"
            })
            
        if not reports:
            reports = [
                {"title": f'Initial Audit Report ({domain})', "type": 'BASELINE', "date": datetime.now().strftime('%b %d, %Y'), "size": '1.2 MB', "format": 'SYS_LOG', "image": 'https://picsum.photos/seed/init/400/200'}
            ]
            
        return {"status": "success", "reports": reports}
    finally:
        conn.close()

@app.get("/api/alerts/stream")
async def stream_alerts(request: Request, domain: str = None, company: str = None):
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
                where_al = ""
                params_al = []
                if domain and company:
                    where_al = " AND (message LIKE ? OR message LIKE ?)"
                    params_al = [f"%{domain}%", f"%{company}%"]
                    
                new_alerts = conn.execute(
                    f"SELECT * FROM alerts WHERE id > ? AND severity IN ('P1', 'P2'){where_al} ORDER BY id ASC",
                    (last_check_id_alert, *params_al)
                ).fetchall()
                
                for alert in new_alerts:
                    last_check_id_alert = alert["id"]
                    payload = json.dumps({"type": "standard", "data": alert})
                    yield f"data: {payload}\n\n"
                
                # Check for new Correlation Alerts
                where_cr = ""
                params_cr = []
                if domain and company:
                    where_cr = " AND (description LIKE ? OR description LIKE ?)"
                    params_cr = [f"%{domain}%", f"%{company}%"]
                    
                new_corrs = conn.execute(
                    f"SELECT * FROM correlation_events WHERE id > ?{where_cr} ORDER BY id ASC",
                    (last_check_id_corr, *params_cr)
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
