"""
DWTIS Phase 2 v3 — Entity-Scoped Breach Monitoring Pipeline
============================================================
Changes from v2:
  - HIBP removed (paid)
  - DeHashed removed (no domain support, limited dataset)
  - XposedOrNot added — completely free, no CC, covers email + domain + password
  - BreachDirectory (RapidAPI) added — free 10 req/month, email + username + IP + domain
  - ALL Phase 1 scrapers now entity-scoped: only save posts that mention
    your input domain / email / company / credential — no more wasted storage

Entities supported:
  --domain      example.com
  --email       user@example.com
  --company     "Acme Corp"
  --credential  username / handle

APIs (all free, no credit card):
  XposedOrNot      — api.xposedornot.com      (no key for email/password)
  BreachDirectory  — via RapidAPI free plan    (email signup only, 10 req/month)
  IntelX           — intelx.io free tier       (email signup)
  Ahmia            — ahmia.fi                  (no key at all)

Phase 1 sources (now entity-scoped):
  Pastebin · GitHub · CISA KEV · Reddit · Telegram

SETUP:
  pip install httpx praw langdetect telethon python-dotenv

  .env keys:
    RAPIDAPI_KEY          — rapidapi.com (free, email only) for BreachDirectory
    INTELX_API_KEY        — intelx.io free tier
    GITHUB_TOKEN          — optional, raises GitHub rate limits
    REDDIT_CLIENT_ID      — optional
    REDDIT_CLIENT_SECRET  — optional
    TELEGRAM_API_ID       — optional
    TELEGRAM_API_HASH     — optional
    TELEGRAM_PHONE        — optional

  XposedOrNot domain scan requires one-time DNS verification at xposedornot.com
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional, List

import httpx
from dotenv import load_dotenv
load_dotenv()

try:
    import praw
    PRAW_AVAILABLE = True
except ImportError:
    PRAW_AVAILABLE = False

try:
    from langdetect import detect as detect_lang
except ImportError:
    def detect_lang(text): return "en"

try:
    from telethon import TelegramClient, events
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False


# ─────────────────────────────────────────────
# ENTITY INPUT MODEL
# ─────────────────────────────────────────────

@dataclass
class TargetEntity:
    """
    User-supplied monitoring target.
    At least one field must be provided.
    All Phase 1 scrapers filter content against these values.
    """
    domain      : Optional[str] = None
    email       : Optional[str] = None
    company     : Optional[str] = None
    credential  : Optional[str] = None

    def validate(self):
        if not any([self.domain, self.email, self.company, self.credential]):
            raise ValueError("At least one entity field must be provided.")
        if self.email and "@" not in self.email:
            raise ValueError(f"Invalid email format: {self.email}")
        if self.domain and "/" in self.domain:
            raise ValueError(f"Domain should not include path: {self.domain}")

    def keywords(self) -> List[str]:
        """
        Returns all non-null entity values as lowercase keywords.
        Used by Phase 1 scrapers to filter relevant content only.
        """
        kw = []
        if self.domain:     kw.append(self.domain.lower())
        if self.email:      kw.append(self.email.lower())
        if self.company:    kw.append(self.company.lower())
        if self.credential: kw.append(self.credential.lower())
        # Also include domain root without TLD for broader matching
        if self.domain:
            root = self.domain.split(".")[0].lower()
            if root not in kw:
                kw.append(root)
        return kw

    def matches(self, text: str) -> bool:
        """Returns True if any entity keyword appears in the text."""
        text_lower = text.lower()
        return any(kw in text_lower for kw in self.keywords())

    def summary(self) -> str:
        parts = []
        if self.domain:     parts.append(f"domain={self.domain}")
        if self.email:      parts.append(f"email={self.email}")
        if self.company:    parts.append(f"company={self.company}")
        if self.credential: parts.append(f"credential={self.credential}")
        return ", ".join(parts)


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

RAPIDAPI_KEY          = os.getenv("RAPIDAPI_KEY", "")          # BreachDirectory via RapidAPI
INTELX_API_KEY        = os.getenv("INTELX_API_KEY", "")

GITHUB_TOKEN          = os.getenv("GITHUB_TOKEN", "")
REDDIT_CLIENT_ID      = os.getenv("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET  = os.getenv("REDDIT_CLIENT_SECRET", "")
REDDIT_USER_AGENT     = "DWTIS/3.0 by research_bot"

TELEGRAM_API_ID       = int(os.getenv("TELEGRAM_API_ID", "0"))
TELEGRAM_API_HASH     = os.getenv("TELEGRAM_API_HASH", "")
TELEGRAM_PHONE        = os.getenv("TELEGRAM_PHONE", "")
TELEGRAM_SESSION_FILE = "dwtis_session"
TELEGRAM_CHANNELS     = []  # add your target channel usernames here

PASTEBIN_SCRAPE_URL   = "https://scrape.pastebin.com/api_scraping.php?limit=100"
CISA_KEV_URL          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_SEARCH_URL     = "https://api.github.com/search/code"
REDDIT_SUBREDDITS     = ["netsec", "cybersecurity", "netsecstudents", "hacking"]

POLL_INTERVAL_PASTEBIN = 60
POLL_INTERVAL_GITHUB   = 300
POLL_INTERVAL_CISA     = 3600
POLL_INTERVAL_REDDIT   = 300
POLL_INTERVAL_BREACH   = 3600

DB_PATH = "dwtis.db"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("DWTIS.ingest")


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

def init_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_posts (
            id          TEXT PRIMARY KEY,
            source      TEXT NOT NULL,
            text        TEXT NOT NULL,
            url         TEXT,
            timestamp   TEXT NOT NULL,
            lang        TEXT DEFAULT 'en',
            matched_kw  TEXT,                -- which keyword triggered save
            processed   INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS breach_findings (
            id              TEXT PRIMARY KEY,
            entity_type     TEXT NOT NULL,
            entity_value    TEXT NOT NULL,
            source_api      TEXT NOT NULL,
            breach_name     TEXT,
            breach_date     TEXT,
            data_classes    TEXT,
            sample          TEXT,
            severity        TEXT DEFAULT 'medium',
            raw_json        TEXT,
            discovered_at   TEXT DEFAULT (datetime('now'))
        )
    """)

    for idx in [
        "CREATE INDEX IF NOT EXISTS idx_source     ON raw_posts(source)",
        "CREATE INDEX IF NOT EXISTS idx_processed  ON raw_posts(processed)",
        "CREATE INDEX IF NOT EXISTS idx_matched_kw ON raw_posts(matched_kw)",
        "CREATE INDEX IF NOT EXISTS idx_entity     ON breach_findings(entity_value)",
        "CREATE INDEX IF NOT EXISTS idx_api        ON breach_findings(source_api)",
        "CREATE INDEX IF NOT EXISTS idx_severity   ON breach_findings(severity)",
    ]:
        conn.execute(idx)

    conn.commit()
    log.info("Database initialised at %s", db_path)
    return conn


def make_id(source: str, url: str, text: str) -> str:
    return hashlib.sha256(f"{source}:{url}:{text[:200]}".encode()).hexdigest()[:16]


def save_post(conn, source, text, url="", timestamp=None,
              lang="en", matched_kw="") -> bool:
    if not text or len(text.strip()) < 20:
        return False
    post_id = make_id(source, url, text)
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO raw_posts "
            "(id, source, text, url, timestamp, lang, matched_kw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (post_id, source, text[:10000], url, ts, lang, matched_kw)
        )
        conn.commit()
        return conn.total_changes > 0
    except Exception as e:
        log.error("DB insert error: %s", e)
        return False


def save_breach(conn, entity_type, entity_value, source_api,
                breach_name="", breach_date="", data_classes=None,
                sample="", severity="medium", raw_json="") -> bool:
    finding_id = hashlib.sha256(
        f"{entity_value}:{source_api}:{breach_name}".encode()
    ).hexdigest()[:16]
    try:
        conn.execute("""
            INSERT OR IGNORE INTO breach_findings
            (id, entity_type, entity_value, source_api, breach_name,
             breach_date, data_classes, sample, severity, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding_id, entity_type, entity_value, source_api,
            breach_name, breach_date,
            json.dumps(data_classes or []),
            sample[:500], severity, raw_json[:5000]
        ))
        conn.commit()
        return conn.total_changes > 0
    except Exception as e:
        log.error("Breach DB insert error: %s", e)
        return False


def safe_detect(text: str) -> str:
    try:
        return detect_lang(text[:500])
    except Exception:
        return "en"


def find_matched_kw(text: str, entity: TargetEntity) -> str:
    """Return the first keyword found in text, for audit logging."""
    text_lower = text.lower()
    for kw in entity.keywords():
        if kw in text_lower:
            return kw
    return ""


# ─────────────────────────────────────────────
# BREACH API 1 — XposedOrNot
# Docs  : api.xposedornot.com
# Free  : completely free, no CC, no key for email/password
# Domain: requires one-time DNS verification at xposedornot.com
# Covers: email breaches, domain breaches, paste exposure, password hashes
# ─────────────────────────────────────────────

class XposedOrNotScanner:

    EMAIL_URL    = "https://api.xposedornot.com/v1/check-email"
    DOMAIN_URL   = "https://api.xposedornot.com/v1/domain-breaches"
    PASTE_URL    = "https://api.xposedornot.com/v1/paste-summary"
    BREACHES_URL = "https://api.xposedornot.com/v1/breach-analytics"

    def __init__(self, conn: sqlite3.Connection, client: httpx.AsyncClient):
        self.conn   = conn
        self.client = client
        self.name   = "xposedornot"

    def _severity_from_classes(self, data_classes: list) -> str:
        high_risk = {"Passwords", "Credit cards", "Bank account numbers",
                     "Social security numbers", "Private messages"}
        if any(c in high_risk for c in data_classes):
            return "high"
        return "medium"

    async def scan_email(self, email: str) -> int:
        """
        Check email against XposedOrNot breach database.
        No API key required.
        Returns breach count with full metadata.
        """
        saved = 0
        try:
            await asyncio.sleep(1)
            r = await self.client.get(
                f"{self.EMAIL_URL}/{email}",
                headers={"User-Agent": "DWTIS-Research/3.0"},
                timeout=15
            )

            if r.status_code == 404:
                log.info("[XON] No breaches for email: %s", email)
                return 0
            if r.status_code == 429:
                log.warning("[XON] Rate limited — sleeping 30s")
                await asyncio.sleep(30)
                return 0
            if r.status_code != 200:
                log.warning("[XON] Email scan status %d", r.status_code)
                return 0

            data     = r.json()
            breaches = data.get("ExposedBreaches", {}).get("breaches_details", [])
            metrics  = data.get("BreachMetrics", {})
            pastes   = data.get("PastesSummary", {})

            for breach in breaches:
                xposed_data  = breach.get("xposed_data", "").split(";")
                data_classes = [d.strip() for d in xposed_data if d.strip()]
                severity     = self._severity_from_classes(data_classes)

                if save_breach(
                    self.conn,
                    entity_type  = "email",
                    entity_value = email,
                    source_api   = self.name,
                    breach_name  = breach.get("breach", ""),
                    breach_date  = str(breach.get("xposed_date", "")),
                    data_classes = data_classes,
                    severity     = severity,
                    raw_json     = json.dumps(breach)
                ):
                    saved += 1
                    log.info("[XON] Breach for %s: %s (%s)",
                             email, breach.get("breach"), breach.get("xposed_date"))

            # Log paste exposure as separate finding if exists
            paste_count = pastes.get("cnt", 0)
            if paste_count:
                save_breach(
                    self.conn,
                    entity_type  = "email",
                    entity_value = email,
                    source_api   = f"{self.name}_paste",
                    breach_name  = f"Paste exposure ({paste_count} pastes)",
                    severity     = "medium",
                    raw_json     = json.dumps(pastes)
                )
                saved += 1

            log.info("[XON] Email %s: %d breach findings, paste_count=%d, risk=%s",
                     email, len(breaches), paste_count,
                     metrics.get("risk_label", "unknown"))

        except Exception as e:
            log.error("[XON] scan_email error: %s", e)

        return saved

    async def scan_domain(self, domain: str) -> int:
        """
        Domain-level breach scan.
        Requires one-time DNS/email/HTML domain verification at xposedornot.com
        After verification, returns all breached accounts under the domain.
        """
        saved = 0
        try:
            await asyncio.sleep(1)
            r = await self.client.get(
                f"{self.DOMAIN_URL}/{domain}",
                headers={"User-Agent": "DWTIS-Research/3.0"},
                timeout=15
            )

            if r.status_code == 401:
                log.warning("[XON] Domain %s not verified. "
                            "Complete DNS verification at xposedornot.com first.", domain)
                return 0
            if r.status_code == 404:
                log.info("[XON] No domain breaches for %s", domain)
                return 0
            if r.status_code != 200:
                log.warning("[XON] Domain scan status %d for %s", r.status_code, domain)
                return 0

            data     = r.json()
            breaches = data.get("breaches", []) or []

            for breach in breaches:
                data_classes = breach.get("xposed_data", "").split(";")
                data_classes = [d.strip() for d in data_classes if d.strip()]

                if save_breach(
                    self.conn,
                    entity_type  = "domain",
                    entity_value = domain,
                    source_api   = self.name,
                    breach_name  = breach.get("breach_name", ""),
                    breach_date  = str(breach.get("breach_date", "")),
                    data_classes = data_classes,
                    severity     = self._severity_from_classes(data_classes),
                    raw_json     = json.dumps(breach)
                ):
                    saved += 1

            log.info("[XON] Domain %s: %d breach records found", domain, saved)

        except Exception as e:
            log.error("[XON] scan_domain error: %s", e)

        return saved

    async def scan_entity(self, entity: TargetEntity) -> int:
        total = 0
        if entity.email:  total += await self.scan_email(entity.email)
        if entity.domain: total += await self.scan_domain(entity.domain)
        log.info("[XON] Total for [%s]: %d", entity.summary(), total)
        return total

    async def run_loop(self, entities: List[TargetEntity]):
        log.info("[XON] Starting loop every %ds", POLL_INTERVAL_BREACH)
        while True:
            for entity in entities:
                await self.scan_entity(entity)
            await asyncio.sleep(POLL_INTERVAL_BREACH)


# ─────────────────────────────────────────────
# BREACH API 2 — BreachDirectory via RapidAPI
# Docs  : rapidapi.com/rohan-patra/api/breachdirectory
# Free  : 10 requests/month — email signup only at rapidapi.com
# Covers: email, username, IP, domain
# ─────────────────────────────────────────────

class BreachDirectoryScanner:

    BASE = "https://breachdirectory.p.rapidapi.com/"

    def __init__(self, conn: sqlite3.Connection, client: httpx.AsyncClient):
        self.conn    = conn
        self.client  = client
        self.name    = "breachdirectory"
        self.req_count = 0  # track to stay within free 10/month

    def _is_configured(self) -> bool:
        if not RAPIDAPI_KEY:
            log.warning("[BD] RAPIDAPI_KEY not set — skipping BreachDirectory")
            return False
        return True

    def _headers(self) -> dict:
        return {
            "X-RapidAPI-Key" : RAPIDAPI_KEY,
            "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
        }

    async def _query(self, term: str) -> dict:
        """
        func=auto lets BreachDirectory auto-detect entity type
        (email / username / IP / domain)
        """
        if not self._is_configured():
            return {}
        if self.req_count >= 9:  # leave 1 buffer on free 10/month plan
            log.warning("[BD] Monthly request limit reached — skipping until next cycle")
            return {}
        try:
            await asyncio.sleep(2)
            r = await self.client.get(
                self.BASE,
                params={"func": "auto", "term": term},
                headers=self._headers(),
                timeout=20
            )
            self.req_count += 1
            log.info("[BD] Request %d/9 used", self.req_count)

            if r.status_code == 200:
                return r.json()
            elif r.status_code == 401:
                log.error("[BD] Invalid RapidAPI key")
            elif r.status_code == 429:
                log.warning("[BD] Rate limited")
            else:
                log.warning("[BD] Status %d for term: %s", r.status_code, term)
        except Exception as e:
            log.error("[BD] Query error: %s", e)
        return {}

    def _severity(self, result: dict) -> str:
        # BreachDirectory returns hashed passwords in 'password' field
        if result.get("password"):
            return "high"
        return "medium"

    async def scan_term(self, entity_type: str, value: str) -> int:
        saved   = 0
        data    = await self._query(value)
        results = data.get("result", []) or []

        for result in results:
            data_classes = [
                k for k in ["email", "username", "password", "ip_address", "phone"]
                if result.get(k)
            ]
            sample = result.get("email", "") or result.get("username", "")

            if save_breach(
                self.conn,
                entity_type  = entity_type,
                entity_value = value,
                source_api   = self.name,
                breach_name  = result.get("sources", ["unknown"])[0]
                               if result.get("sources") else "unknown",
                data_classes = data_classes,
                sample       = sample,
                severity     = self._severity(result),
                raw_json     = json.dumps({
                    k: v for k, v in result.items()
                    if k != "password"  # never store plaintext/hash in raw_json
                })
            ):
                saved += 1

        log.info("[BD] %s=%s: %d findings", entity_type, value, saved)
        return saved

    async def scan_entity(self, entity: TargetEntity) -> int:
        if not self._is_configured():
            return 0
        total = 0
        # Be strategic with 10 req/month limit — prioritise email then domain
        if entity.email:
            total += await self.scan_term("email", entity.email)
        if entity.domain and self.req_count < 9:
            total += await self.scan_term("domain", entity.domain)
        if entity.credential and self.req_count < 9:
            total += await self.scan_term("credential", entity.credential)
        log.info("[BD] Total for [%s]: %d", entity.summary(), total)
        return total

    async def run_loop(self, entities: List[TargetEntity]):
        log.info("[BD] Starting loop every %ds", POLL_INTERVAL_BREACH)
        while True:
            self.req_count = 0  # reset monthly counter each loop cycle
            for entity in entities:
                await self.scan_entity(entity)
            # Sleep a full month cycle to respect free tier
            await asyncio.sleep(30 * 24 * 3600)


# ─────────────────────────────────────────────
# BREACH API 3 — IntelX
# Free tier, email signup only at intelx.io
# Covers: email, domain, paste, darknet indexed mentions
# ─────────────────────────────────────────────

class IntelXScanner:

    BASE   = "https://2.intelx.io"
    SEARCH = f"{BASE}/intelligent/search"
    RESULT = f"{BASE}/intelligent/search/result"

    def __init__(self, conn: sqlite3.Connection, client: httpx.AsyncClient):
        self.conn   = conn
        self.client = client
        self.name   = "intelx"

    def _is_configured(self) -> bool:
        if not INTELX_API_KEY:
            log.warning("[IntelX] INTELX_API_KEY not set — skipping")
            return False
        return True

    async def _search(self, term: str) -> Optional[str]:
        try:
            r = await self.client.post(
                self.SEARCH,
                headers={"x-key": INTELX_API_KEY},
                json={
                    "term": term, "buckets": [], "lookuplevel": 0,
                    "maxresults": 20, "timeout": 10,
                    "datefrom": "", "dateto": "", "sort": 4,
                    "media": 0, "terminate": []
                },
                timeout=15
            )
            if r.status_code == 200:
                return r.json().get("id")
            log.warning("[IntelX] Search init %d for %s", r.status_code, term)
        except Exception as e:
            log.error("[IntelX] Search error: %s", e)
        return None

    async def _fetch_results(self, search_id: str) -> list:
        await asyncio.sleep(3)
        try:
            r = await self.client.get(
                self.RESULT,
                headers={"x-key": INTELX_API_KEY},
                params={"id": search_id, "limit": 20},
                timeout=15
            )
            if r.status_code == 200:
                return r.json().get("records", []) or []
        except Exception as e:
            log.error("[IntelX] Result error: %s", e)
        return []

    async def scan_term(self, entity_type: str, value: str, entity: TargetEntity) -> int:
        if not self._is_configured():
            return 0
        saved     = 0
        search_id = await self._search(value)
        if not search_id:
            return 0

        for record in await self._fetch_results(search_id):
            media_type   = record.get("media", 0)
            systemid     = record.get("systemid", "")
            name         = record.get("name", "")
            date         = record.get("date", "")
            source_label = {1: "paste", 7: "darknet", 8: "forum"}.get(media_type, "other")
            severity     = "high" if media_type == 7 else "medium"

            text = (
                f"[IntelX {source_label}] Match for {value}\n"
                f"Record: {name}\nDate: {date}"
            )

            # Only save to raw_posts if it matches entity keywords
            if entity.matches(text) or entity.matches(name):
                save_post(
                    self.conn, f"intelx_{source_label}", text,
                    url=f"https://intelx.io/?did={systemid}",
                    timestamp=date or None, lang="en",
                    matched_kw=value
                )

            if save_breach(
                self.conn,
                entity_type  = entity_type,
                entity_value = value,
                source_api   = self.name,
                breach_name  = name or source_label,
                breach_date  = date,
                severity     = severity,
                raw_json     = json.dumps(record)
            ):
                saved += 1

        log.info("[IntelX] %s=%s: %d findings", entity_type, value, saved)
        return saved

    async def scan_entity(self, entity: TargetEntity) -> int:
        total = 0
        if entity.email:      total += await self.scan_term("email",      entity.email,      entity)
        if entity.domain:     total += await self.scan_term("domain",     entity.domain,     entity)
        if entity.company:    total += await self.scan_term("company",    entity.company,    entity)
        if entity.credential: total += await self.scan_term("credential", entity.credential, entity)
        return total

    async def run_loop(self, entities: List[TargetEntity]):
        log.info("[IntelX] Starting loop every %ds", POLL_INTERVAL_BREACH)
        while True:
            for entity in entities:
                await self.scan_entity(entity)
            await asyncio.sleep(POLL_INTERVAL_BREACH)


# ─────────────────────────────────────────────
# BREACH API 4 — Ahmia (no key needed)
# Clearnet interface to Tor-indexed onion sites
# ─────────────────────────────────────────────

class AhmiaScanner:

    BASE = "https://ahmia.fi/search"

    def __init__(self, conn: sqlite3.Connection, client: httpx.AsyncClient):
        self.conn   = conn
        self.client = client
        self.name   = "ahmia"

    async def scan_term(self, entity_type: str, value: str) -> int:
        saved = 0
        try:
            await asyncio.sleep(2)
            r = await self.client.get(
                self.BASE,
                params={"q": value},
                headers={"User-Agent": "DWTIS-Research-Bot/3.0"},
                timeout=20
            )
            if r.status_code != 200:
                log.warning("[Ahmia] Status %d for %s", r.status_code, value)
                return 0

            links  = re.findall(r'href="(http://[a-z2-7]{16,56}\.onion[^"]*)"', r.text)
            titles = re.findall(r'<h4[^>]*>(.*?)</h4>', r.text, re.DOTALL)

            for i, link in enumerate(links[:10]):
                title = re.sub(r'<[^>]+>', '', titles[i]).strip() \
                        if i < len(titles) else "Unknown"
                text  = f"[Ahmia] Match: {value}\nTitle: {title}\nURL: {link}"

                save_post(
                    self.conn, "ahmia", text, url=link,
                    lang="en", matched_kw=value
                )
                if save_breach(
                    self.conn,
                    entity_type  = entity_type,
                    entity_value = value,
                    source_api   = self.name,
                    breach_name  = title,
                    severity     = "medium",
                    raw_json     = json.dumps({"url": link, "title": title})
                ):
                    saved += 1

        except Exception as e:
            log.error("[Ahmia] error: %s", e)

        log.info("[Ahmia] %s=%s: %d findings", entity_type, value, saved)
        return saved

    async def scan_entity(self, entity: TargetEntity) -> int:
        total = 0
        if entity.domain:     total += await self.scan_term("domain",     entity.domain)
        if entity.email:      total += await self.scan_term("email",      entity.email)
        if entity.company:    total += await self.scan_term("company",    entity.company)
        if entity.credential: total += await self.scan_term("credential", entity.credential)
        return total

    async def run_loop(self, entities: List[TargetEntity]):
        log.info("[Ahmia] Starting loop every %ds", POLL_INTERVAL_BREACH)
        while True:
            for entity in entities:
                await self.scan_entity(entity)
            await asyncio.sleep(POLL_INTERVAL_BREACH)


# ─────────────────────────────────────────────
# PHASE 1 — PASTEBIN (entity-scoped)
# Only saves pastes that mention your entity keywords
# ─────────────────────────────────────────────

class PastebinScraper:

    def __init__(self, conn, client, entities: List[TargetEntity]):
        self.conn     = conn
        self.client   = client
        self.entities = entities
        self.name     = "pastebin"

    def _relevant(self, text: str):
        """Returns (True, matched_entity) if text matches any entity."""
        for e in self.entities:
            kw = find_matched_kw(text, e)
            if kw:
                return True, kw
        return False, ""

    async def fetch_paste_content(self, paste_key: str) -> str:
        try:
            r = await self.client.get(
                f"https://pastebin.com/raw/{paste_key}", timeout=10
            )
            if r.status_code == 200:
                return r.text
        except Exception:
            pass
        return ""

    async def run_once(self) -> int:
        saved = 0
        try:
            r = await self.client.get(PASTEBIN_SCRAPE_URL, timeout=15)
            if r.status_code == 403:
                return await self._scrape_archive()

            for paste in r.json():
                key = paste.get("key", "")
                if int(paste.get("size", 0)) > 50000:
                    continue

                # Quick title check before fetching full content
                title = paste.get("title", "")
                relevant, kw = self._relevant(title)

                content = await self.fetch_paste_content(key)
                if not content:
                    continue

                full_text   = f"{title}\n{content}".strip()
                relevant, kw = self._relevant(full_text)

                if not relevant:
                    await asyncio.sleep(0.1)
                    continue  # skip — doesn't mention our entities

                ts = datetime.fromtimestamp(
                    int(paste.get("date", time.time())), tz=timezone.utc
                ).isoformat()

                if save_post(self.conn, self.name, full_text,
                             f"https://pastebin.com/{key}", ts,
                             safe_detect(full_text), matched_kw=kw):
                    saved += 1
                    log.info("[Pastebin] Relevant paste saved — keyword: %s", kw)

                await asyncio.sleep(0.3)

        except Exception as e:
            log.error("[Pastebin] %s", e)

        log.info("[Pastebin] Saved %d entity-relevant pastes", saved)
        return saved

    async def _scrape_archive(self) -> int:
        saved = 0
        try:
            r    = await self.client.get("https://pastebin.com/archive", timeout=15)
            keys = re.findall(r'href="/([A-Za-z0-9]{8})"', r.text)[:20]
            for key in keys:
                content = await self.fetch_paste_content(key)
                if not content:
                    continue
                relevant, kw = self._relevant(content)
                if relevant and save_post(
                    self.conn, self.name, content,
                    f"https://pastebin.com/{key}",
                    lang=safe_detect(content), matched_kw=kw
                ):
                    saved += 1
                await asyncio.sleep(0.5)
        except Exception as e:
            log.error("[Pastebin archive] %s", e)
        return saved

    async def run_loop(self):
        log.info("[Pastebin] Starting entity-scoped loop every %ds", POLL_INTERVAL_PASTEBIN)
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_PASTEBIN)


# ─────────────────────────────────────────────
# PHASE 1 — GITHUB (entity-scoped)
# Searches GitHub for entity keywords directly
# instead of generic terms like "password"
# ─────────────────────────────────────────────

class GitHubScraper:

    def __init__(self, conn, client, entities: List[TargetEntity]):
        self.conn     = conn
        self.client   = client
        self.entities = entities
        self.name     = "github"
        self.headers  = {
            "Accept"              : "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if GITHUB_TOKEN:
            self.headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    async def search_term(self, term: str, matched_kw: str) -> int:
        saved = 0
        since = (datetime.now(timezone.utc) - timedelta(hours=48)
                 ).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            r = await self.client.get(
                GITHUB_SEARCH_URL,
                params={
                    "q"       : f"{term} in:file pushed:>{since}",
                    "per_page": 10,
                    "sort"    : "indexed"
                },
                headers=self.headers,
                timeout=15
            )
            if r.status_code == 403:
                log.warning("[GitHub] Rate limited — sleeping 60s")
                await asyncio.sleep(60)
                return 0
            if r.status_code != 200:
                return 0

            for item in r.json().get("items", []):
                repo = item.get("repository", {})
                text = (
                    f"[GitHub] Entity mention in code\n"
                    f"Keyword: {term}\n"
                    f"File: {item.get('name','')}\n"
                    f"Repo: {repo.get('full_name','')}\n"
                    f"URL: {item.get('html_url','')}"
                )
                if save_post(self.conn, self.name, text,
                             item.get("html_url", ""),
                             repo.get("pushed_at", ""),
                             "en", matched_kw=matched_kw):
                    saved += 1

        except Exception as e:
            log.error("[GitHub] %s", e)
        return saved

    async def run_once(self) -> int:
        total = 0
        for entity in self.entities:
            for kw in entity.keywords():
                total += await self.search_term(kw, kw)
                await asyncio.sleep(10)  # GitHub rate limit
        log.info("[GitHub] Saved %d entity-relevant results", total)
        return total

    async def run_loop(self):
        log.info("[GitHub] Starting entity-scoped loop every %ds", POLL_INTERVAL_GITHUB)
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_GITHUB)


# ─────────────────────────────────────────────
# PHASE 1 — CISA KEV (entity-scoped)
# Only saves CVEs mentioning entity vendor/product
# ─────────────────────────────────────────────

class CISAScraper:

    def __init__(self, conn, client, entities: List[TargetEntity]):
        self.conn      = conn
        self.client    = client
        self.entities  = entities
        self.name      = "cisa_kev"
        self.seen_cves : set = set()

    async def run_once(self) -> int:
        saved = 0
        try:
            r = await self.client.get(CISA_KEV_URL, timeout=20)
            if r.status_code != 200:
                return 0

            for v in r.json().get("vulnerabilities", []):
                cve_id = v.get("cveID", "")
                if cve_id in self.seen_cves:
                    continue

                text = (
                    f"[CISA KEV] {cve_id}\n"
                    f"Vendor: {v.get('vendorProject','')}\n"
                    f"Product: {v.get('product','')}\n"
                    f"{v.get('shortDescription','')}"
                )

                # Only save if relevant to an entity
                matched = False
                for entity in self.entities:
                    kw = find_matched_kw(text, entity)
                    if kw:
                        added = v.get("dateAdded", "")
                        ts    = f"{added}T00:00:00+00:00" if added else \
                                datetime.now(timezone.utc).isoformat()
                        if save_post(self.conn, self.name, text,
                                     CISA_KEV_URL, ts, "en", matched_kw=kw):
                            saved += 1
                        self.seen_cves.add(cve_id)
                        matched = True
                        break

                if not matched:
                    self.seen_cves.add(cve_id)  # mark seen to avoid re-checking

        except Exception as e:
            log.error("[CISA] %s", e)

        log.info("[CISA] Saved %d entity-relevant KEV entries", saved)
        return saved

    async def run_loop(self):
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_CISA)


# ─────────────────────────────────────────────
# PHASE 1 — REDDIT (entity-scoped)
# Only saves posts mentioning your entity keywords
# ─────────────────────────────────────────────

class RedditScraper:

    def __init__(self, conn, client, entities: List[TargetEntity]):
        self.conn     = conn
        self.client   = client
        self.entities = entities
        self.name     = "reddit"

    def _relevant(self, text: str):
        for e in self.entities:
            kw = find_matched_kw(text, e)
            if kw:
                return True, kw
        return False, ""

    async def _fetch_subreddit(self, subreddit: str) -> list:
        try:
            r = await self.client.get(
                f"https://www.reddit.com/r/{subreddit}/new.json?limit=25",
                headers={"User-Agent": REDDIT_USER_AGENT},
                timeout=15
            )
            if r.status_code == 200:
                return r.json().get("data", {}).get("children", [])
        except Exception:
            pass
        return []

    async def run_once(self) -> int:
        total  = 0
        cutoff = time.time() - 86400

        for sub in REDDIT_SUBREDDITS:
            for child in await self._fetch_subreddit(sub):
                post = child.get("data", {})
                if post.get("created_utc", 0) < cutoff:
                    continue

                text = f"[Reddit r/{sub}] {post.get('title','')}\n" \
                       f"{post.get('selftext','')}".strip()
                if len(text) < 30:
                    continue

                relevant, kw = self._relevant(text)
                if not relevant:
                    continue

                ts = datetime.fromtimestamp(
                    post["created_utc"], tz=timezone.utc
                ).isoformat()

                if save_post(
                    self.conn, self.name, text,
                    f"https://reddit.com{post.get('permalink','')}",
                    ts, safe_detect(text), matched_kw=kw
                ):
                    total += 1
                    log.info("[Reddit] Relevant post saved — keyword: %s", kw)

            await asyncio.sleep(2)

        log.info("[Reddit] Saved %d entity-relevant posts", total)
        return total

    async def run_loop(self):
        log.info("[Reddit] Starting entity-scoped loop every %ds", POLL_INTERVAL_REDDIT)
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_REDDIT)


# ─────────────────────────────────────────────
# PHASE 1 — TELEGRAM (entity-scoped)
# ─────────────────────────────────────────────

class TelegramScraper:

    def __init__(self, conn, entities: List[TargetEntity]):
        self.conn     = conn
        self.entities = entities
        self.name     = "telegram"

    def _is_configured(self) -> bool:
        if not TELETHON_AVAILABLE:
            return False
        return bool(TELEGRAM_API_ID and TELEGRAM_API_HASH)

    def _relevant(self, text: str):
        for e in self.entities:
            kw = find_matched_kw(text, e)
            if kw:
                return True, kw
        return False, ""

    async def run_loop(self):
        if not self._is_configured():
            log.info("[Telegram] Disabled — idling")
            while True:
                await asyncio.sleep(3600)
        while True:
            try:
                await self._connect_and_listen()
            except Exception as e:
                log.error("[Telegram] %s — reconnecting in 30s", e)
                await asyncio.sleep(30)

    async def _connect_and_listen(self):
        if not TELEGRAM_CHANNELS:
            log.info("[Telegram] No channels configured — idling")
            while True:
                await asyncio.sleep(3600)

        client = TelegramClient(TELEGRAM_SESSION_FILE, TELEGRAM_API_ID, TELEGRAM_API_HASH)
        await client.start(phone=TELEGRAM_PHONE)
        log.info("[Telegram] Connected — monitoring %d channels", len(TELEGRAM_CHANNELS))

        @client.on(events.NewMessage(chats=TELEGRAM_CHANNELS))
        async def handler(event):
            try:
                text = event.message.message or ""
                if len(text.strip()) < 20:
                    return

                relevant, kw = self._relevant(text)
                if not relevant:
                    return  # skip non-entity messages

                chat     = await event.get_chat()
                username = getattr(chat, "username", None) or str(chat.id)
                ts       = event.message.date.isoformat() if event.message.date else None
                url      = f"https://t.me/{username}/{event.message.id}"

                if save_post(self.conn, self.name, text, url, ts,
                             safe_detect(text), matched_kw=kw):
                    log.info("[Telegram] Entity-relevant message from @%s — kw: %s",
                             username, kw)

            except Exception as e:
                log.error("[Telegram] Handler: %s", e)

        await client.run_until_disconnected()


# ─────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────

def print_report(conn: sqlite3.Connection, entity: TargetEntity):
    conditions, params = [], []
    if entity.domain:
        conditions.append("entity_value LIKE ?")
        params.append(f"%{entity.domain}%")
    if entity.email:
        conditions.append("entity_value = ?")
        params.append(entity.email)
    if entity.company:
        conditions.append("entity_value LIKE ?")
        params.append(f"%{entity.company}%")
    if entity.credential:
        conditions.append("entity_value LIKE ?")
        params.append(f"%{entity.credential}%")

    where = f"WHERE {' OR '.join(conditions)}" if conditions else ""
    rows  = conn.execute(
        f"SELECT entity_type, entity_value, source_api, breach_name, "
        f"breach_date, data_classes, severity, discovered_at "
        f"FROM breach_findings {where} "
        f"ORDER BY CASE severity "
        f"  WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
        f"  WHEN 'medium' THEN 3 ELSE 4 END, discovered_at DESC",
        params
    ).fetchall()

    raw_count = conn.execute(
        "SELECT COUNT(*) FROM raw_posts WHERE matched_kw != ''",
        []
    ).fetchone()[0]

    print(f"\n{'='*65}")
    print(f"  DWTIS BREACH REPORT — {entity.summary()}")
    print(f"{'='*65}")
    print(f"  Structured breach findings : {len(rows)}")
    print(f"  Raw entity-relevant posts  : {raw_count}")

    sev_counts: dict = {}
    for row in rows:
        sev = row[6]
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    order = ["critical", "high", "medium", "low"]
    for sev in order:
        if sev in sev_counts:
            print(f"    {sev.upper():<10}: {sev_counts[sev]}")

    print(f"\n{'─'*65}")
    for row in rows:
        etype, evalue, source, breach, date, classes, sev, disc = row
        print(f"  [{sev.upper()}] {breach}  ({source})")
        print(f"    Entity  : {etype} = {evalue}")
        print(f"    Date    : {date or 'unknown'}")
        try:
            exposed = json.loads(classes or "[]")
        except Exception:
            exposed = []
        print(f"    Exposed : {', '.join(exposed) or 'n/a'}")
        print(f"    Found   : {disc}")
        print()


# ─────────────────────────────────────────────
# ORCHESTRATOR
# ─────────────────────────────────────────────

class IngestionPipeline:

    def __init__(self, entities: List[TargetEntity], db_path: str = DB_PATH):
        for e in entities:
            e.validate()
        self.entities = entities
        self.conn     = init_db(db_path)
        log.info("Monitoring %d entities: %s",
                 len(entities), " | ".join(e.summary() for e in entities))
        log.info("Active keywords: %s",
                 ", ".join(kw for e in entities for kw in e.keywords()))

    def stats(self) -> dict:
        r1 = self.conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT source) FROM raw_posts "
            "WHERE matched_kw != ''"
        ).fetchone()
        r2 = self.conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT source_api) FROM breach_findings"
        ).fetchone()
        return {
            "entity_relevant_posts": r1[0],
            "active_sources"       : r1[1],
            "breach_findings"      : r2[0],
            "breach_sources"       : r2[1],
        }

    async def run(self):
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        async with httpx.AsyncClient(
            limits=limits, follow_redirects=True,
            headers={"User-Agent": "DWTIS-Research-Bot/3.0"}
        ) as client:

            # Phase 1 — entity-scoped open source ingestion
            pastebin = PastebinScraper(self.conn, client, self.entities)
            github   = GitHubScraper(self.conn, client, self.entities)
            cisa     = CISAScraper(self.conn, client, self.entities)
            reddit   = RedditScraper(self.conn, client, self.entities)
            telegram = TelegramScraper(self.conn, self.entities)

            # Phase 2 — targeted breach API scanning
            xon      = XposedOrNotScanner(self.conn, client)
            bd       = BreachDirectoryScanner(self.conn, client)
            intelx   = IntelXScanner(self.conn, client)
            ahmia    = AhmiaScanner(self.conn, client)

            log.info("=" * 55)
            log.info("DWTIS v3 — Entity-Scoped Breach Monitor")
            log.info("Phase 1 (scoped): Pastebin · GitHub · CISA · Reddit · Telegram")
            log.info("Phase 2 (breach): XposedOrNot · BreachDirectory · IntelX · Ahmia")
            log.info("=" * 55)

            await asyncio.gather(
                pastebin.run_loop(),
                github.run_loop(),
                cisa.run_loop(),
                reddit.run_loop(),
                telegram.run_loop(),
                xon.run_loop(self.entities),
                bd.run_loop(self.entities),
                intelx.run_loop(self.entities),
                ahmia.run_loop(self.entities),
                return_exceptions=True
            )


# ─────────────────────────────────────────────
# ONE-SHOT SCAN
# ─────────────────────────────────────────────

async def run_once_all(entities: List[TargetEntity], db_path: str = DB_PATH):
    conn   = init_db(db_path)
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)

    async with httpx.AsyncClient(
        limits=limits, follow_redirects=True,
        headers={"User-Agent": "DWTIS-Research-Bot/3.0"}
    ) as client:

        xon    = XposedOrNotScanner(conn, client)
        bd     = BreachDirectoryScanner(conn, client)
        intelx = IntelXScanner(conn, client)
        ahmia  = AhmiaScanner(conn, client)

        for entity in entities:
            log.info("Scanning: %s", entity.summary())
            results = await asyncio.gather(
                xon.scan_entity(entity),
                bd.scan_entity(entity),
                intelx.scan_entity(entity),
                ahmia.scan_entity(entity),
                return_exceptions=True
            )
            for label, r in zip(["XposedOrNot", "BreachDirectory", "IntelX", "Ahmia"], results):
                if isinstance(r, Exception):
                    log.error("[%s] Failed: %s", label, r)
                else:
                    log.info("[%s] %d findings", label, r)

            print_report(conn, entity)

    return conn


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description="DWTIS v3 — Entity-Scoped Breach Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python breach_monitor_v3.py --domain example.com --once
  python breach_monitor_v3.py --email user@example.com --once
  python breach_monitor_v3.py --domain example.com --email ceo@example.com
  python breach_monitor_v3.py --company "Acme Corp" --domain example.com --once
  python breach_monitor_v3.py --domain example.com --report-only
        """
    )
    parser.add_argument("--domain",      help="Target domain (e.g. example.com)")
    parser.add_argument("--email",       help="Target email (e.g. user@example.com)")
    parser.add_argument("--company",     help="Target company name")
    parser.add_argument("--credential",  help="Target username / handle")
    parser.add_argument("--once",        action="store_true",
                        help="Run breach APIs once and exit")
    parser.add_argument("--report-only", action="store_true",
                        help="Print report from existing DB and exit")
    args = parser.parse_args()

    entity = TargetEntity(
        domain     = args.domain,
        email      = args.email,
        company    = args.company,
        credential = args.credential
    )

    try:
        entity.validate()
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    log.info("Target entity: %s", entity.summary())
    log.info("Monitoring keywords: %s", ", ".join(entity.keywords()))

    if args.report_only:
        conn = init_db()
        print_report(conn, entity)
        sys.exit(0)

    if args.once:
        asyncio.run(run_once_all([entity]))
    else:
        pipeline = IngestionPipeline([entity])
        try:
            asyncio.run(pipeline.run())
        except KeyboardInterrupt:
            print(f"\nStopped.\nStats: {json.dumps(pipeline.stats(), indent=2)}")