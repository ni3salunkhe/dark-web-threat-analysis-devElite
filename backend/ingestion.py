"""
DWTIS Phase 2 — Entity-Based Breach Monitoring Pipeline
Extends Phase 1 ingestion with targeted entity scanning.

Entities supported:
  - domain     (e.g. example.com)
  - email      (e.g. user@example.com)
  - company    (e.g. Acme Corp)
  - credential (username / handle)

APIs integrated (all free tier):
  - DeHashed        (domain + email + credential search)
  - IntelX.io       (domain + email + paste search)
  - Ahmia           (surface-indexed onion mentions — no key needed)

Phase 1 sources retained:
  Pastebin · GitHub · CISA KEV · Reddit · Telegram

SETUP:
  pip install httpx praw langdetect telethon python-dotenv

  .env keys required:
    HIBP_API_KEY        — haveibeenpwned.com/API/Key  (free)
    DEHASHED_EMAIL      — your DeHashed account email
    DEHASHED_API_KEY    — dehashed.com/profile        (free tier)
    INTELX_API_KEY      — intelx.io/account/api       (free tier)
    GITHUB_TOKEN        — github.com/settings/tokens  (optional)
    REDDIT_CLIENT_ID    — reddit.com/prefs/apps        (optional)
    REDDIT_CLIENT_SECRET
    TELEGRAM_API_ID     — my.telegram.org              (optional)
    TELEGRAM_API_HASH
    TELEGRAM_PHONE
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict

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
    Represents a user-supplied monitoring target.
    At least one field must be provided.
    """
    domain      : Optional[str] = None   # example.com
    email       : Optional[str] = None   # user@example.com
    company     : Optional[str] = None   # Acme Corp
    credential  : Optional[str] = None   # username / handle

    def validate(self):
        # Strip whitespace from all fields
        if self.domain:     self.domain     = self.domain.strip()
        if self.email:      self.email      = self.email.strip()
        if self.company:    self.company     = self.company.strip()
        if self.credential: self.credential = self.credential.strip()

        # Treat empty-after-strip as None
        if self.domain     == "": self.domain     = None
        if self.email      == "": self.email      = None
        if self.company    == "": self.company    = None
        if self.credential == "": self.credential = None

        if not any([self.domain, self.email, self.company, self.credential]):
            raise ValueError("At least one entity field must be provided.")
        if self.email:
            parts = self.email.split("@")
            if len(parts) != 2 or not parts[0] or not parts[1] or "." not in parts[1]:
                raise ValueError(f"Invalid email format: {self.email}")
        if self.domain:
            if "/" in self.domain:
                raise ValueError(f"Domain should not include path: {self.domain}")
            if ".." in self.domain:
                raise ValueError(f"Invalid domain format: {self.domain}")

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

DEHASHED_EMAIL        = os.getenv("DEHASHED_EMAIL", "")
DEHASHED_API_KEY      = os.getenv("DEHASHED_API_KEY", "")
INTELX_API_KEY        = os.getenv("INTELX_API_KEY", "")

GITHUB_TOKEN          = os.getenv("GITHUB_TOKEN", "")
REDDIT_CLIENT_ID      = os.getenv("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET  = os.getenv("REDDIT_CLIENT_SECRET", "")
REDDIT_USER_AGENT     = "DWTIS/2.0 by research_bot"

TELEGRAM_API_ID       = int(os.getenv("TELEGRAM_API_ID", "0"))
TELEGRAM_API_HASH     = os.getenv("TELEGRAM_API_HASH", "")
TELEGRAM_PHONE        = os.getenv("TELEGRAM_PHONE", "")
TELEGRAM_SESSION_FILE = "dwtis_session"
TELEGRAM_CHANNELS     = ["niranjan_leaks","Hacker_Niranjan"]

PASTEBIN_SCRAPE_URL   = "https://scrape.pastebin.com/api_scraping.php?limit=100"
CISA_KEV_URL          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_SEARCH_URL     = "https://api.github.com/search/code"
GITHUB_SEARCH_TERMS   = ["password", "api_key", "secret", "token", "credential"]
REDDIT_SUBREDDITS     = ["netsec", "cybersecurity", "netsecstudents"]

POLL_INTERVAL_PASTEBIN = 60
POLL_INTERVAL_GITHUB   = 300
POLL_INTERVAL_CISA     = 3600
POLL_INTERVAL_REDDIT   = 300
POLL_INTERVAL_BREACH   = 3600   # breach APIs — respect rate limits

DB_PATH = "dwtis.db"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("DWTIS.ingest")


# ─────────────────────────────────────────────
# DATABASE SETUP
# Extended with breach_findings table
# ─────────────────────────────────────────────

def init_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")

    # Phase 1 table — retained unchanged
    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_posts (
            id          TEXT PRIMARY KEY,
            source      TEXT NOT NULL,
            text        TEXT NOT NULL,
            url         TEXT,
            timestamp   TEXT NOT NULL,
            lang        TEXT DEFAULT 'en',
            processed   INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)

    # Phase 2 table — structured breach findings per entity
    conn.execute("""
        CREATE TABLE IF NOT EXISTS breach_findings (
            id              TEXT PRIMARY KEY,
            entity_type     TEXT NOT NULL,   -- domain / email / company / credential
            entity_value    TEXT NOT NULL,
            source_api      TEXT NOT NULL,   -- hibp / dehashed / intelx / ahmia
            breach_name     TEXT,
            breach_date     TEXT,
            data_classes    TEXT,            -- JSON list: ["email","password",...]
            sample          TEXT,            -- redacted sample if available
            severity        TEXT DEFAULT 'medium',
            raw_json        TEXT,
            discovered_at   TEXT DEFAULT (datetime('now'))
        )
    """)

    for idx in [
        "CREATE INDEX IF NOT EXISTS idx_source     ON raw_posts(source)",
        "CREATE INDEX IF NOT EXISTS idx_processed  ON raw_posts(processed)",
        "CREATE INDEX IF NOT EXISTS idx_timestamp  ON raw_posts(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_entity     ON breach_findings(entity_value)",
        "CREATE INDEX IF NOT EXISTS idx_entity_src ON breach_findings(source_api)",
    ]:
        conn.execute(idx)

    conn.commit()
    log.info("Database initialised at %s", db_path)
    return conn


def make_id(source: str, url: str, text: str) -> str:
    raw = f"{source}:{url}:{text[:200]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def save_post(conn, source, text, url="", timestamp=None, lang="en") -> bool:
    if not text or len(text.strip()) < 20:
        log.debug("Dropped post (text too short, %d chars): %s", len(text or ""), source)
        return False
    post_id = make_id(source, url, text)
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    try:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO raw_posts (id, source, text, url, timestamp, lang) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (post_id, source, text[:10000], url, ts, lang)
        )
        conn.commit()
        return cursor.rowcount > 0
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
        cursor = conn.execute("""
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
        return cursor.rowcount > 0
    except Exception as e:
        log.error("Breach DB insert error: %s", e)
        return False


def safe_detect(text: str) -> str:
    try:
        return detect_lang(text[:500])
    except Exception:
        return "en"



# ─────────────────────────────────────────────
# BREACH API 2 — DeHashed
# Docs: dehashed.com/api
# Free: 5 requests/day on free tier
# Covers: email, domain, username, password, IP
# ─────────────────────────────────────────────

class DeHashedScanner:

    BASE = "https://api.dehashed.com/search"

    def __init__(self, conn: sqlite3.Connection, client: httpx.AsyncClient):
        self.conn   = conn
        self.client = client
        self.name   = "dehashed"

    def _is_configured(self) -> bool:
        if not DEHASHED_EMAIL or not DEHASHED_API_KEY:
            log.warning("[DeHashed] DEHASHED_EMAIL / DEHASHED_API_KEY not set — skipping")
            return False
        return True

    async def _query(self, query_type: str, value: str) -> list:
        """
        query_type: email | domain | username | password | name
        """
        if not self._is_configured():
            return []
        try:
            r = await self.client.get(
                self.BASE,
                params={"query": f"{query_type}:{value}", "size": 100},
                auth=(DEHASHED_EMAIL, DEHASHED_API_KEY),
                headers={"Accept": "application/json"},
                timeout=20
            )
            if r.status_code == 200:
                return r.json().get("entries", []) or []
            elif r.status_code == 401:
                log.error("[DeHashed] Invalid credentials")
            elif r.status_code == 429:
                log.warning("[DeHashed] Daily limit reached")
            else:
                log.warning("[DeHashed] Status %d for %s:%s", r.status_code, query_type, value)
        except Exception as e:
            log.error("[DeHashed] Query error: %s", e)
        return []

    def _severity(self, entry: dict) -> str:
        if entry.get("password") or entry.get("hashed_password"):
            return "high"
        if entry.get("credit_card"):
            return "critical"
        return "medium"

    async def scan_entity(self, entity: TargetEntity) -> int:
        if not self._is_configured():
            return 0
        saved = 0

        queries = []
        if entity.email:      queries.append(("email",    entity.email))
        if entity.domain:     queries.append(("domain",   entity.domain))
        if entity.credential: queries.append(("username", entity.credential))
        if entity.company:    queries.append(("name",     entity.company))

        for query_type, value in queries:
            entries = await self._query(query_type, value)
            for entry in entries:
                data_classes = [
                    k for k in ["email", "username", "password", "hashed_password",
                                 "phone", "address", "name", "ip_address"]
                    if entry.get(k)
                ]
                sample = entry.get("email", "") or entry.get("username", "")

                if save_breach(
                    self.conn,
                    entity_type  = query_type,
                    entity_value = value,
                    source_api   = self.name,
                    breach_name  = entry.get("database_name", "unknown"),
                    data_classes = data_classes,
                    sample       = sample,
                    severity     = self._severity(entry),
                    raw_json     = json.dumps({
                        k: v for k, v in entry.items()
                        if k not in ["password", "hashed_password"]  # don't store plain passwords
                    })
                ):
                    saved += 1

            await asyncio.sleep(2)  # be gentle with free tier

        log.info("[DeHashed] Findings for [%s]: %d", entity.summary(), saved)
        return saved

    async def run_loop(self, entities: List[TargetEntity]):
        log.info("[DeHashed] Starting loop every %ds", POLL_INTERVAL_BREACH)
        while True:
            for entity in entities:
                await self.scan_entity(entity)
            await asyncio.sleep(POLL_INTERVAL_BREACH)


# ─────────────────────────────────────────────
# BREACH API 3 — IntelX
# Docs: intelx.io/api
# Free: limited searches/month, no CC needed
# Covers: email, domain, paste, dark web mentions
# ─────────────────────────────────────────────

class IntelXScanner:

    BASE     = "https://free.intelx.io"
    SEARCH   = f"{BASE}/intelligent/search"
    RESULT   = f"{BASE}/intelligent/search/result"

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
        """Initiate a search, return search ID."""
        try:
            r = await self.client.post(
                self.SEARCH,
                headers={"x-key": INTELX_API_KEY},
                json={
                    "term"       : term,
                    "buckets"    : [],
                    "lookuplevel": 0,
                    "maxresults" : 20,
                    "timeout"    : 10,
                    "datefrom"   : "",
                    "dateto"     : "",
                    "sort"       : 4,
                    "media"      : 0,
                    "terminate"  : []
                },
                timeout=15
            )
            if r.status_code == 200:
                return r.json().get("id")
            log.warning("[IntelX] Search init status %d for %s", r.status_code, term)
        except Exception as e:
            log.error("[IntelX] Search init error: %s", e)
        return None

    async def _fetch_results(self, search_id: str) -> list:
        """Poll for results after search initiation."""
        await asyncio.sleep(3)  # allow search to complete
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
            log.error("[IntelX] Result fetch error: %s", e)
        return []

    async def scan_term(self, entity_type: str, value: str) -> int:
        if not self._is_configured():
            return 0
        saved     = 0
        search_id = await self._search(value)
        if not search_id:
            return 0

        records = await self._fetch_results(search_id)
        for record in records:
            media_type = record.get("media", 0)
            systemid   = record.get("systemid", "")
            name       = record.get("name", "")
            date       = record.get("date", "")

            # media type 1 = paste, 7 = darknet, 8 = forum
            source_label = {1: "paste", 7: "darknet", 8: "forum"}.get(media_type, "other")
            severity     = "high" if media_type == 7 else "medium"

            text = (
                f"[IntelX {source_label}] Match for {value}\n"
                f"Record: {name}\n"
                f"Date: {date}\n"
                f"System ID: {systemid}"
            )

            # Save to raw_posts for NLP pipeline to pick up
            save_post(
                self.conn, f"intelx_{source_label}", text,
                url=f"https://intelx.io/?did={systemid}",
                timestamp=date or None,
                lang="en"
            )

            # Save structured finding
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

        log.info("[IntelX] Findings for %s=%s: %d", entity_type, value, saved)
        return saved

    async def scan_entity(self, entity: TargetEntity) -> int:
        total = 0
        if entity.email:      total += await self.scan_term("email",      entity.email)
        if entity.domain:     total += await self.scan_term("domain",     entity.domain)
        if entity.company:    total += await self.scan_term("company",    entity.company)
        if entity.credential: total += await self.scan_term("credential", entity.credential)
        return total

    async def run_loop(self, entities: List[TargetEntity]):
        log.info("[IntelX] Starting loop every %ds", POLL_INTERVAL_BREACH)
        while True:
            for entity in entities:
                await self.scan_entity(entity)
            await asyncio.sleep(POLL_INTERVAL_BREACH)


# ─────────────────────────────────────────────
# BONUS — Ahmia (no API key needed)
# Public dark web search engine that indexes
# onion sites and exposes a clearnet search API
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
            r = await self.client.get(
                self.BASE,
                params={"q": value},
                headers={"User-Agent": "DWTIS-Research-Bot/2.0"},
                timeout=20
            )
            if r.status_code != 200:
                log.warning("[Ahmia] Status %d for %s", r.status_code, value)
                return 0

            # Ahmia results are placed inside <li class="result">
            # Ensure we only match links that appear inside a result block.
            results_block = re.search(r'<ol class="searchResults">(.*?)</ol>', r.text, re.DOTALL)
            if not results_block:
                log.info("[Ahmia] No valid search results found for %s", value)
                return 0
                
            block_html = results_block.group(1)
            links  = re.findall(r'href="(http://[a-z2-7]{16,56}\.onion[^"]*)"', block_html)
            titles = re.findall(r'<h4[^>]*>(.*?)</h4>', block_html)

            for i, link in enumerate(links[:10]):
                title = titles[i] if i < len(titles) else "Unknown"
                text  = f"[Ahmia onion mention] Query: {value}\nTitle: {title}\nURL: {link}"

                save_post(self.conn, "ahmia", text, url=link, lang="en")
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
            log.error("[Ahmia] scan error: %s", e)

        log.info("[Ahmia] Findings for %s=%s: %d", entity_type, value, saved)
        return saved

    async def scan_entity(self, entity: TargetEntity) -> int:
        total = 0
        if entity.domain:  total += await self.scan_term("domain",  entity.domain)
        if entity.company: total += await self.scan_term("company", entity.company)
        if entity.email:   total += await self.scan_term("email",   entity.email)
        return total

    async def run_loop(self, entities: List[TargetEntity]):
        log.info("[Ahmia] Starting loop every %ds", POLL_INTERVAL_BREACH)
        while True:
            for entity in entities:
                await self.scan_entity(entity)
            await asyncio.sleep(POLL_INTERVAL_BREACH)


# ─────────────────────────────────────────────
# PHASE 1 SOURCES — retained from original
# ─────────────────────────────────────────────

class PastebinScraper:

    def __init__(self, conn, client):
        self.conn = conn; self.client = client; self.name = "pastebin"

    async def fetch_paste_content(self, paste_key):
        url = f"https://pastebin.com/raw/{paste_key}"
        try:
            r = await self.client.get(url, timeout=10)
            if r.status_code == 200:
                return r.text
        except Exception:
            pass
        return ""

    async def run_once(self):
        saved = 0
        try:
            r = await self.client.get(PASTEBIN_SCRAPE_URL, timeout=15)
            if r.status_code == 403:
                return await self._scrape_archive()
            for paste in r.json():
                key = paste.get("key", "")
                if int(paste.get("size", 0)) > 50000:
                    continue
                content = await self.fetch_paste_content(key)
                if not content:
                    continue
                text = f"{paste.get('title','')}\n{content}".strip()
                ts   = datetime.fromtimestamp(
                    int(paste.get("date", time.time())), tz=timezone.utc
                ).isoformat()
                if save_post(self.conn, self.name, text,
                             f"https://pastebin.com/{key}", ts, safe_detect(text)):
                    saved += 1
                await asyncio.sleep(0.3)
        except Exception as e:
            log.error("[Pastebin] %s", e)
        log.info("[Pastebin] Saved %d", saved)
        return saved

    async def _scrape_archive(self):
        saved = 0
        try:
            r = await self.client.get("https://pastebin.com/archive", timeout=15)
            keys = re.findall(r'href="/([A-Za-z0-9]{8})"', r.text)[:20]
            for key in keys:
                content = await self.fetch_paste_content(key)
                if content and save_post(self.conn, self.name, content,
                                         f"https://pastebin.com/{key}",
                                         lang=safe_detect(content)):
                    saved += 1
                await asyncio.sleep(0.5)
        except Exception as e:
            log.error("[Pastebin archive] %s", e)
        return saved

    async def run_loop(self):
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_PASTEBIN)


class GitHubScraper:

    def __init__(self, conn, client):
        self.conn = conn; self.client = client; self.name = "github"
        self.headers = {"Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"}
        if GITHUB_TOKEN:
            self.headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    async def search_term(self, term):
        saved = 0
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            r = await self.client.get(
                GITHUB_SEARCH_URL,
                params={"q": f"{term} in:file pushed:>{since}", "per_page": 20, "sort": "indexed"},
                headers=self.headers, timeout=15
            )
            if r.status_code == 403:
                await asyncio.sleep(60); return 0
            if r.status_code != 200:
                return 0
            for item in r.json().get("items", []):
                repo = item.get("repository", {})
                text = (f"[GitHub] Potential secret exposure\n"
                        f"File: {item.get('name','')}\nRepo: {repo.get('full_name','')}\n"
                        f"Term: {term}\nURL: {item.get('html_url','')}")
                if save_post(self.conn, self.name, text, item.get("html_url",""),
                             repo.get("pushed_at",""), "en"):
                    saved += 1
        except Exception as e:
            log.error("[GitHub] %s", e)
        return saved

    async def run_once(self, entity_terms=None):
        """Search GitHub for entity-related code. Only entity terms -- no generic noise."""
        total = 0
        terms = list(entity_terms) if entity_terms else GITHUB_SEARCH_TERMS
        for term in terms:
            total += await self.search_term(term)
            await asyncio.sleep(8)
        log.info("[GitHub] Saved %d", total)
        return total

    async def run_loop(self):
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_GITHUB)


class CISAScraper:

    def __init__(self, conn, client):
        self.conn = conn; self.client = client
        self.name = "cisa_kev"; self.seen_cves: set = set()

    async def run_once(self):
        saved = 0
        try:
            r = await self.client.get(CISA_KEV_URL, timeout=20)
            if r.status_code != 200:
                return 0
            for v in r.json().get("vulnerabilities", []):
                cve_id = v.get("cveID", "")
                if cve_id in self.seen_cves:
                    continue
                text = (f"[CISA KEV] {cve_id}\nVendor: {v.get('vendorProject','')}\n"
                        f"Product: {v.get('product','')}\n{v.get('shortDescription','')}")
                added = v.get("dateAdded", "")
                ts = f"{added}T00:00:00+00:00" if added else datetime.now(timezone.utc).isoformat()
                if save_post(self.conn, self.name, text, CISA_KEV_URL, ts, "en"):
                    saved += 1
                    self.seen_cves.add(cve_id)
        except Exception as e:
            log.error("[CISA] %s", e)
        log.info("[CISA] Saved %d", saved)
        return saved

    async def run_loop(self):
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_CISA)


class RedditScraper:

    def __init__(self, conn, client):
        self.conn = conn; self.client = client; self.name = "reddit"
        self.reddit = None
        if PRAW_AVAILABLE and REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET:
            try:
                self.reddit = praw.Reddit(
                    client_id=REDDIT_CLIENT_ID, client_secret=REDDIT_CLIENT_SECRET,
                    user_agent=REDDIT_USER_AGENT, ratelimit_seconds=60
                )
            except Exception:
                pass

    async def _fetch_json_api(self, subreddit):
        try:
            r = await self.client.get(
                f"https://www.reddit.com/r/{subreddit}/new.json?limit=25",
                headers={"User-Agent": REDDIT_USER_AGENT}, timeout=15
            )
            if r.status_code == 200:
                return r.json().get("data", {}).get("children", [])
        except Exception:
            pass
        return []

    async def _search_subreddit(self, subreddit, query):
        """Search a subreddit for entity-related posts."""
        saved = 0
        try:
            r = await self.client.get(
                f"https://www.reddit.com/r/{subreddit}/search.json",
                params={"q": query, "sort": "new", "limit": 25,
                        "restrict_sr": "on", "t": "week"},
                headers={"User-Agent": REDDIT_USER_AGENT}, timeout=15
            )
            if r.status_code == 200:
                for child in r.json().get("data", {}).get("children", []):
                    post = child.get("data", {})
                    text = f"[Reddit r/{subreddit}] {post.get('title','')}\n{post.get('selftext','')}".strip()
                    if len(text) < 30:
                        continue
                    ts = datetime.fromtimestamp(
                        post.get("created_utc", time.time()), tz=timezone.utc
                    ).isoformat()
                    if save_post(self.conn, self.name, text,
                                 f"https://reddit.com{post.get('permalink','')}",
                                 ts, safe_detect(text)):
                        saved += 1
        except Exception as e:
            log.error("[Reddit search] %s", e)
        return saved

    async def run_once(self, entity_terms=None):
        """Entity-specific search only. No general feed scraping."""
        total = 0
        if entity_terms:
            # ONLY search for entity-specific posts -- no noise
            for sub in REDDIT_SUBREDDITS:
                for term in entity_terms:
                    total += await self._search_subreddit(sub, term)
                    await asyncio.sleep(2)
        else:
            # Fallback: general feed (only used in continuous mode)
            cutoff = time.time() - 86400
            for sub in REDDIT_SUBREDDITS:
                for child in await self._fetch_json_api(sub):
                    post = child.get("data", {})
                    if post.get("created_utc", 0) < cutoff:
                        continue
                    text = f"[Reddit r/{sub}] {post.get('title','')}\n{post.get('selftext','')}".strip()
                    if len(text) < 30:
                        continue
                    ts = datetime.fromtimestamp(post["created_utc"], tz=timezone.utc).isoformat()
                    if save_post(self.conn, self.name, text,
                                 f"https://reddit.com{post.get('permalink','')}", ts,
                                 safe_detect(text)):
                        total += 1
                await asyncio.sleep(2)
        log.info("[Reddit] Saved %d", total)
        return total

    async def run_loop(self):
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_REDDIT)


class TelegramScraper:

    def __init__(self, conn):
        self.conn = conn; self.name = "telegram"

    def _is_configured(self):
        if not TELETHON_AVAILABLE:
            log.info("[Telegram] telethon not installed -- skipping")
            return False
        if not TELEGRAM_API_ID or not TELEGRAM_API_HASH:
            log.info("[Telegram] API credentials not set -- skipping")
            return False
        return True

    @staticmethod
    def reset_session():
        """Kill existing Telegram session files and force fresh authentication."""
        import glob as _glob
        for f in _glob.glob(f"{TELEGRAM_SESSION_FILE}*"):
            try:
                os.remove(f)
                log.info("[Telegram] Removed old session: %s", f)
            except Exception as e:
                log.warning("[Telegram] Could not remove %s: %s", f, e)

    async def run_once(self, entity_terms=None):
        """One-shot: connect using existing session (or prompt if new), fetch recent msgs, disconnect."""
        if not self._is_configured():
            return 0

        saved = 0

        try:
            client = TelegramClient(TELEGRAM_SESSION_FILE, TELEGRAM_API_ID, TELEGRAM_API_HASH)
            await client.start(phone=TELEGRAM_PHONE)
            log.info("[Telegram] Connected")

            for channel_name in TELEGRAM_CHANNELS:
                try:
                    channel = await client.get_entity(channel_name)
                    messages = await client.get_messages(channel, limit=100)
                    log.info("[Telegram] Fetched %d messages from @%s",
                             len(messages), channel_name)

                    for msg in messages:
                        text = msg.message or ""
                        if len(text.strip()) < 20:
                            continue

                        # If entity terms given, keep only relevant messages
                        if entity_terms:
                            text_lower = text.lower()
                            if not any(t.lower() in text_lower for t in entity_terms):
                                continue

                        ts = msg.date.isoformat() if msg.date else None
                        url = f"https://t.me/{channel_name}/{msg.id}"
                        if save_post(self.conn, self.name, text, url,
                                     ts, safe_detect(text)):
                            saved += 1

                except Exception as e:
                    log.error("[Telegram] Channel @%s error: %s", channel_name, e)

            await client.disconnect()
            log.info("[Telegram] Disconnected")

        except Exception as e:
            log.error("[Telegram] Connection error: %s", e)

        log.info("[Telegram] Saved %d messages", saved)
        return saved

    async def run_loop(self, entity_terms=None):
        if not self._is_configured():
            log.info("[Telegram] Disabled -- idling")
            while True:
                await asyncio.sleep(3600)
        while True:
            try:
                await self._connect_and_listen()
            except Exception as e:
                log.error("[Telegram] %s -- reconnecting in 30s", e)
                await asyncio.sleep(30)

    async def _connect_and_listen(self):
        client = TelegramClient(TELEGRAM_SESSION_FILE, TELEGRAM_API_ID, TELEGRAM_API_HASH)
        await client.start(phone=TELEGRAM_PHONE)
        log.info("[Telegram] Connected for live monitoring")

        @client.on(events.NewMessage(chats=TELEGRAM_CHANNELS))
        async def handler(event):
            try:
                chat     = await event.get_chat()
                username = getattr(chat, "username", None) or str(chat.id)
                text     = event.message.message or ""
                if len(text.strip()) < 20:
                    return
                ts  = event.message.date.isoformat() if event.message.date else None
                url = f"https://t.me/{username}/{event.message.id}"
                if save_post(self.conn, self.name, text, url, ts, safe_detect(text)):
                    log.info("[Telegram] Saved from @%s", username)
            except Exception as e:
                log.error("[Telegram] Handler: %s", e)

        await client.run_until_disconnected()


# ─────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────

def print_full_report(conn: sqlite3.Connection, entity: TargetEntity):
    """Print comprehensive threat intelligence report."""
    print(f"\n{'='*65}")
    print(f"  DWTIS THREAT INTELLIGENCE REPORT")
    print(f"  Target: {entity.summary()}")
    print(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*65}")

    # --- Collection stats ---
    raw = conn.execute("SELECT COUNT(*), COUNT(DISTINCT source) FROM raw_posts").fetchone()
    try:
        proc = conn.execute("SELECT COUNT(*) FROM processed_posts").fetchone()
    except Exception:
        proc = (0,)
    try:
        breach = conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT source_api) FROM breach_findings"
        ).fetchone()
    except Exception:
        breach = (0, 0)

    print(f"\n  Collection Summary:")
    print(f"    Raw posts collected : {raw[0]} from {raw[1]} sources")
    print(f"    NLP-processed posts : {proc[0]}")
    print(f"    Breach findings     : {breach[0]} from {breach[1]} APIs")

    # --- Per-source breakdown ---
    sources = conn.execute(
        "SELECT source, COUNT(*) FROM raw_posts GROUP BY source ORDER BY COUNT(*) DESC"
    ).fetchall()
    if sources:
        print(f"\n  Posts by Source:")
        for src, count in sources:
            print(f"    {src:15s} : {count}")

    # --- Severity distribution ---
    try:
        sevs = conn.execute(
            "SELECT severity, COUNT(*) FROM processed_posts GROUP BY severity ORDER BY severity"
        ).fetchall()
    except Exception:
        sevs = []
    if sevs:
        print(f"\n  Severity Distribution:")
        for sev, count in sevs:
            indicator = {
                "P1": "!!! CRITICAL", "P2": "!! HIGH",
                "P3": "! MEDIUM", "P4": "  LOW"
            }.get(sev, sev)
            print(f"    {sev} {indicator:15s} : {count}")

    # --- Alerts ---
    try:
        alerts = conn.execute(
            "SELECT severity, score, message FROM alerts ORDER BY score DESC LIMIT 15"
        ).fetchall()
    except Exception:
        alerts = []
    if alerts:
        print(f"\n  {'='*55}")
        print(f"  ACTIVE ALERTS ({len(alerts)})")
        print(f"  {'='*55}")
        for a in alerts:
            print(f"    [{a[0]}] score={a[1]:.2f} | {a[2]}")

    # --- Top NLP threat detections ---
    try:
        threats = conn.execute("""
            SELECT source, label, severity, severity_score, original_text, url
            FROM processed_posts
            WHERE label != 'benign'
            ORDER BY severity_score DESC LIMIT 20
        """).fetchall()
    except Exception:
        threats = []
    if threats:
        print(f"\n  {'='*55}")
        print(f"  TOP THREAT DETECTIONS")
        print(f"  {'='*55}")
        for t in threats:
            preview = (t[4] or "")[:80].replace('\n', ' ')
            print(f"    [{t[2]}] {t[3]:.3f} | {t[1]:18s} | {t[0]:10s} | {preview}")
            if t[5]:
                print(f"         URL: {t[5]}")

    # --- Breach findings ---
    try:
        breaches = conn.execute("""
            SELECT entity_type, entity_value, source_api, breach_name,
                   breach_date, data_classes, severity
            FROM breach_findings
            ORDER BY severity DESC, discovered_at DESC
        """).fetchall()
    except Exception:
        breaches = []
    if breaches:
        print(f"\n  {'='*55}")
        print(f"  BREACH FINDINGS ({len(breaches)})")
        print(f"  {'='*55}")
        for b in breaches:
            print(f"    [{b[6].upper()}] {b[3]} ({b[2]})")
            print(f"      Entity : {b[0]} = {b[1]}")
            print(f"      Date   : {b[4] or 'unknown'}")
            classes = json.loads(b[5] or "[]")
            if classes:
                print(f"      Exposed: {', '.join(classes)}")

    # --- Cross-source correlations ---
    try:
        corrs = conn.execute(
            "SELECT org, severity, message FROM correlation_events ORDER BY timestamp DESC"
        ).fetchall()
    except Exception:
        corrs = []
    if corrs:
        print(f"\n  {'='*55}")
        print(f"  CROSS-SOURCE CORRELATIONS ({len(corrs)})")
        print(f"  {'='*55}")
        for c in corrs:
            print(f"    [{c[1]}] {c[2]}")

    print(f"\n{'='*65}")
    print(f"  END OF REPORT")
    print(f"{'='*65}\n")


# ─────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────

class IngestionPipeline:

    def __init__(self, entities: List[TargetEntity], db_path: str = DB_PATH):
        for e in entities:
            e.validate()
        self.entities = entities
        self.conn     = init_db(db_path)
        log.info("Monitoring %d entities: %s",
                 len(entities), " | ".join(e.summary() for e in entities))

    def stats(self) -> dict:
        row = self.conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT source), SUM(processed) FROM raw_posts"
        ).fetchone()
        breach_row = self.conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT source_api) FROM breach_findings"
        ).fetchone()
        return {
            "raw_posts"      : row[0],
            "sources_active" : row[1],
            "processed"      : row[2] or 0,
            "breach_findings": breach_row[0],
            "breach_sources" : breach_row[1],
        }

    async def run(self):
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        async with httpx.AsyncClient(
            limits=limits, follow_redirects=True,
            headers={"User-Agent": "DWTIS-Research-Bot/2.0"}
        ) as client:

            # Phase 1 — background open source ingestion
            pastebin = PastebinScraper(self.conn, client)
            github   = GitHubScraper(self.conn, client)
            cisa     = CISAScraper(self.conn, client)
            reddit   = RedditScraper(self.conn, client)
            telegram = TelegramScraper(self.conn)

            # Phase 2 — targeted entity breach scanning
            dehashed = DeHashedScanner(self.conn, client)
            intelx   = IntelXScanner(self.conn, client)
            ahmia    = AhmiaScanner(self.conn, client)

            log.info("=" * 55)
            log.info("DWTIS v2 — Entity Breach Monitor starting")
            log.info("Phase 1: Pastebin · GitHub · CISA · Reddit · Telegram")
            log.info("Phase 2: DeHashed · IntelX · Ahmia")
            log.info("=" * 55)

            await asyncio.gather(
                # Phase 1 sources
                pastebin.run_loop(),
                github.run_loop(),
                cisa.run_loop(),
                reddit.run_loop(),
                telegram.run_loop(),
                # Phase 2 breach API loops
                dehashed.run_loop(self.entities),
                intelx.run_loop(self.entities),
                ahmia.run_loop(self.entities),
                return_exceptions=True
            )


# ─────────────────────────────────────────────
# ONE-SHOT FULL SCAN — all Phase 1 + Phase 2
# ─────────────────────────────────────────────

async def run_once_all(entities: List[TargetEntity], db_path: str = DB_PATH):
    """
    Entity-targeted one-shot scan. Only collects data RELEVANT to the input entity.
    Phase 1: GitHub code search, Reddit entity search, Telegram entity filter
    Phase 2: DeHashed, IntelX, Ahmia (breach intelligence)
    Skips Pastebin (random noise) and CISA KEV (bulk CVE dump) for speed.
    """
    conn   = init_db(db_path)
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)

    # Build entity search terms
    entity_terms = []
    for entity in entities:
        if entity.domain:     entity_terms.append(entity.domain)
        if entity.email:      entity_terms.append(entity.email)
        if entity.company:    entity_terms.append(entity.company)
        if entity.credential: entity_terms.append(entity.credential)
    entity_terms = list(set(entity_terms))

    async with httpx.AsyncClient(
        limits=limits, follow_redirects=True,
        headers={"User-Agent": "DWTIS-Research-Bot/2.0"}
    ) as client:

        # Phase 1: Entity-targeted OSINT (no bulk feeds)
        github   = GitHubScraper(conn, client)
        reddit   = RedditScraper(conn, client)
        telegram = TelegramScraper(conn)

        # Phase 2: Breach intelligence APIs
        dehashed = DeHashedScanner(conn, client)
        intelx   = IntelXScanner(conn, client)
        ahmia    = AhmiaScanner(conn, client)

        log.info("=" * 55)
        log.info("DWTIS v2 -- Entity-Targeted Threat Scan")
        log.info("Targets: %s", ", ".join(entity_terms))
        log.info("=" * 55)

        # Phase 1: OSINT — only entity-relevant data
        log.info("--- Phase 1: Entity-Targeted OSINT ---")
        p1_results = await asyncio.gather(
            github.run_once(entity_terms),
            reddit.run_once(entity_terms),
            telegram.run_once(entity_terms),
            return_exceptions=True
        )
        for label, r in zip(["GitHub", "Reddit", "Telegram"], p1_results):
            if isinstance(r, Exception):
                log.error("[%s] Failed: %s", label, r)
            else:
                log.info("[%s] Collected %d relevant items", label, r)

        # Phase 2: Breach APIs — already entity-targeted
        log.info("--- Phase 2: Breach Intelligence ---")
        for entity in entities:
            log.info("Scanning entity: %s", entity.summary())
            p2_results = await asyncio.gather(
                dehashed.scan_entity(entity),
                intelx.scan_entity(entity),
                ahmia.scan_entity(entity),
                return_exceptions=True
            )
            for label, r in zip(["DeHashed", "IntelX", "Ahmia"], p2_results):
                if isinstance(r, Exception):
                    log.error("[%s] Failed: %s", label, r)
                else:
                    log.info("[%s] %d findings", label, r)

    return conn


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="DWTIS v2 -- Dark Web Threat Intelligence Scanner")
    parser.add_argument("--domain",      help="Target domain (e.g. example.com)")
    parser.add_argument("--email",       help="Target email (e.g. user@example.com)")
    parser.add_argument("--company",     help="Target company name")
    parser.add_argument("--credential",  help="Target username / handle")
    parser.add_argument("--report-only", action="store_true", help="Print report from existing DB")
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
        print("Provide at least one: --domain, --email, --company, --credential")
        sys.exit(1)

    if args.report_only:
        conn = init_db()
        print_full_report(conn, entity)
        sys.exit(0)

    conn = asyncio.run(run_once_all([entity]))
    print_full_report(conn, entity)