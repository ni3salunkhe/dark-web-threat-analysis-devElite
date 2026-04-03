"""
DWTIS Phase 1 — Async Ingestion Pipeline
Sources: Pastebin · GitHub Code Search · CISA KEV · Reddit
Storage: SQLite (raw_posts table)
RAM target: < 200 MB
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
import feedparser

try:
    import praw
    PRAW_AVAILABLE = True
except ImportError:
    PRAW_AVAILABLE = False

try:
    from langdetect import detect as detect_lang
except ImportError:
    def detect_lang(text):
        return "en"

# ─────────────────────────────────────────────
# CONFIG — fill in your API keys here
# ─────────────────────────────────────────────

GITHUB_TOKEN   = os.getenv("GITHUB_TOKEN", "")          # optional but avoids rate limits
REDDIT_CLIENT_ID     = os.getenv("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET = os.getenv("REDDIT_CLIENT_SECRET", "")
REDDIT_USER_AGENT    = "DWTIS/1.0 by research_bot"

PASTEBIN_SCRAPE_URL  = "https://scrape.pastebin.com/api_scraping.php?limit=100"
CISA_KEV_URL         = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_SEARCH_URL    = "https://api.github.com/search/code"

GITHUB_SEARCH_TERMS  = ["password", "api_key", "secret", "token", "credential"]
REDDIT_SUBREDDITS    = ["netsec", "cybersecurity", "netsecstudents"]

POLL_INTERVAL_PASTEBIN = 60    # seconds
POLL_INTERVAL_GITHUB   = 300   # 5 min (rate limit aware)
POLL_INTERVAL_CISA     = 3600  # 1 hour
POLL_INTERVAL_REDDIT   = 300   # 5 min

DB_PATH = "dwtis.db"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("DWTIS.ingest")


# ─────────────────────────────────────────────
# DATABASE SETUP
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
            processed   INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source    ON raw_posts(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_processed ON raw_posts(processed)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON raw_posts(timestamp)")
    conn.commit()
    log.info("Database initialised at %s", db_path)
    return conn


def make_id(source: str, url: str, text: str) -> str:
    """Deterministic dedup ID from source + url + first 200 chars."""
    raw = f"{source}:{url}:{text[:200]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def save_post(conn: sqlite3.Connection, source: str, text: str,
              url: str = "", timestamp: Optional[str] = None,
              lang: str = "en") -> bool:
    """Insert post — returns True if new, False if duplicate."""
    if not text or len(text.strip()) < 20:
        return False
    post_id   = make_id(source, url, text)
    ts        = timestamp or datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO raw_posts (id, source, text, url, timestamp, lang) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (post_id, source, text[:10000], url, ts, lang)
        )
        conn.commit()
        return conn.total_changes > 0
    except Exception as e:
        log.error("DB insert error: %s", e)
        return False


def safe_detect(text: str) -> str:
    try:
        return detect_lang(text[:500])
    except Exception:
        return "en"


# ─────────────────────────────────────────────
# SOURCE 1 — PASTEBIN SCRAPER
# ─────────────────────────────────────────────

class PastebinScraper:
    """
    Hits scrape.pastebin.com (requires Pro account for full access,
    but public endpoint returns recent public pastes).
    Falls back to scraping pastebin.com/archive for free users.
    """

    def __init__(self, conn: sqlite3.Connection, client: httpx.AsyncClient):
        self.conn   = conn
        self.client = client
        self.name   = "pastebin"

    async def fetch_paste_content(self, paste_key: str) -> str:
        url = f"https://pastebin.com/raw/{paste_key}"
        try:
            r = await self.client.get(url, timeout=10)
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
                log.warning("Pastebin scrape API requires Pro — falling back to archive")
                return await self._scrape_archive()

            pastes = r.json()
            for paste in pastes:
                key      = paste.get("key", "")
                url      = f"https://pastebin.com/{key}"
                title    = paste.get("title", "")
                raw_size = int(paste.get("size", 0))

                # skip huge pastes (> 50KB) to save RAM
                if raw_size > 50000:
                    continue

                content = await self.fetch_paste_content(key)
                if not content:
                    continue

                text = f"{title}\n{content}".strip()
                lang = safe_detect(text)
                ts   = datetime.fromtimestamp(
                    int(paste.get("date", time.time())), tz=timezone.utc
                ).isoformat()

                if save_post(self.conn, self.name, text, url, ts, lang):
                    saved += 1

                await asyncio.sleep(0.3)  # polite delay

        except Exception as e:
            log.error("[Pastebin] Error: %s", e)

        log.info("[Pastebin] Saved %d new posts", saved)
        return saved

    async def _scrape_archive(self) -> int:
        """Fallback: scrape public archive page for paste keys."""
        saved = 0
        try:
            r = await self.client.get("https://pastebin.com/archive", timeout=15)
            if r.status_code != 200:
                return 0
            keys = re.findall(r'href="/([A-Za-z0-9]{8})"', r.text)[:20]
            for key in keys:
                url     = f"https://pastebin.com/{key}"
                content = await self.fetch_paste_content(key)
                if content:
                    lang = safe_detect(content)
                    if save_post(self.conn, self.name, content, url, lang=lang):
                        saved += 1
                await asyncio.sleep(0.5)
        except Exception as e:
            log.error("[Pastebin archive] Error: %s", e)
        return saved

    async def run_loop(self):
        log.info("[Pastebin] Starting loop every %ds", POLL_INTERVAL_PASTEBIN)
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_PASTEBIN)


# ─────────────────────────────────────────────
# SOURCE 2 — GITHUB CODE SEARCH
# ─────────────────────────────────────────────

class GitHubScraper:
    """
    Searches GitHub code for accidentally committed secrets.
    Uses REST API — rate limited to 10/min unauth, 30/min with token.
    """

    def __init__(self, conn: sqlite3.Connection, client: httpx.AsyncClient):
        self.conn   = conn
        self.client = client
        self.name   = "github"
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if GITHUB_TOKEN:
            self.headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    async def search_term(self, term: str) -> int:
        saved = 0
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        query = f"{term} in:file pushed:>{since}"

        try:
            r = await self.client.get(
                GITHUB_SEARCH_URL,
                params={"q": query, "per_page": 20, "sort": "indexed"},
                headers=self.headers,
                timeout=15
            )

            if r.status_code == 403:
                log.warning("[GitHub] Rate limited — sleeping 60s")
                await asyncio.sleep(60)
                return 0

            if r.status_code != 200:
                log.warning("[GitHub] Status %d for term '%s'", r.status_code, term)
                return 0

            data  = r.json()
            items = data.get("items", [])

            for item in items:
                repo     = item.get("repository", {})
                html_url = item.get("html_url", "")
                name     = item.get("name", "")
                repo_name = repo.get("full_name", "")
                description = repo.get("description", "") or ""

                text = (
                    f"[GitHub] Potential secret exposure\n"
                    f"File: {name}\n"
                    f"Repo: {repo_name}\n"
                    f"Description: {description}\n"
                    f"Search term matched: {term}\n"
                    f"URL: {html_url}"
                )

                ts = item.get("repository", {}).get("pushed_at",
                     datetime.now(timezone.utc).isoformat())

                if save_post(self.conn, self.name, text, html_url, ts, "en"):
                    saved += 1

        except Exception as e:
            log.error("[GitHub] Error searching '%s': %s", term, e)

        return saved

    async def run_once(self) -> int:
        total = 0
        for term in GITHUB_SEARCH_TERMS:
            n = await self.search_term(term)
            total += n
            await asyncio.sleep(8)  # stay under rate limit
        log.info("[GitHub] Saved %d new posts", total)
        return total

    async def run_loop(self):
        log.info("[GitHub] Starting loop every %ds", POLL_INTERVAL_GITHUB)
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_GITHUB)


# ─────────────────────────────────────────────
# SOURCE 3 — CISA KEV JSON FEED
# ─────────────────────────────────────────────

class CISAScraper:
    """
    CISA Known Exploited Vulnerabilities catalog.
    This is ground truth for active exploitation — pre-disclosure
    for many orgs that haven't patched yet.
    """

    def __init__(self, conn: sqlite3.Connection, client: httpx.AsyncClient):
        self.conn      = conn
        self.client    = client
        self.name      = "cisa_kev"
        self.seen_cves: set = set()

    async def run_once(self) -> int:
        saved = 0
        try:
            r = await self.client.get(CISA_KEV_URL, timeout=20)
            if r.status_code != 200:
                log.warning("[CISA] Status %d", r.status_code)
                return 0

            data = r.json()
            vulns = data.get("vulnerabilities", [])

            for v in vulns:
                cve_id = v.get("cveID", "")
                if cve_id in self.seen_cves:
                    continue

                vendor   = v.get("vendorProject", "")
                product  = v.get("product", "")
                desc     = v.get("shortDescription", "")
                added    = v.get("dateAdded", "")
                due_date = v.get("dueDate", "")
                action   = v.get("requiredAction", "")

                text = (
                    f"[CISA KEV] Active exploitation detected\n"
                    f"CVE: {cve_id}\n"
                    f"Vendor: {vendor} — Product: {product}\n"
                    f"Description: {desc}\n"
                    f"Date added to KEV: {added}\n"
                    f"Patch due: {due_date}\n"
                    f"Required action: {action}"
                )

                url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                ts  = f"{added}T00:00:00+00:00" if added else datetime.now(timezone.utc).isoformat()

                if save_post(self.conn, self.name, text, url, ts, "en"):
                    saved += 1
                    self.seen_cves.add(cve_id)

        except Exception as e:
            log.error("[CISA] Error: %s", e)

        log.info("[CISA] Saved %d new KEV entries", saved)
        return saved

    async def run_loop(self):
        log.info("[CISA] Starting loop every %ds", POLL_INTERVAL_CISA)
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_CISA)


# ─────────────────────────────────────────────
# SOURCE 4 — REDDIT SCRAPER
# ─────────────────────────────────────────────

class RedditScraper:
    """
    Monitors r/netsec, r/cybersecurity for early breach signals.
    Security researchers post IOCs and breach warnings here before
    official disclosures.
    Uses PRAW if credentials available, falls back to JSON API.
    """

    def __init__(self, conn: sqlite3.Connection, client: httpx.AsyncClient):
        self.conn   = conn
        self.client = client
        self.name   = "reddit"
        self.reddit = None

        if PRAW_AVAILABLE and REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET:
            try:
                self.reddit = praw.Reddit(
                    client_id=REDDIT_CLIENT_ID,
                    client_secret=REDDIT_CLIENT_SECRET,
                    user_agent=REDDIT_USER_AGENT,
                    ratelimit_seconds=60
                )
                log.info("[Reddit] PRAW authenticated")
            except Exception as e:
                log.warning("[Reddit] PRAW init failed: %s — using JSON fallback", e)

    async def _fetch_json_api(self, subreddit: str) -> list:
        """Fallback: Reddit's public JSON API (no auth needed)."""
        url = f"https://www.reddit.com/r/{subreddit}/new.json?limit=25"
        headers = {"User-Agent": REDDIT_USER_AGENT}
        try:
            r = await self.client.get(url, headers=headers, timeout=15)
            if r.status_code == 200:
                data = r.json()
                return data.get("data", {}).get("children", [])
        except Exception as e:
            log.error("[Reddit JSON] %s: %s", subreddit, e)
        return []

    async def scrape_subreddit_json(self, subreddit: str) -> int:
        saved   = 0
        cutoff  = time.time() - 86400  # last 24h
        posts   = await self._fetch_json_api(subreddit)

        for child in posts:
            post = child.get("data", {})
            created = post.get("created_utc", 0)
            if created < cutoff:
                continue

            title    = post.get("title", "")
            selftext = post.get("selftext", "")
            url      = f"https://reddit.com{post.get('permalink', '')}"
            score    = post.get("score", 0)

            text = f"[Reddit r/{subreddit}] {title}\n{selftext}".strip()
            if len(text) < 30:
                continue

            lang = safe_detect(text)
            ts   = datetime.fromtimestamp(created, tz=timezone.utc).isoformat()

            if save_post(self.conn, self.name, text, url, ts, lang):
                saved += 1

        return saved

    def scrape_subreddit_praw(self, subreddit: str) -> int:
        saved  = 0
        cutoff = time.time() - 86400
        try:
            sub = self.reddit.subreddit(subreddit)
            for post in sub.new(limit=30):
                if post.created_utc < cutoff:
                    continue
                text = f"[Reddit r/{subreddit}] {post.title}\n{post.selftext}".strip()
                if len(text) < 30:
                    continue
                lang = safe_detect(text)
                ts   = datetime.fromtimestamp(post.created_utc, tz=timezone.utc).isoformat()
                url  = f"https://reddit.com{post.permalink}"
                if save_post(self.conn, self.name, text, url, ts, lang):
                    saved += 1
        except Exception as e:
            log.error("[Reddit PRAW] %s: %s", subreddit, e)
        return saved

    async def run_once(self) -> int:
        total = 0
        for sub in REDDIT_SUBREDDITS:
            if self.reddit:
                # PRAW is sync — run in thread pool
                n = await asyncio.get_event_loop().run_in_executor(
                    None, self.scrape_subreddit_praw, sub
                )
            else:
                n = await self.scrape_subreddit_json(sub)
            total += n
            await asyncio.sleep(2)

        log.info("[Reddit] Saved %d new posts", total)
        return total

    async def run_loop(self):
        log.info("[Reddit] Starting loop every %ds", POLL_INTERVAL_REDDIT)
        while True:
            await self.run_once()
            await asyncio.sleep(POLL_INTERVAL_REDDIT)


# ─────────────────────────────────────────────
# ORCHESTRATOR
# ─────────────────────────────────────────────

class IngestionPipeline:

    def __init__(self, db_path: str = DB_PATH):
        self.conn   = init_db(db_path)
        self.client = None

    def stats(self) -> dict:
        row = self.conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT source), SUM(processed) FROM raw_posts"
        ).fetchone()
        by_source = self.conn.execute(
            "SELECT source, COUNT(*) FROM raw_posts GROUP BY source"
        ).fetchall()
        return {
            "total_posts"   : row[0],
            "sources_active": row[1],
            "processed"     : row[2] or 0,
            "by_source"     : dict(by_source),
        }

    async def run(self):
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        async with httpx.AsyncClient(
            limits=limits,
            follow_redirects=True,
            headers={"User-Agent": "DWTIS-Research-Bot/1.0 (academic threat intelligence)"}
        ) as client:
            self.client = client

            pastebin = PastebinScraper(self.conn, client)
            github   = GitHubScraper(self.conn, client)
            cisa     = CISAScraper(self.conn, client)
            reddit   = RedditScraper(self.conn, client)

            log.info("=" * 50)
            log.info("DWTIS Ingestion Pipeline starting")
            log.info("Sources: Pastebin · GitHub · CISA KEV · Reddit")
            log.info("=" * 50)

            # Run all scrapers concurrently
            await asyncio.gather(
                pastebin.run_loop(),
                github.run_loop(),
                cisa.run_loop(),
                reddit.run_loop(),
            )


# ─────────────────────────────────────────────
# ONE-SHOT MODE (for testing / seeding)
# ─────────────────────────────────────────────

async def run_once_all(db_path: str = DB_PATH):
    """Run each scraper once and return stats. Good for testing."""
    conn   = init_db(db_path)
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)

    async with httpx.AsyncClient(
        limits=limits,
        follow_redirects=True,
        headers={"User-Agent": "DWTIS-Research-Bot/1.0"}
    ) as client:

        pastebin = PastebinScraper(conn, client)
        github   = GitHubScraper(conn, client)
        cisa     = CISAScraper(conn, client)
        reddit   = RedditScraper(conn, client)

        results = await asyncio.gather(
            pastebin.run_once(),
            github.run_once(),
            cisa.run_once(),
            reddit.run_once(),
            return_exceptions=True
        )

        labels = ["pastebin", "github", "cisa", "reddit"]
        for label, r in zip(labels, results):
            if isinstance(r, Exception):
                log.error("[%s] Failed: %s", label, r)
            else:
                log.info("[%s] Fetched %d posts", label, r)

        row = conn.execute("SELECT COUNT(*), COUNT(DISTINCT source) FROM raw_posts").fetchone()
        log.info("Total in DB: %d posts from %d sources", row[0], row[1])
        return row[0]


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if "--once" in sys.argv:
        # Single run for testing
        count = asyncio.run(run_once_all())
        print(f"\nDone. {count} total posts in database.")
    else:
        # Continuous loop
        pipeline = IngestionPipeline()
        try:
            asyncio.run(pipeline.run())
        except KeyboardInterrupt:
            stats = pipeline.stats()
            print(f"\nStopped. Stats: {json.dumps(stats, indent=2)}")