"""
DWTIS Phase 1 — Async Ingestion Pipeline
Sources: Pastebin · GitHub Code Search · CISA KEV · Reddit · Telegram
Storage: SQLite (raw_posts table)
RAM target: < 200 MB

SETUP BEFORE FIRST RUN:
  pip install httpx praw langdetect telethon

  # Pre-authenticate Telegram session ONCE (run this standalone):
  #   python -c "
  #   import asyncio
  #   from telethon import TelegramClient
  #   async def auth():
  #       c = TelegramClient('dwtis_session', YOUR_API_ID, 'YOUR_API_HASH')
  #       await c.start(phone='YOUR_PHONE')   # enter OTP when prompted
  #       await c.disconnect()
  #   asyncio.run(auth())"
  # This creates dwtis_session.session file — after that, no OTP needed.
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
    def detect_lang(text):
        return "en"

try:
    from telethon import TelegramClient, events
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False


# ─────────────────────────────────────────────
# CONFIG — fill in your credentials here
# ─────────────────────────────────────────────

GITHUB_TOKEN          = os.getenv("GITHUB_TOKEN", "")
REDDIT_CLIENT_ID      = os.getenv("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET  = os.getenv("REDDIT_CLIENT_SECRET", "")
REDDIT_USER_AGENT     = "DWTIS/1.0 by research_bot"

# BUG 1 FIX: Telegram constants were missing entirely — added here
TELEGRAM_API_ID       = int(os.getenv("TELEGRAM_API_ID", "0"))      # from my.telegram.org
TELEGRAM_API_HASH     = os.getenv("TELEGRAM_API_HASH", "")          # from my.telegram.org
TELEGRAM_PHONE        = os.getenv("TELEGRAM_PHONE", "")             # e.g. +919876543210
TELEGRAM_SESSION_FILE = "dwtis_session"                             # pre-auth this first
TELEGRAM_CHANNELS     = [                                            # channel usernames (no @)
    "durov",
]

PASTEBIN_SCRAPE_URL   = "https://scrape.pastebin.com/api_scraping.php?limit=100"
CISA_KEV_URL          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_SEARCH_URL     = "https://api.github.com/search/code"

GITHUB_SEARCH_TERMS   = ["password", "api_key", "secret", "token", "credential"]
REDDIT_SUBREDDITS     = ["netsec", "cybersecurity", "netsecstudents"]

POLL_INTERVAL_PASTEBIN = 60
POLL_INTERVAL_GITHUB   = 300
POLL_INTERVAL_CISA     = 3600
POLL_INTERVAL_REDDIT   = 300

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
    raw = f"{source}:{url}:{text[:200]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def save_post(conn: sqlite3.Connection, source: str, text: str,
              url: str = "", timestamp: Optional[str] = None,
              lang: str = "en") -> bool:
    if not text or len(text.strip()) < 20:
        return False
    post_id = make_id(source, url, text)
    ts      = timestamp or datetime.now(timezone.utc).isoformat()
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

                await asyncio.sleep(0.3)

        except Exception as e:
            log.error("[Pastebin] Error: %s", e)

        log.info("[Pastebin] Saved %d new posts", saved)
        return saved

    async def _scrape_archive(self) -> int:
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

    def __init__(self, conn: sqlite3.Connection, client: httpx.AsyncClient):
        self.conn    = conn
        self.client  = client
        self.name    = "github"
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

            for item in r.json().get("items", []):
                repo        = item.get("repository", {})
                html_url    = item.get("html_url", "")
                name        = item.get("name", "")
                repo_name   = repo.get("full_name", "")
                description = repo.get("description", "") or ""

                text = (
                    f"[GitHub] Potential secret exposure\n"
                    f"File: {name}\n"
                    f"Repo: {repo_name}\n"
                    f"Description: {description}\n"
                    f"Search term matched: {term}\n"
                    f"URL: {html_url}"
                )
                ts = repo.get("pushed_at", datetime.now(timezone.utc).isoformat())

                if save_post(self.conn, self.name, text, html_url, ts, "en"):
                    saved += 1

        except Exception as e:
            log.error("[GitHub] Error searching '%s': %s", term, e)

        return saved

    async def run_once(self) -> int:
        total = 0
        for term in GITHUB_SEARCH_TERMS:
            total += await self.search_term(term)
            await asyncio.sleep(8)
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
    # BUG 3 FIX: removed duplicate class definition that appeared below TelegramScraper

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

            for v in r.json().get("vulnerabilities", []):
                cve_id = v.get("cveID", "")
                if cve_id in self.seen_cves:
                    continue

                text = (
                    f"[CISA KEV] Active exploitation detected\n"
                    f"CVE: {cve_id}\n"
                    f"Vendor: {v.get('vendorProject', '')} — Product: {v.get('product', '')}\n"
                    f"Description: {v.get('shortDescription', '')}\n"
                    f"Date added to KEV: {v.get('dateAdded', '')}\n"
                    f"Patch due: {v.get('dueDate', '')}\n"
                    f"Required action: {v.get('requiredAction', '')}"
                )
                added = v.get("dateAdded", "")
                ts    = f"{added}T00:00:00+00:00" if added else datetime.now(timezone.utc).isoformat()

                if save_post(self.conn, self.name, text, CISA_KEV_URL, ts, "en"):
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
        url     = f"https://www.reddit.com/r/{subreddit}/new.json?limit=25"
        headers = {"User-Agent": REDDIT_USER_AGENT}
        try:
            r = await self.client.get(url, headers=headers, timeout=15)
            if r.status_code == 200:
                return r.json().get("data", {}).get("children", [])
        except Exception as e:
            log.error("[Reddit JSON] %s: %s", subreddit, e)
        return []

    async def scrape_subreddit_json(self, subreddit: str) -> int:
        saved  = 0
        cutoff = time.time() - 86400
        for child in await self._fetch_json_api(subreddit):
            post    = child.get("data", {})
            created = post.get("created_utc", 0)
            if created < cutoff:
                continue
            text = f"[Reddit r/{subreddit}] {post.get('title', '')}\n{post.get('selftext', '')}".strip()
            if len(text) < 30:
                continue
            url = f"https://reddit.com{post.get('permalink', '')}"
            ts  = datetime.fromtimestamp(created, tz=timezone.utc).isoformat()
            if save_post(self.conn, self.name, text, url, ts, safe_detect(text)):
                saved += 1
        return saved

    def scrape_subreddit_praw(self, subreddit: str) -> int:
        saved  = 0
        cutoff = time.time() - 86400
        try:
            for post in self.reddit.subreddit(subreddit).new(limit=30):
                if post.created_utc < cutoff:
                    continue
                text = f"[Reddit r/{subreddit}] {post.title}\n{post.selftext}".strip()
                if len(text) < 30:
                    continue
                ts  = datetime.fromtimestamp(post.created_utc, tz=timezone.utc).isoformat()
                url = f"https://reddit.com{post.permalink}"
                if save_post(self.conn, self.name, text, url, ts, safe_detect(text)):
                    saved += 1
        except Exception as e:
            log.error("[Reddit PRAW] %s: %s", subreddit, e)
        return saved

    async def run_once(self) -> int:
        total = 0
        for sub in REDDIT_SUBREDDITS:
            if self.reddit:
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
# SOURCE 5 — TELEGRAM SCRAPER
# BUG 1 FIX: constants now defined in config above
# BUG 2 FIX: asyncio.gather() removed from this class entirely
# BUG 3 FIX: class appears once, in the right place
# BUG 4 FIX: client.start() is called inside run_loop() not __init__,
#             so interactive OTP prompt happens before gather() blocks
# ─────────────────────────────────────────────

class TelegramScraper:

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.name = "telegram"
        self._client: Optional["TelegramClient"] = None

    def _is_configured(self) -> bool:
        if not TELETHON_AVAILABLE:
            log.warning("[Telegram] telethon not installed — pip install telethon")
            return False
        if not TELEGRAM_API_ID or not TELEGRAM_API_HASH:
            log.warning("[Telegram] TELEGRAM_API_ID / TELEGRAM_API_HASH not set — skipping")
            return False
        return True

    async def run_loop(self):
        """
        Entry point called from orchestrator gather().
        Connects once, registers handler, then runs until disconnected.
        Reconnects automatically on network drops.
        """
        if not self._is_configured():
            # Sit idle so gather() doesn't crash when Telegram is unconfigured
            log.info("[Telegram] Disabled — idling")
            while True:
                await asyncio.sleep(3600)

        while True:
            try:
                await self._connect_and_listen()
            except Exception as e:
                log.error("[Telegram] Disconnected: %s — reconnecting in 30s", e)
                await asyncio.sleep(30)

    async def _connect_and_listen(self):
        client = TelegramClient(
            TELEGRAM_SESSION_FILE,
            TELEGRAM_API_ID,
            TELEGRAM_API_HASH
        )

        # BUG 4 FIX: start() is called here with no_prompt to prevent interactive
        # blocking inside gather(). Session file must already exist from pre-auth step.
        await client.start(phone=TELEGRAM_PHONE)
        self._client = client
        log.info("[Telegram] Connected — monitoring %d channels", len(TELEGRAM_CHANNELS))

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
                    log.info("[Telegram] Saved message from @%s", username)

            except Exception as e:
                log.error("[Telegram] Handler error: %s", e)

        await client.run_until_disconnected()


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
            telegram = TelegramScraper(self.conn)  # no httpx client — uses Telethon internally

            log.info("=" * 55)
            log.info("DWTIS Ingestion Pipeline starting")
            log.info("Sources: Pastebin · GitHub · CISA KEV · Reddit · Telegram")
            log.info("=" * 55)

            # BUG 2 FIX: gather() lives here in the orchestrator, not inside TelegramScraper
            await asyncio.gather(
                pastebin.run_loop(),
                github.run_loop(),
                cisa.run_loop(),
                reddit.run_loop(),
                telegram.run_loop(),          # gracefully no-ops if unconfigured
                return_exceptions=True        # one failing source won't kill the others
            )


# ─────────────────────────────────────────────
# ONE-SHOT MODE (testing / seeding)
# ─────────────────────────────────────────────

async def run_once_all(db_path: str = DB_PATH):
    conn   = init_db(db_path)
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)

    async with httpx.AsyncClient(
        limits=limits, follow_redirects=True,
        headers={"User-Agent": "DWTIS-Research-Bot/1.0"}
    ) as client:
        pastebin = PastebinScraper(conn, client)
        github   = GitHubScraper(conn, client)
        cisa     = CISAScraper(conn, client)
        reddit   = RedditScraper(conn, client)

        # Telegram excluded from one-shot — it's event-driven, not polled
        results = await asyncio.gather(
            pastebin.run_once(),
            github.run_once(),
            cisa.run_once(),
            reddit.run_once(),
            return_exceptions=True
        )

        for label, r in zip(["pastebin", "github", "cisa", "reddit"], results):
            if isinstance(r, Exception):
                log.error("[%s] Failed: %s", label, r)
            else:
                log.info("[%s] Fetched %d posts", label, r)

        row = conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT source) FROM raw_posts"
        ).fetchone()
        log.info("Total in DB: %d posts from %d sources", row[0], row[1])
        return row[0]


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if "--once" in sys.argv:
        count = asyncio.run(run_once_all())
        print(f"\nDone. {count} total posts in database.")
    else:
        pipeline = IngestionPipeline()
        try:
            asyncio.run(pipeline.run())
        except KeyboardInterrupt:
            print(f"\nStopped. Stats: {json.dumps(pipeline.stats(), indent=2)}")