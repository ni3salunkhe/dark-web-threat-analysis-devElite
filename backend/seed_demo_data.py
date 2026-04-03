"""
DWTIS Phase 2 — Test & Demo Seeder
Seeds SQLite with realistic threat posts for demo/testing without live crawlers.
Run this before nlp_engine.py --once to validate the full pipeline.
"""

import sqlite3
import hashlib
import json
from datetime import datetime, timedelta
import random

DB_PATH = "dwtis.db"

SEED_POSTS = [
    # P1 expected — credential leak + Indian org
    {
        "source": "pastebin",
        "text": (
            "FRESH LOGS - HDFC Bank combolist 2024. 45,000 entries. "
            "email:pass format. Fullz available separately. "
            "BTC only. DM for sample. user@hdfc.com:Pass1234 type format."
        ),
        "url": "https://pastebin.com/test1",
    },
    # P1 expected — ransomware + watchlist org
    {
        "source": "reddit",
        "text": (
            "New RaaS targeting Indian fintech. Paytm and PhonePe employees "
            "being targeted via spear phishing. Payload delivered via fake KYC "
            "email. RAT drops Racoon stealer then deploys LockBit variant. "
            "C2 at 185.220.101.45"
        ),
        "url": "https://reddit.com/r/netsec/test2",
    },
    # P2 expected — carding
    {
        "source": "github",
        "text": (
            "Selling fresh CVVs - SBI and Axis Bank cards. "
            "CC dumps with track1+track2. High balance accounts. "
            "Verified hits only. 5432111122223333 type format available."
        ),
        "url": "https://github.com/test3",
    },
    # P2 expected — data breach
    {
        "source": "cisa",
        "text": (
            "Zomato database breach confirmed. 17 million user records exposed "
            "including email addresses, phone numbers, and delivery addresses. "
            "Data appeared on BreachForums. MD5 hashed passwords crackable."
        ),
        "url": "https://cisa.gov/test4",
    },
    # P3 expected — exploit sale
    {
        "source": "pastebin",
        "text": (
            "0day for Apache Struts RCE. Affects versions 2.5.x. "
            "PoC available. Price negotiable. Contact via Telegram @exploitdev. "
            "Affects enterprise targets running Java backend."
        ),
        "url": "https://pastebin.com/test5",
    },
    # P3 expected — phishing
    {
        "source": "pastebin",
        "text": (
            "Phishing kit for IRCTC login page clone. "
            "Includes bulletproof hosting config, fake SMS OTP bypass, "
            "and automated cashout scripts. FUD against major AVs."
        ),
        "url": "https://pastebin.com/test6",
    },
    # P2 expected — doxxing + Indian org
    {
        "source": "reddit",
        "text": (
            "TCS employee database leaked. Names, employee IDs, Aadhaar numbers, "
            "salary details, and manager contacts of 8,000 employees. "
            "Posted as revenge after mass layoffs. Download link in comments."
        ),
        "url": "https://reddit.com/r/test7",
    },
    # P4 expected — benign discussion
    {
        "source": "reddit",
        "text": (
            "Interesting writeup on OWASP Top 10 for 2024. "
            "Broken access control remains #1. Good read for developers "
            "building secure APIs. Link to full article in comments."
        ),
        "url": "https://reddit.com/r/cybersecurity/test8",
    },
    # P1 expected — cross-source correlation trigger (HDFC again = correlation)
    {
        "source": "github",
        "text": (
            "Accidentally committed HDFC API keys to public repo. "
            "Keys: HDFC_API_KEY=sk-hdfc-prod-abcdef123456. "
            "Account is now deleted but keys may still be active."
        ),
        "url": "https://github.com/test9",
    },
    # P2 — multilingual hint (Hindi transliteration)
    {
        "source": "pastebin",
        "text": (
            "Bhai fresh logs chahiye? SBI net banking wale accounts hain. "
            "OTP bypass bhi hai. Escrow accepted. Serious buyers only. "
            "Stealer logs from Mumbai region. 500 accounts available."
        ),
        "url": "https://pastebin.com/test10",
    },
]


def seed_database():
    conn = sqlite3.connect(DB_PATH)

    # Ensure raw_posts table exists (Phase 1 creates it, but we create it here too)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_posts (
            id        TEXT PRIMARY KEY,
            source    TEXT,
            text      TEXT,
            url       TEXT,
            timestamp TEXT,
            lang      TEXT DEFAULT 'en',
            processed INTEGER DEFAULT 0
        )
    """)
    conn.commit()

    inserted = 0
    for i, post in enumerate(SEED_POSTS):
        # Generate ID same way Phase 1 does
        post_id = hashlib.sha256(
            f"{post['url']}{post['text'][:50]}".encode()
        ).hexdigest()[:16]

        # Spread timestamps over last 5 hours for correlation testing
        ts = (datetime.utcnow() - timedelta(hours=random.uniform(0, 5))).isoformat()

        try:
            conn.execute("""
                INSERT OR IGNORE INTO raw_posts (id, source, text, url, timestamp, processed)
                VALUES (?, ?, ?, ?, ?, 0)
            """, (post_id, post["source"], post["text"], post["url"], ts))
            inserted += 1
        except Exception as e:
            print(f"Seed error: {e}")

    conn.commit()
    conn.close()
    print(f"✅ Seeded {inserted} test posts into {DB_PATH}")
    print("Now run:  python nlp_engine.py --once")


if __name__ == "__main__":
    seed_database()