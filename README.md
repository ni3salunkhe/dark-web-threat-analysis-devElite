# dark-web-threat-analysis-devElite
AI-powered system that monitors dark web sources and identifies potential cybersecurity threats.

DevElite - 
Niranjan Patil,
Nitin Salunkhe,
Saurabh Chilamshettiwar,
Aditya Patil.

Hackup 2026 - 24 hours hackathon at A.C Patil college ,Navi mumbai 

# 🚀 Phase 1: Data Collection (0–3 Hours)

In this phase, we collect data in real-time without using any machine learning models.

- Fast async scrapers are used to fetch data from sources like GitHub.
- It helps find exposed credentials, API keys, and sensitive information.
- The collected data is stored directly in a SQLite database.
- The system keeps updating automatically to simulate live monitoring.

This phase ensures that real-time data is available quickly for further analysis.

> Note: All sensitive data is masked or simulated for safety.

## 🧠 Phase 2: NLP Processing 

In this phase, we add AI capabilities to analyze the collected data.

- Used spaCy (en_core_web_sm) for detecting entities like emails, organizations, and credentials.
- Used BART (bart-large-mnli) for classifying threats (leak, phishing, malware, etc.).
- The system analyzes text and assigns a threat level with confidence score.
- Models are loaded efficiently to keep memory usage low.

This phase helps in understanding and identifying potential cybersecurity threats from raw data.

# BACKEND

# DWTIS Backend

Backend for the Dark Web Threat Intelligence System. This handles all the data collection, threat analysis, and serves the API that the React frontend talks to.

---

## Files

- `ingestion.py` — Data collection pipeline, scrapers, and breach API integrations
- `nlp_engine_v2.py` — NLP processing, threat classification, entity extraction
- `api.py` — FastAPI server with all the endpoints the frontend needs
- `alerter.py` — Dispatches critical alerts to file and webhook
- `run_system.py` — CLI entry point to run the full pipeline
- `requirements_phase1.txt` — Dependencies

---

## What changed

### ingestion.py

Added a `TargetEntity` dataclass so the system can accept specific domains, emails, company names, or credentials as monitoring targets instead of just scraping everything blindly.

Integrated three new breach intelligence APIs:
- **DeHashed** — queries their breach database by email, domain, username, or company. Automatically flags severity based on what's exposed (passwords = high, credit cards = critical).
- **IntelX** — async search + poll pattern. Classifies results by type (paste, darknet, forum). Darknet hits get higher severity.
- **Ahmia** — searches for .onion mentions related to our target. No API key needed, just parses the HTML results.

The whole collection approach changed from "scrape everything" to entity-targeted. `run_once_all()` only grabs data that's actually relevant to the entity you're scanning. GitHub now searches with entity-specific terms instead of generic stuff like "password". Reddit does targeted subreddit searches. Telegram filters by entity keywords in one-shot mode.

All breach data goes into its own `breach_findings` table separate from `raw_posts`. SQLite runs in WAL mode now to avoid lock issues when the API and scrapers are both writing.

Added rate limiting sleeps between API calls so we don't blow through free tier limits.

### nlp_engine_v2.py

Rewrote this from scratch. The old version had hardcoded org lists and a static slang dictionary which was pretty limiting.

Now it uses **bart-large-mnli** for zero-shot threat classification — 8 categories (credential-leak, ransomware, carding, data-breach, exploit-sale, phishing, doxxing, benign). It classifies based on meaning not keywords.

Entity extraction runs in three layers:
1. spaCy NER for orgs, locations, persons
2. Regex for emails, IPs, domains, crypto wallets, password hashes, card numbers
3. flan-t5-base to catch anything the first two missed (malware names, threat actors, etc)

Slang detection is fully dynamic now — 30+ structural patterns for underground trading signals (escrow, crypto payments, credential dumps, pricing, etc), OOV word detection, and LLM-based jargon identification. No more maintaining a dictionary by hand.

Severity scoring uses 5 weighted components: classification confidence, entity richness, underground signals, PII indicators, and a translation bonus for non-English content. Maps to P1 through P4.

Added cross-language support using langdetect + Helsinki-NLP translation models. Covers Russian, French, German, Chinese, Arabic, Portuguese, Spanish, Hindi, and a few others. Foreign language threat content gets a severity bump since it's usually more legit.

Signal correlation groups entities across sources and flags when the same org shows up in 2+ independent sources within a 6 hour window. No watchlist needed — works on whatever entities it extracts.

Also added an impact estimation module that tries to figure out affected user count, data sensitivity, financial exposure, and remediation complexity from the threat data.

All models lazy-load so startup isn't slow.

### api.py

FastAPI server with CORS enabled. Runs on port 8000.

Auth stuff — `/api/register` and `/api/login`. Passwords hashed with SHA-256 + salt. Registration takes a target domain and company so alerts can be scoped.

Target management — add, list, and toggle monitoring targets per user through `/api/targets`.

Background crawler queue starts on app startup. It loops through enabled targets, runs ingestion, then pushes NLP processing to a thread so it doesn't block the API. 45 second cooldown between targets.

Frontend endpoints:
- `/api/stats` — counts for raw posts, processed, breaches, alerts
- `/api/alerts` — P1/P2 alerts + correlation events
- `/api/breaches` — breach findings with parsed JSON
- `/api/threats` — processed posts with all the NLP enrichment
- `/api/entities` — unique entities sorted by how often they show up
- `/api/reports` — generated reports from correlation data

SSE streaming at `/api/alerts/stream` — frontend connects with EventSource for live push notifications. Polls every 2 seconds, scoped to the user's domain/company.

DB tables auto-create on startup.

### alerter.py

Simple alert dispatcher. Pulls unseen P1/P2 alerts and correlation events, writes them to `critical_alerts.jsonl`, and optionally pushes to a webhook URL for Slack/Teams/Discord. Marks everything as seen after dispatch.

### run_system.py

CLI wrapper: `python run_system.py --domain example.com --company "Example Inc"`

Runs the full pipeline in order: scraping → NLP analysis → correlation → alert dispatch → prints a threat report. Caps NLP at 20 posts per run to keep it fast. Use `--report-only` to skip scraping and just analyze existing data.

---

## Setup

```bash
pip install -r requirements_phase1.txt
python -m spacy download en_core_web_sm
```

For the breach APIs, create a `.env` file with whatever keys you have. None of them are required — the system just skips sources that aren't configured.

```
DEHASHED_EMAIL=your_email
DEHASHED_API_KEY=your_key
INTELX_API_KEY=your_key
GITHUB_TOKEN=your_token
REDDIT_CLIENT_ID=your_id
REDDIT_CLIENT_SECRET=your_secret
WEBHOOK_URL=https://your-webhook-url
```

## Running

```bash
# one-shot scan
python run_system.py --domain example.com

# start API server for frontend
python api.py

# run NLP engine standalone
python nlp_engine_v2.py --once

# dispatch pending alerts
python alerter.py
```

## Database

SQLite file (`dwtis.db`), WAL mode. Tables: `raw_posts`, `processed_posts`, `breach_findings`, `alerts`, `correlation_events`, `users`, `tracked_targets`.
