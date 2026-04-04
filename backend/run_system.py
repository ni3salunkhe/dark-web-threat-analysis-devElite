"""
DWTIS v2 -- Dark Web Threat Intelligence System
Entity input -> targeted scraping -> fast NLP analysis -> threat report

Usage:
    python run_system.py --domain hdfc.com
    python run_system.py --email user@example.com --company "Acme Corp"
    python run_system.py --credential admin123 --domain target.com
"""

import asyncio
import argparse
import sqlite3
import sys
import time

from ingestion import (
    TargetEntity, run_once_all, print_full_report, DB_PATH, init_db
)
from nlp_engine_v2 import (
    process_batch, run_correlation_pass,
    init_db as init_nlp_db,
    get_classifier, get_nlp, get_extractor
)

# Maximum posts to feed through NLP -- keeps response under 20s
MAX_NLP_POSTS = 20


def run_nlp_processing(db_path: str = DB_PATH):
    """Fast NLP: load models, process top N posts only, run correlation."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    init_nlp_db(conn)

    # Check how many unprocessed posts exist
    unprocessed = conn.execute(
        "SELECT COUNT(*) FROM raw_posts WHERE processed = 0"
    ).fetchone()[0]

    if unprocessed == 0:
        print("  No posts to analyze.")
        return conn

    print(f"\n--- Phase 3: NLP Threat Analysis ---")
    print(f"  {unprocessed} posts collected. Analyzing top {min(unprocessed, MAX_NLP_POSTS)}...")

    t0 = time.time()
    get_classifier()
    get_nlp()
    get_extractor()
    print(f"  Models loaded in {time.time() - t0:.1f}s")

    # Single pass -- process at most MAX_NLP_POSTS, no looping
    t1 = time.time()
    count = process_batch(conn, batch_size=MAX_NLP_POSTS)
    print(f"  Analyzed {count} posts in {time.time() - t1:.1f}s")

    # Phase 4: cross-source correlation
    print("\n--- Phase 4: Cross-Source Correlation ---")
    events = run_correlation_pass(conn)
    if events:
        print(f"  {len(events)} correlation events detected!")
    else:
        print("  No cross-source correlations found.")

    return conn


async def main():
    parser = argparse.ArgumentParser(
        description="DWTIS v2 -- Dark Web Threat Intelligence Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_system.py --domain hdfc.com
    python run_system.py --email user@example.com --company "Acme Corp"
    python run_system.py --credential admin123
    python run_system.py --report-only --domain example.com
        """
    )
    parser.add_argument("--domain",      help="Target domain (e.g. hdfc.com)")
    parser.add_argument("--email",       help="Target email (e.g. user@example.com)")
    parser.add_argument("--company",     help="Target company name")
    parser.add_argument("--credential",  help="Target username / handle")
    parser.add_argument("--db",          default=DB_PATH, help="Database path")
    parser.add_argument("--report-only", action="store_true",
                        help="Skip scraping, just NLP + report on existing DB")
    args = parser.parse_args()

    entity = TargetEntity(
        domain=args.domain,
        email=args.email,
        company=args.company,
        credential=args.credential
    )

    try:
        entity.validate()
    except ValueError as e:
        print(f"Error: {e}")
        print("Provide at least one of: --domain, --email, --company, --credential")
        sys.exit(1)

    print("=" * 55)
    print("  DWTIS v2 -- Dark Web Threat Intelligence System")
    print("=" * 55)
    print(f"  Target : {entity.summary()}")
    print(f"  DB     : {args.db}")
    print("=" * 55)

    start = time.time()

    if not args.report_only:
        # Phase 1 + 2: Entity-targeted scraping + breach APIs
        await run_once_all([entity], db_path=args.db)

    # Phase 3 + 4: Fast NLP (capped at 20 posts) + correlation
    nlp_conn = run_nlp_processing(args.db)

    # Dispatch alerts (JSON Log / Webhook)
    from alerter import pull_and_dispatch_alerts
    pull_and_dispatch_alerts(args.db)

    # Phase 5: Threat report
    print_full_report(nlp_conn, entity)

    elapsed = time.time() - start
    print(f"  Total scan time: {elapsed:.1f}s\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(0)