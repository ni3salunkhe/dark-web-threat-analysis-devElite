import asyncio
import threading

from ingestion import IngestionPipeline
from nlp_engine_v2 import main as nlp_main


def start_nlp():
    nlp_main(once=False, interval=60)


if __name__ == "__main__":
    print("🚀 Starting Full Threat Intelligence System\n")

    # Start NLP in background
    threading.Thread(target=start_nlp, daemon=True).start()

    # Start ingestion
    pipeline = IngestionPipeline()
    asyncio.run(pipeline.run())