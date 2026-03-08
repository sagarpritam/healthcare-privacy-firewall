"""
Healthcare Privacy Firewall — Text Worker Runner
Consumes text scanning jobs from Redis queue.
"""

import sys
import logging
import json
import hashlib
import time
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from queue.redis_client import get_redis_client, QUEUE_TEXT
from masking.pii_masker import PIIMasker
from alerts.alert_engine import AlertEngine
from analytics.metrics_engine import get_metrics_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | TEXT-WORKER | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)


def process_text_job(job_data: dict) -> dict:
    """Process a single text scanning job."""
    job_id = job_data.get("job_id", "unknown")
    payload = job_data.get("payload", "")
    metadata = job_data.get("metadata", {})

    logger.info(f"Processing text job {job_id} ({len(payload)} chars)")

    masker = PIIMasker()
    result = masker.process_text(
        text=payload,
        source_ip=metadata.get("source_ip"),
        endpoint=metadata.get("endpoint"),
        metadata=metadata,
    )

    return {
        "job_id": job_id,
        "masked_text": result["masked_text"],
        "entity_count": result["entity_count"],
        "risk_score": result["risk"]["score"],
        "risk_level": result["risk"]["level"],
        "policy_result": result["policy"]["result"],
        "processing_time_ms": result["processing_time_ms"],
    }


def main():
    """Main worker loop — consume from text queue."""
    logger.info("🔧 Text worker starting...")
    redis = get_redis_client()
    metrics = get_metrics_engine()
    alert_engine = AlertEngine()

    if not redis.health_check():
        logger.error("Redis not available. Exiting.")
        sys.exit(1)

    logger.info("✅ Text worker connected to Redis. Listening for jobs...")

    while True:
        try:
            job_data = redis.dequeue(QUEUE_TEXT, timeout=5)
            if job_data is None:
                continue

            job_id = job_data.get("job_id", "unknown")
            redis.update_job_status(job_id, "processing")

            try:
                result = process_text_job(job_data)
                redis.update_job_status(job_id, "completed", result)

                # Record metrics
                metrics.record_scan({
                    "scan_type": "text",
                    "risk": {"score": result["risk_score"], "level": result["risk_level"]},
                    "entity_count": result["entity_count"],
                    "policy": {"result": result["policy_result"]},
                    "processing_time_ms": result["processing_time_ms"],
                })

                logger.info(f"✅ Job {job_id} completed: {result['entity_count']} entities, risk={result['risk_score']}")

            except Exception as e:
                logger.error(f"❌ Job {job_id} failed: {e}")
                redis.update_job_status(job_id, "failed", {"error": str(e)})

        except KeyboardInterrupt:
            logger.info("Worker shutting down...")
            break
        except Exception as e:
            logger.error(f"Worker error: {e}")
            time.sleep(1)

    redis.close()


if __name__ == "__main__":
    main()
