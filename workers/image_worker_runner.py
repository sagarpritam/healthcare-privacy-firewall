"""
Healthcare Privacy Firewall — Image Worker Runner
Consumes image scanning jobs from Redis queue.
"""

import sys
import logging
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from queue.redis_client import get_redis_client, QUEUE_IMAGE
from masking.blur_engine import BlurEngine
from analytics.metrics_engine import get_metrics_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | IMAGE-WORKER | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)


def process_image_job(job_data: dict) -> dict:
    """Process a single image scanning job."""
    job_id = job_data.get("job_id", "unknown")
    image_path = job_data.get("image_path", "")

    logger.info(f"Processing image job {job_id}: {image_path}")

    blur_engine = BlurEngine()
    result = blur_engine.process_image(image_path)

    return {
        "job_id": job_id,
        "entity_count": result.get("entity_count", 0),
        "regions_masked": result.get("regions_masked", 0),
        "risk_score": result.get("risk", {}).get("score", 0),
        "risk_level": result.get("risk", {}).get("level", "low"),
        "output_path": result.get("output_path"),
        "processing_time_ms": result.get("processing_time_ms", 0),
    }


def main():
    logger.info("🖼️ Image worker starting...")
    redis = get_redis_client()
    metrics = get_metrics_engine()

    if not redis.health_check():
        logger.error("Redis not available. Exiting.")
        sys.exit(1)

    logger.info("✅ Image worker connected. Listening for jobs...")

    while True:
        try:
            job_data = redis.dequeue(QUEUE_IMAGE, timeout=5)
            if job_data is None:
                continue

            job_id = job_data.get("job_id", "unknown")
            redis.update_job_status(job_id, "processing")

            try:
                result = process_image_job(job_data)
                redis.update_job_status(job_id, "completed", result)
                metrics.record_scan({
                    "scan_type": "image",
                    "risk": {"score": result["risk_score"], "level": result["risk_level"]},
                    "entity_count": result["entity_count"],
                    "policy": {"result": "pass"},
                    "processing_time_ms": result["processing_time_ms"],
                })
                logger.info(f"✅ Job {job_id} completed")
            except Exception as e:
                logger.error(f"❌ Job {job_id} failed: {e}")
                redis.update_job_status(job_id, "failed", {"error": str(e)})

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Worker error: {e}")
            time.sleep(1)

    redis.close()


if __name__ == "__main__":
    main()
