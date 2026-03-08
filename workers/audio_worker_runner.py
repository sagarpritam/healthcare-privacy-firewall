"""
Healthcare Privacy Firewall — Audio Worker Runner
Consumes audio scanning jobs from Redis queue.
"""

import sys
import logging
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from queue.redis_client import get_redis_client, QUEUE_AUDIO
from workers.audio_worker.whisper_engine import get_whisper_engine
from masking.pii_masker import PIIMasker
from analytics.metrics_engine import get_metrics_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | AUDIO-WORKER | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)


def process_audio_job(job_data: dict) -> dict:
    """Process a single audio scanning job."""
    job_id = job_data.get("job_id", "unknown")
    audio_path = job_data.get("audio_path", "")

    logger.info(f"Processing audio job {job_id}: {audio_path}")

    # Transcribe
    whisper = get_whisper_engine()
    transcription = whisper.transcribe(audio_path)
    text = transcription.get("text", "")

    # Detect PII
    if text.strip():
        masker = PIIMasker()
        result = masker.process_text(text=text)
        return {
            "job_id": job_id,
            "transcribed_text": text,
            "masked_text": result["masked_text"],
            "entity_count": result["entity_count"],
            "risk_score": result["risk"]["score"],
            "risk_level": result["risk"]["level"],
            "duration_seconds": transcription.get("duration_seconds", 0),
            "processing_time_ms": result["processing_time_ms"],
        }
    else:
        return {
            "job_id": job_id,
            "transcribed_text": "",
            "masked_text": "",
            "entity_count": 0,
            "risk_score": 0,
            "risk_level": "low",
            "duration_seconds": 0,
            "processing_time_ms": 0,
        }


def main():
    logger.info("🎙️ Audio worker starting...")
    redis = get_redis_client()
    metrics = get_metrics_engine()

    if not redis.health_check():
        logger.error("Redis not available. Exiting.")
        sys.exit(1)

    logger.info("✅ Audio worker connected. Listening for jobs...")

    while True:
        try:
            job_data = redis.dequeue(QUEUE_AUDIO, timeout=5)
            if job_data is None:
                continue

            job_id = job_data.get("job_id", "unknown")
            redis.update_job_status(job_id, "processing")

            try:
                result = process_audio_job(job_data)
                redis.update_job_status(job_id, "completed", result)
                metrics.record_scan({
                    "scan_type": "audio",
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
