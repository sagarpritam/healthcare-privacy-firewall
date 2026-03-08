"""
Healthcare Privacy Firewall — Redis Queue Client
Manages job publishing and consumption for text, image, and audio processing workers.
"""

import os
import json
import uuid
import logging
from datetime import datetime
from typing import Optional, Dict, Any, Callable

import redis
from rq import Queue, Worker
from rq.job import Job

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Queue names
QUEUE_TEXT = "text_processing"
QUEUE_IMAGE = "image_processing"
QUEUE_AUDIO = "audio_processing"
QUEUE_ALERTS = "alert_processing"


class RedisClient:
    """Central Redis client for queue management and caching."""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or REDIS_URL
        self.connection = redis.from_url(
            self.redis_url,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            retry_on_timeout=True,
        )
        self._raw_connection = redis.from_url(
            self.redis_url,
            decode_responses=False,
            socket_timeout=5,
            socket_connect_timeout=5,
        )

        # Initialize queues
        self.text_queue = Queue(QUEUE_TEXT, connection=self._raw_connection)
        self.image_queue = Queue(QUEUE_IMAGE, connection=self._raw_connection)
        self.audio_queue = Queue(QUEUE_AUDIO, connection=self._raw_connection)
        self.alert_queue = Queue(QUEUE_ALERTS, connection=self._raw_connection)

    def health_check(self) -> bool:
        """Check Redis connectivity."""
        try:
            return self.connection.ping()
        except redis.ConnectionError:
            logger.error("Redis connection failed")
            return False

    def enqueue_text_scan(
        self, payload: str, metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Enqueue a text scanning job."""
        job_id = str(uuid.uuid4())
        job_data = {
            "job_id": job_id,
            "type": "text",
            "payload": payload,
            "metadata": metadata or {},
            "created_at": datetime.utcnow().isoformat(),
        }
        self.connection.rpush(QUEUE_TEXT, json.dumps(job_data))
        self.connection.hset(f"job:{job_id}", mapping={
            "status": "queued",
            "type": "text",
            "created_at": job_data["created_at"],
        })
        logger.info(f"Enqueued text scan job: {job_id}")
        return job_id

    def enqueue_image_scan(
        self, image_path: str, metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Enqueue an image scanning job."""
        job_id = str(uuid.uuid4())
        job_data = {
            "job_id": job_id,
            "type": "image",
            "image_path": image_path,
            "metadata": metadata or {},
            "created_at": datetime.utcnow().isoformat(),
        }
        self.connection.rpush(QUEUE_IMAGE, json.dumps(job_data))
        self.connection.hset(f"job:{job_id}", mapping={
            "status": "queued",
            "type": "image",
            "created_at": job_data["created_at"],
        })
        logger.info(f"Enqueued image scan job: {job_id}")
        return job_id

    def enqueue_audio_scan(
        self, audio_path: str, metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Enqueue an audio scanning job."""
        job_id = str(uuid.uuid4())
        job_data = {
            "job_id": job_id,
            "type": "audio",
            "audio_path": audio_path,
            "metadata": metadata or {},
            "created_at": datetime.utcnow().isoformat(),
        }
        self.connection.rpush(QUEUE_AUDIO, json.dumps(job_data))
        self.connection.hset(f"job:{job_id}", mapping={
            "status": "queued",
            "type": "audio",
            "created_at": job_data["created_at"],
        })
        logger.info(f"Enqueued audio scan job: {job_id}")
        return job_id

    def enqueue_alert(self, alert_data: Dict[str, Any]) -> str:
        """Enqueue an alert for delivery."""
        job_id = str(uuid.uuid4())
        alert_data["job_id"] = job_id
        alert_data["created_at"] = datetime.utcnow().isoformat()
        self.connection.rpush(QUEUE_ALERTS, json.dumps(alert_data))
        logger.info(f"Enqueued alert job: {job_id}")
        return job_id

    def dequeue(self, queue_name: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """Blocking dequeue from a named queue."""
        result = self.connection.blpop(queue_name, timeout=timeout)
        if result:
            _, data = result
            return json.loads(data)
        return None

    def get_job_status(self, job_id: str) -> Optional[Dict[str, str]]:
        """Get the status of a job."""
        return self.connection.hgetall(f"job:{job_id}")

    def update_job_status(
        self, job_id: str, status: str, result: Optional[Dict[str, Any]] = None
    ):
        """Update job status and optionally store result."""
        updates = {"status": status, "updated_at": datetime.utcnow().isoformat()}
        self.connection.hset(f"job:{job_id}", mapping=updates)
        if result:
            self.connection.hset(
                f"job:{job_id}:result",
                mapping={k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in result.items()},
            )
        # Auto-expire job keys after 24 hours
        self.connection.expire(f"job:{job_id}", 86400)
        if result:
            self.connection.expire(f"job:{job_id}:result", 86400)

    def get_job_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored result for a completed job."""
        raw = self.connection.hgetall(f"job:{job_id}:result")
        if not raw:
            return None
        result = {}
        for k, v in raw.items():
            try:
                result[k] = json.loads(v)
            except (json.JSONDecodeError, TypeError):
                result[k] = v
        return result

    def get_queue_lengths(self) -> Dict[str, int]:
        """Get lengths of all processing queues."""
        return {
            QUEUE_TEXT: self.connection.llen(QUEUE_TEXT),
            QUEUE_IMAGE: self.connection.llen(QUEUE_IMAGE),
            QUEUE_AUDIO: self.connection.llen(QUEUE_AUDIO),
            QUEUE_ALERTS: self.connection.llen(QUEUE_ALERTS),
        }

    def cache_set(self, key: str, value: Any, ttl: int = 3600):
        """Set a cached value with TTL."""
        self.connection.setex(key, ttl, json.dumps(value))

    def cache_get(self, key: str) -> Optional[Any]:
        """Get a cached value."""
        raw = self.connection.get(key)
        if raw:
            return json.loads(raw)
        return None

    def close(self):
        """Close Redis connections."""
        self.connection.close()
        self._raw_connection.close()


# Module-level singleton
_client: Optional[RedisClient] = None


def get_redis_client() -> RedisClient:
    """Get or create the global Redis client singleton."""
    global _client
    if _client is None:
        _client = RedisClient()
    return _client
