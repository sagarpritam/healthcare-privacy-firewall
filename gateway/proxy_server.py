"""
Healthcare Privacy Firewall — FastAPI Gateway Proxy Server
Main entry point for the firewall. Exposes REST API for text, image, and audio scanning.
"""

import os
import sys
import logging
import time
import uuid
from typing import Optional, Dict, Any, List
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks, status, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

# Add project root to path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from gateway.request_interceptor import RequestInterceptor
from masking.pii_masker import PIIMasker
from intelligence.risk_engine import RiskEngine
from intelligence.policy_engine import PolicyEngine
from alerts.alert_engine import AlertEngine
from alerts.slack_notifier import SlackNotifier
from analytics.metrics_engine import get_metrics_engine

# Optional imports — these may not be installed locally
try:
    from masking.blur_engine import BlurEngine
    HAS_BLUR = True
except ImportError:
    HAS_BLUR = False

try:
    from workers.audio_worker.whisper_engine import get_whisper_engine
    HAS_WHISPER = True
except ImportError:
    HAS_WHISPER = False

try:
    from job_queue.redis_client import get_redis_client
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)


# ──────────────────────────── Pydantic Models ────────────────────────────

class TextScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=1000000, description="Text payload to scan")
    source: Optional[str] = Field(None, description="Source identifier")
    endpoint: Optional[str] = Field(None, description="Original API endpoint")
    async_mode: bool = Field(False, description="Queue for async processing")

class TextScanResponse(BaseModel):
    scan_id: str
    masked_text: str
    entity_count: int
    risk_score: float
    risk_level: str
    policy_result: str
    should_block: bool
    processing_time_ms: float
    detections: list
    recommendations: list

class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    services: dict


# ──────────────────────────── App Lifecycle ────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info("🚀 Healthcare Privacy Firewall starting up...")

    # Initialize core engines
    app.state.pii_masker = PIIMasker()
    app.state.risk_engine = RiskEngine()
    app.state.policy_engine = PolicyEngine()
    app.state.alert_engine = AlertEngine()
    app.state.metrics = get_metrics_engine()
    app.state.interceptor = RequestInterceptor()
    app.state.start_time = time.time()

    # Optional engines
    if HAS_BLUR:
        app.state.blur_engine = BlurEngine()
        logger.info("✅ Image scanning enabled")
    else:
        app.state.blur_engine = None
        logger.warning("⚠️  Image scanning disabled (pytesseract not installed)")

    app.state.whisper_available = HAS_WHISPER
    if HAS_WHISPER:
        logger.info("✅ Audio scanning enabled")
    else:
        logger.warning("⚠️  Audio scanning disabled (whisper not installed)")

    # Register Slack notifier
    try:
        slack = SlackNotifier()
        app.state.alert_engine.register_notifier("slack", slack)
    except Exception:
        logger.warning("⚠️  Slack notifier not configured")

    # Try to initialize Redis (non-blocking)
    app.state.redis = None
    if HAS_REDIS:
        try:
            redis = get_redis_client()
            if redis.health_check():
                app.state.redis = redis
                logger.info("✅ Redis connected")
            else:
                logger.warning("⚠️  Redis not available — running without queue")
        except Exception:
            logger.warning("⚠️  Redis not available — running without queue")
    else:
        logger.warning("⚠️  Redis library not installed — running without queue")

    # Try to initialize DB (non-blocking)
    try:
        from storage.db import init_db
        await init_db()
        logger.info("✅ Database initialized")
    except Exception as e:
        logger.warning(f"⚠️  Database not available: {e}")

    logger.info("✅ Healthcare Privacy Firewall ready")
    yield
    logger.info("🛑 Healthcare Privacy Firewall shutting down...")


# ──────────────────────────── FastAPI App ────────────────────────────

# --- API Key Security Setup ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_api_key(api_key: str = Depends(api_key_header)):
    """Validate the API key from the request header."""
    expected_key = os.environ.get("API_KEY", "dev-secret-key-123")
    if api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    return api_key

app = FastAPI(
    title="Healthcare Privacy Firewall",
    description=(
        "Production-grade API firewall for detecting and masking PHI/PII "
        "in healthcare API payloads. Supports text, image, and audio scanning."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────── Routes ────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check(request: Request):
    """System health check endpoint."""
    uptime = time.time() - request.app.state.start_time
    redis_ok = False
    try:
        if request.app.state.redis:
            redis_ok = request.app.state.redis.health_check()
    except Exception:
        pass

    return HealthResponse(
        status="healthy",
        version="1.0.0",
        uptime_seconds=round(uptime, 2),
        services={
            "gateway": True,
            "redis": redis_ok,
            "presidio": True,
            "regex_detector": True,
            "image_scanner": HAS_BLUR,
            "audio_scanner": HAS_WHISPER,
        },
    )


@app.post("/scan/text", response_model=TextScanResponse, tags=["Scanning"])
async def scan_text(
    body: TextScanRequest,
    request: Request,
    api_key: str = Depends(get_api_key)
):
    """
    Scan text payload for PHI/PII.
    Detects entities, applies masking, scores risk, and evaluates policies.
    """
    scan_id = str(uuid.uuid4())

    # Intercept and validate
    interceptor: RequestInterceptor = request.app.state.interceptor
    validation = interceptor.validate_text_request(body.text)
    if not validation["valid"]:
        raise HTTPException(status_code=400, detail=validation["error"])

    # Async mode: queue for background processing
    if body.async_mode and request.app.state.redis:
        redis = request.app.state.redis
        job_id = redis.enqueue_text_scan(
            body.text, metadata={"source": body.source, "endpoint": body.endpoint}
        )
        return JSONResponse(
            status_code=202,
            content={"scan_id": job_id, "status": "queued", "message": "Processing asynchronously"},
        )

    # Synchronous processing
    pii_masker: PIIMasker = request.app.state.pii_masker
    client_ip = request.client.host if request.client else None

    result = pii_masker.process_text(
        text=body.text,
        source_ip=client_ip,
        endpoint=body.endpoint,
        metadata={"source": body.source},
    )

    # Record metrics
    metrics = request.app.state.metrics
    metrics.record_scan({
        "scan_type": "text",
        "risk": result["risk"],
        "entity_count": result["entity_count"],
        "policy": result["policy"],
        "processing_time_ms": result["processing_time_ms"],
    })

    # Trigger alerts if needed
    if result["policy"].get("should_alert", False):
        alert_engine: AlertEngine = request.app.state.alert_engine
        alerts = alert_engine.evaluate_and_alert(result, scan_id)
        for alert in alerts:
            metrics.record_alert(alert)

    return TextScanResponse(
        scan_id=scan_id,
        masked_text=result["masked_text"],
        entity_count=result["entity_count"],
        risk_score=result["risk"]["score"],
        risk_level=result["risk"]["level"],
        policy_result=result["policy"]["result"],
        should_block=result["policy"]["should_block"],
        processing_time_ms=result["processing_time_ms"],
        detections=result["detections"],
        recommendations=result["risk"].get("recommendations", []),
    )


@app.post("/scan/image", tags=["Scanning"])
async def scan_image(
    request: Request,
    file: UploadFile = File(..., description="Image file to scan"),
    mode: str = Form("blur", description="'blur' or 'redact'"),
):
    """Scan image for PHI/PII using OCR."""
    if not request.app.state.blur_engine:
        raise HTTPException(status_code=503, detail="Image scanning not available (pytesseract not installed)")

    scan_id = str(uuid.uuid4())

    allowed = {"image/png", "image/jpeg", "image/tiff", "image/bmp"}
    if file.content_type not in allowed:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {file.content_type}")

    image_bytes = await file.read()
    if len(image_bytes) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Image exceeds 50MB limit")

    blur_engine = request.app.state.blur_engine
    try:
        result = blur_engine.process_image_bytes(image_bytes, mode=mode)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image processing failed: {str(e)}")

    metrics = request.app.state.metrics
    metrics.record_scan({
        "scan_type": "image",
        "risk": result.get("risk", {}),
        "entity_count": result.get("entity_count", 0),
        "policy": {"result": "pass"},
        "processing_time_ms": result.get("processing_time_ms", 0),
    })

    return {
        "scan_id": scan_id,
        "extracted_text": result.get("extracted_text", ""),
        "entity_count": result.get("entity_count", 0),
        "regions_masked": result.get("regions_masked", 0),
        "risk_score": result.get("risk", {}).get("score", 0),
        "risk_level": result.get("risk", {}).get("level", "low"),
        "detections": result.get("detections", []),
        "processing_time_ms": result.get("processing_time_ms", 0),
    }


@app.post("/scan/audio", tags=["Scanning"])
async def scan_audio(
    request: Request,
    file: UploadFile = File(..., description="Audio file to scan"),
):
    """Scan audio for PHI/PII using Whisper transcription + text detection."""
    if not request.app.state.whisper_available:
        raise HTTPException(status_code=503, detail="Audio scanning not available (whisper not installed)")

    scan_id = str(uuid.uuid4())

    audio_bytes = await file.read()
    if len(audio_bytes) > 100 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Audio file exceeds 100MB limit")

    start_time = time.time()

    whisper = get_whisper_engine()
    try:
        ext = Path(file.filename).suffix.lstrip(".") if file.filename else "wav"
        transcription = whisper.transcribe_bytes(audio_bytes, format=ext)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transcription failed: {str(e)}")

    pii_masker: PIIMasker = request.app.state.pii_masker
    text = transcription.get("text", "")

    if text.strip():
        result = pii_masker.process_text(text=text)
    else:
        result = {
            "masked_text": "", "entity_count": 0, "detections": [],
            "risk": {"score": 0, "level": "low", "recommendations": []},
            "policy": {"result": "pass", "should_block": False},
        }

    processing_time_ms = round((time.time() - start_time) * 1000, 2)

    metrics = request.app.state.metrics
    metrics.record_scan({
        "scan_type": "audio",
        "risk": result.get("risk", {}),
        "entity_count": result.get("entity_count", 0),
        "policy": result.get("policy", {}),
        "processing_time_ms": processing_time_ms,
    })

    return {
        "scan_id": scan_id,
        "transcribed_text": text,
        "masked_text": result.get("masked_text", ""),
        "entity_count": result.get("entity_count", 0),
        "risk_score": result.get("risk", {}).get("score", 0),
        "risk_level": result.get("risk", {}).get("level", "low"),
        "detections": result.get("detections", []),
        "segments": transcription.get("segments", []),
        "duration_seconds": transcription.get("duration_seconds", 0),
        "processing_time_ms": processing_time_ms,
    }


@app.get("/scan/{scan_id}/status", tags=["Scanning"])
async def get_scan_status(scan_id: str, request: Request):
    """Get the status of an async scan job."""
    if not request.app.state.redis:
        raise HTTPException(status_code=503, detail="Redis not available")

    redis = request.app.state.redis
    status = redis.get_job_status(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail="Scan job not found")

    result = redis.get_job_result(scan_id)
    return {"scan_id": scan_id, "status": status.get("status", "unknown"), "result": result}


@app.get("/analytics/dashboard", tags=["Analytics"])
async def get_dashboard(request: Request):
    """Get real-time analytics dashboard data."""
    return request.app.state.metrics.get_dashboard_metrics()


@app.get("/analytics/metrics", tags=["Analytics"])
async def get_prometheus_metrics(request: Request):
    """Prometheus-compatible metrics endpoint."""
    return PlainTextResponse(request.app.state.metrics.get_prometheus_metrics())


@app.get("/queue/status", tags=["System"])
async def get_queue_status(request: Request):
    """Get Redis queue lengths and status."""
    if not request.app.state.redis:
        return {"status": "unavailable", "message": "Redis not connected"}
    return {"status": "connected", "queues": request.app.state.redis.get_queue_lengths()}


# ──────────────────────────── Entry Point ────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "gateway.proxy_server:app",
        host=os.getenv("GATEWAY_HOST", "0.0.0.0"),
        port=int(os.getenv("GATEWAY_PORT", "8000")),
        reload=True,
        log_level="info",
    )
