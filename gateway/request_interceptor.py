"""
Healthcare Privacy Firewall — Request Interceptor Middleware
Validates, sanitizes, and extracts payloads from incoming API requests.
"""

import re
import html
import logging
import time
from typing import Dict, Any, Optional, Tuple

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

MAX_TEXT_LENGTH = 1_000_000  # 1MB text
MAX_PAYLOAD_SIZE = 100 * 1024 * 1024  # 100MB
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 100  # requests per window


class RequestInterceptor:
    """
    Pre-processes and validates incoming requests before they reach
    the scanning pipeline. Handles input sanitization and rate limiting.
    """

    def __init__(
        self,
        max_text_length: int = MAX_TEXT_LENGTH,
        max_payload_size: int = MAX_PAYLOAD_SIZE,
        strip_html: bool = True,
    ):
        self.max_text_length = max_text_length
        self.max_payload_size = max_payload_size
        self.strip_html = strip_html
        self._request_counts: Dict[str, list] = {}

    def validate_text_request(self, text: str) -> Dict[str, Any]:
        """
        Validate and sanitize a text scan request.

        Returns dict with valid (bool), sanitized_text, and optional error.
        """
        if not text or not text.strip():
            return {"valid": False, "error": "Text payload is empty"}

        if len(text) > self.max_text_length:
            return {
                "valid": False,
                "error": f"Text exceeds maximum length of {self.max_text_length} characters",
            }

        # Sanitize
        sanitized = self._sanitize_text(text)

        return {
            "valid": True,
            "sanitized_text": sanitized,
            "original_length": len(text),
            "sanitized_length": len(sanitized),
        }

    def _sanitize_text(self, text: str) -> str:
        """Sanitize input text."""
        sanitized = text

        # Decode HTML entities
        sanitized = html.unescape(sanitized)

        # Strip HTML tags if configured
        if self.strip_html:
            sanitized = re.sub(r"<[^>]+>", " ", sanitized)

        # Normalize whitespace
        sanitized = re.sub(r"\s+", " ", sanitized).strip()

        return sanitized

    def check_rate_limit(self, client_ip: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if client IP has exceeded rate limits.

        Returns (allowed, info_dict).
        """
        now = time.time()

        if client_ip not in self._request_counts:
            self._request_counts[client_ip] = []

        # Clean old entries
        self._request_counts[client_ip] = [
            t for t in self._request_counts[client_ip]
            if now - t < RATE_LIMIT_WINDOW
        ]

        current_count = len(self._request_counts[client_ip])

        if current_count >= RATE_LIMIT_MAX:
            return False, {
                "error": "Rate limit exceeded",
                "limit": RATE_LIMIT_MAX,
                "window_seconds": RATE_LIMIT_WINDOW,
                "retry_after": RATE_LIMIT_WINDOW - (now - self._request_counts[client_ip][0]),
            }

        self._request_counts[client_ip].append(now)
        return True, {
            "remaining": RATE_LIMIT_MAX - current_count - 1,
            "limit": RATE_LIMIT_MAX,
        }

    def extract_metadata(self, request: Request) -> Dict[str, Any]:
        """Extract useful metadata from the incoming request."""
        return {
            "client_ip": request.client.host if request.client else None,
            "method": request.method,
            "path": str(request.url.path),
            "user_agent": request.headers.get("user-agent", ""),
            "content_type": request.headers.get("content-type", ""),
            "content_length": request.headers.get("content-length", "0"),
            "timestamp": time.time(),
        }


class InterceptorMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for automatic request interception.
    Applies rate limiting and logs all incoming requests.
    """

    def __init__(self, app, interceptor: Optional[RequestInterceptor] = None):
        super().__init__(app)
        self.interceptor = interceptor or RequestInterceptor()

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()

        # Extract metadata
        metadata = self.interceptor.extract_metadata(request)

        # Rate limit check
        client_ip = metadata.get("client_ip", "unknown")
        allowed, rate_info = self.interceptor.check_rate_limit(client_ip)

        if not allowed:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded", **rate_info},
            )

        # Process request
        response = await call_next(request)

        # Log request
        duration_ms = round((time.time() - start_time) * 1000, 2)
        logger.info(
            f"{request.method} {request.url.path} → {response.status_code} "
            f"({duration_ms}ms) from {client_ip}"
        )

        # Add headers
        response.headers["X-Request-Duration-Ms"] = str(duration_ms)
        response.headers["X-RateLimit-Remaining"] = str(rate_info.get("remaining", 0))

        return response
