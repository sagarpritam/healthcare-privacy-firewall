"""
Healthcare Privacy Firewall — Blur Engine
Orchestrates image-based PII detection and redaction pipeline.
"""

import logging
import time
from typing import Dict, Any, Optional, List

from workers.image_worker.ocr_engine import get_ocr_engine
from workers.image_worker.image_blur import ImageBlurEngine
from workers.text_worker.presidio_engine import get_presidio_engine
from workers.text_worker.regex_detector import get_regex_detector
from intelligence.risk_engine import RiskEngine

logger = logging.getLogger(__name__)


class BlurEngine:
    """
    Orchestrates the image PII detection and redaction pipeline:
    OCR → text detection → blur/redact regions.
    """

    def __init__(self, blur_radius: int = 30, mode: str = "blur"):
        self.blur_engine = ImageBlurEngine(blur_radius=blur_radius)
        self.risk_engine = RiskEngine()
        self.mode = mode  # "blur" or "redact"

    def process_image(
        self,
        image_path: str,
        output_path: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Full image scanning pipeline:
        1. OCR to extract text
        2. Detect PII in extracted text
        3. Map PII to image regions
        4. Blur/redact those regions

        Returns result with OCR text, detections, risk, and output image path.
        """
        start_time = time.time()
        blur_mode = mode or self.mode

        # Step 1: OCR extraction
        ocr_engine = get_ocr_engine()
        ocr_result = ocr_engine.extract_text(image_path)

        extracted_text = ocr_result["text"]
        words_with_positions = ocr_result.get("words_with_positions", [])

        if not extracted_text.strip():
            return {
                "image_path": image_path,
                "output_path": None,
                "extracted_text": "",
                "entity_count": 0,
                "detections": [],
                "risk": {"score": 0, "level": "low"},
                "processing_time_ms": round((time.time() - start_time) * 1000, 2),
            }

        # Step 2: Detect PII in extracted text
        all_detections = []

        try:
            presidio = get_presidio_engine()
            all_detections.extend(presidio.analyze(extracted_text))
        except Exception as e:
            logger.error(f"Presidio failed on OCR text: {e}")

        try:
            regex = get_regex_detector()
            all_detections.extend(regex.detect(extracted_text))
        except Exception as e:
            logger.error(f"Regex failed on OCR text: {e}")

        # Step 3: Map detections to image regions
        pii_regions = self.blur_engine.get_pii_regions(
            words_with_positions, all_detections
        )

        # Step 4: Blur/redact regions
        result_path = None
        if pii_regions:
            result_path = self.blur_engine.blur_regions(
                image_path, pii_regions, output_path, mode=blur_mode
            )

        # Step 5: Risk scoring
        risk_result = self.risk_engine.calculate_risk(all_detections)

        processing_time_ms = round((time.time() - start_time) * 1000, 2)

        return {
            "image_path": image_path,
            "output_path": result_path,
            "extracted_text": extracted_text,
            "ocr_confidence": ocr_result["confidence"],
            "entity_count": len(all_detections),
            "regions_masked": len(pii_regions),
            "detections": [
                {
                    "entity_type": d["entity_type"],
                    "text": d.get("text", ""),
                    "score": d["score"],
                    "engine": d.get("detection_engine", "unknown"),
                }
                for d in all_detections
            ],
            "risk": {
                "score": risk_result["risk_score"],
                "level": risk_result["risk_level"],
            },
            "processing_time_ms": processing_time_ms,
        }

    def process_image_bytes(
        self, image_bytes: bytes, mode: Optional[str] = None
    ) -> Dict[str, Any]:
        """Process image from bytes (for API uploads)."""
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(
            suffix=".png", delete=False
        ) as tmp:
            tmp.write(image_bytes)
            tmp_path = tmp.name

        try:
            return self.process_image(tmp_path, mode=mode)
        finally:
            os.unlink(tmp_path)
