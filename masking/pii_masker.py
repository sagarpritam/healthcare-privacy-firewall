"""
Healthcare Privacy Firewall — PII Masker (Orchestrator)
Central masking orchestrator that combines detection + masking for text payloads.
"""

import hashlib
import logging
import time
from typing import Dict, Any, List, Optional

from workers.text_worker.presidio_engine import get_presidio_engine
from workers.text_worker.regex_detector import get_regex_detector
from workers.text_worker.text_masker import TextMasker, create_masker_from_config
from intelligence.risk_engine import RiskEngine
from intelligence.policy_engine import PolicyEngine

logger = logging.getLogger(__name__)


class PIIMasker:
    """
    Orchestrates the full PII detection and masking pipeline for text payloads.
    Combines Presidio NLP + regex detection, applies masking, scores risk, evaluates policies.
    """

    def __init__(
        self,
        policies: Optional[Dict[str, Any]] = None,
        use_presidio: bool = True,
        use_regex: bool = True,
    ):
        self.use_presidio = use_presidio
        self.use_regex = use_regex

        # Initialize engines
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()

        # Initialize masker from policies
        if policies:
            self.text_masker = create_masker_from_config(policies)
        else:
            self.text_masker = TextMasker(
                entity_policies=self.policy_engine.policies.get("entity_policies", {})
            )

    def process_text(
        self,
        text: str,
        source_ip: Optional[str] = None,
        endpoint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Full pipeline: detect → mask → score → evaluate policy.

        Returns complete scan result with masked text, detections, risk, and policy evaluation.
        """
        start_time = time.time()

        # Step 1: Detect PII/PHI entities
        all_detections = self._detect(text)

        # Step 2: Mask detected entities
        masking_result = self.text_masker.mask_text(text, all_detections)

        # Step 3: Calculate risk score
        context = {
            "source_ip": source_ip,
            "endpoint": endpoint,
            "payload_size": len(text),
        }
        risk_result = self.risk_engine.calculate_risk(all_detections, context)

        # Step 4: Evaluate policies
        policy_result = self.policy_engine.evaluate(
            detections=all_detections,
            risk_score=risk_result["risk_score"],
            risk_level=risk_result["risk_level"],
            masking_applied=True,
        )

        processing_time_ms = round((time.time() - start_time) * 1000, 2)

        # Build result
        result = {
            "original_hash": hashlib.sha256(text.encode()).hexdigest(),
            "masked_text": masking_result["masked_text"],
            "entity_count": masking_result["entity_count"],
            "detections": [
                {
                    "entity_type": d["entity_type"],
                    "start": d["start"],
                    "end": d["end"],
                    "score": d["score"],
                    "engine": d.get("detection_engine", "unknown"),
                }
                for d in all_detections
            ],
            "masking_details": masking_result["masking_details"],
            "risk": {
                "score": risk_result["risk_score"],
                "level": risk_result["risk_level"],
                "high_risk_entities": risk_result["high_risk_entities"],
                "recommendations": risk_result["recommendations"],
            },
            "policy": {
                "result": policy_result["overall_result"],
                "violations": policy_result["violations"],
                "should_block": policy_result["should_block"],
                "should_alert": policy_result["should_alert"],
                "actions": policy_result["actions"],
            },
            "processing_time_ms": processing_time_ms,
            "metadata": metadata or {},
        }

        logger.info(
            f"Processed text ({len(text)} chars): "
            f"{result['entity_count']} entities, "
            f"risk={result['risk']['score']} ({result['risk']['level']}), "
            f"policy={result['policy']['result']}, "
            f"time={processing_time_ms}ms"
        )

        return result

    def _detect(self, text: str) -> List[Dict[str, Any]]:
        """Run all detection engines and merge results."""
        all_detections = []

        # Presidio NLP detection
        if self.use_presidio:
            try:
                presidio = get_presidio_engine()
                presidio_results = presidio.analyze(text)
                all_detections.extend(presidio_results)
            except Exception as e:
                logger.error(f"Presidio detection failed: {e}")

        # Regex pattern detection
        if self.use_regex:
            try:
                regex = get_regex_detector()
                regex_results = regex.detect(text)
                all_detections.extend(regex_results)
            except Exception as e:
                logger.error(f"Regex detection failed: {e}")

        # Deduplicate overlapping detections
        all_detections = self._deduplicate(all_detections)

        return all_detections

    def _deduplicate(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate/overlapping detections, keeping highest confidence."""
        if not detections:
            return []

        # Sort by start position, then by score descending
        sorted_dets = sorted(detections, key=lambda x: (x["start"], -x["score"]))
        deduped = [sorted_dets[0]]

        for det in sorted_dets[1:]:
            last = deduped[-1]
            # Check for overlap
            if det["start"] < last["end"]:
                # Keep the one with higher score
                if det["score"] > last["score"]:
                    deduped[-1] = det
            else:
                deduped.append(det)

        return deduped

    def detect_only(self, text: str) -> List[Dict[str, Any]]:
        """Run detection without masking (for preview/analysis)."""
        return self._detect(text)

    def mask_only(
        self, text: str, detections: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Apply masking to pre-detected entities."""
        return self.text_masker.mask_text(text, detections)
