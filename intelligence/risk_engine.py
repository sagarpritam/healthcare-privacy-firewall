"""
Healthcare Privacy Firewall — Risk Scoring Engine
Calculates weighted risk scores based on detected PII/PHI entities and context.
"""

import logging
import ipaddress
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Default risk weights per entity type
DEFAULT_RISK_WEIGHTS = {
    "US_SSN": 40,
    "CREDIT_CARD": 35,
    "API_KEY": 45,
    "PASSWORD": 50,
    "PRIVATE_KEY": 50,
    "AWS_CREDENTIALS": 50,
    "JWT_TOKEN": 40,
    "DATABASE_URL": 45,
    "MEDICAL_RECORD_NUMBER": 30,
    "NPI_NUMBER": 25,
    "DATE_OF_BIRTH": 20,
    "US_DRIVER_LICENSE": 30,
    "ICD_CODE": 20,
    "CPT_CODE": 15,
    "HEALTH_PLAN_ID": 25,
    "DEA_NUMBER": 35,
    "PERSON": 15,
    "PHONE_NUMBER": 10,
    "EMAIL_ADDRESS": 10,
    "LOCATION": 5,
    "IP_ADDRESS": 5,
    "DATE_TIME": 3,
    "IBAN_CODE": 30,
    "US_BANK_NUMBER": 30,
    "US_PASSPORT": 35,
}

RISK_LEVELS = {
    "low": (0, 30),
    "medium": (30, 60),
    "high": (60, 85),
    "critical": (85, 101),
}


class RiskEngine:
    """
    Calculates risk scores for scanned payloads based on:
    - Entity types detected and their weights
    - Confidence scores of detections
    - Volume of detections
    - Context sensitivity modifiers
    """

    def __init__(
        self,
        risk_weights: Optional[Dict[str, int]] = None,
        risk_levels: Optional[Dict[str, tuple]] = None,
    ):
        self.risk_weights = risk_weights or DEFAULT_RISK_WEIGHTS
        self.risk_levels = risk_levels or RISK_LEVELS

    def calculate_risk(
        self,
        detections: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Calculate overall risk score for a set of detections.

        Args:
            detections: List of detected entities with entity_type, score, text
            context: Optional context (source_ip, endpoint, user_agent, etc.)

        Returns:
            Dict with risk_score, risk_level, breakdown, and recommendations.
        """
        if not detections:
            return {
                "risk_score": 0.0,
                "risk_level": "low",
                "entity_count": 0,
                "breakdown": [],
                "high_risk_entities": [],
                "recommendations": [],
            }

        breakdown = []
        total_weighted_score = 0.0
        high_risk_entities = []
        entity_type_counts = {}

        for det in detections:
            entity_type = det.get("entity_type", "UNKNOWN")
            confidence = det.get("score", 0.5)
            weight = self.risk_weights.get(entity_type, 10)

            # Weighted contribution: weight * confidence
            contribution = weight * confidence
            total_weighted_score += contribution

            # Track counts per entity type
            entity_type_counts[entity_type] = entity_type_counts.get(entity_type, 0) + 1

            if weight >= 30:
                high_risk_entities.append({
                    "entity_type": entity_type,
                    "weight": weight,
                    "confidence": round(confidence, 4),
                    "contribution": round(contribution, 2),
                })

            breakdown.append({
                "entity_type": entity_type,
                "weight": weight,
                "confidence": round(confidence, 4),
                "contribution": round(contribution, 2),
            })

        # Volume multiplier: more entities = higher risk (diminishing returns)
        entity_count = len(detections)
        volume_multiplier = min(2.0, 1.0 + (entity_count - 1) * 0.1)

        # Diversity multiplier: different entity types = higher risk
        unique_types = len(entity_type_counts)
        diversity_multiplier = min(1.5, 1.0 + (unique_types - 1) * 0.1)

        # Context modifier
        context_modifier = self._calculate_context_modifier(context)

        # Final risk score (capped at 100)
        raw_score = total_weighted_score * volume_multiplier * diversity_multiplier * context_modifier
        risk_score = min(100.0, round(raw_score, 2))

        # Determine risk level
        risk_level = self._get_risk_level(risk_score)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            risk_score, risk_level, high_risk_entities, entity_type_counts
        )

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "entity_count": entity_count,
            "unique_entity_types": unique_types,
            "volume_multiplier": round(volume_multiplier, 2),
            "diversity_multiplier": round(diversity_multiplier, 2),
            "context_modifier": round(context_modifier, 2),
            "breakdown": breakdown,
            "high_risk_entities": high_risk_entities,
            "entity_type_counts": entity_type_counts,
            "recommendations": recommendations,
        }

    def _calculate_context_modifier(
        self, context: Optional[Dict[str, Any]]
    ) -> float:
        """Calculate context-based risk modifier."""
        if not context:
            return 1.0

        modifier = 1.0

        # External source IP increases risk
        source_ip = context.get("source_ip") or ""
        if source_ip:
            try:
                # Use standard standard ipaddress library to correctly classify private/local networks
                if not ipaddress.ip_address(source_ip).is_private:
                    modifier *= 1.2
            except ValueError:
                # If IP is malformed/invalid, treat it as untrusted
                modifier *= 1.2

        # Certain endpoints are higher risk
        endpoint = context.get("endpoint") or ""
        high_risk_endpoints = ["/patient", "/medical", "/billing", "/insurance", "/prescription"]
        if endpoint and any(ep in endpoint.lower() for ep in high_risk_endpoints):
            modifier *= 1.3

        # Large payload size increases risk
        payload_size = context.get("payload_size", 0)
        if payload_size > 10000:
            modifier *= 1.1

        return modifier

    def _get_risk_level(self, score: float) -> str:
        """Map numeric score to risk level."""
        for level, (low, high) in self.risk_levels.items():
            if low <= score < high:
                return level
        return "critical"

    def _generate_recommendations(
        self,
        risk_score: float,
        risk_level: str,
        high_risk_entities: List[Dict],
        entity_counts: Dict[str, int],
    ) -> List[str]:
        """Generate actionable recommendations based on risk assessment."""
        recommendations = []

        if risk_level in ("high", "critical"):
            recommendations.append("IMMEDIATE: Block or quarantine this payload for manual review")
            recommendations.append("Notify security team and compliance officer")

        if any(e["entity_type"] in ("US_SSN", "CREDIT_CARD") for e in high_risk_entities):
            recommendations.append("PCI/HIPAA violation potential — ensure data is not stored unencrypted")

        if any(e["entity_type"] in ("API_KEY", "PASSWORD", "AWS_CREDENTIALS", "PRIVATE_KEY") for e in high_risk_entities):
            recommendations.append("CREDENTIAL LEAK: Rotate exposed credentials immediately")

        if "MEDICAL_RECORD_NUMBER" in entity_counts or "NPI_NUMBER" in entity_counts:
            recommendations.append("PHI detected — HIPAA compliance review required")

        if risk_level == "medium":
            recommendations.append("Review masking effectiveness and consider stricter policies")

        if not recommendations:
            recommendations.append("Low risk — standard masking applied")

        return recommendations

    def should_alert(self, risk_score: float, min_score: float = 60.0) -> bool:
        """Determine if an alert should be triggered."""
        return risk_score >= min_score

    def should_block(self, risk_score: float, block_threshold: float = 85.0) -> bool:
        """Determine if the request should be blocked."""
        return risk_score >= block_threshold
