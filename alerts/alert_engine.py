"""
Healthcare Privacy Firewall — Alert Engine
Manages alert generation, routing, and delivery based on risk scores and policy violations.
"""

import logging
import time
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class AlertEngine:
    """
    Generates and routes alerts when scan results exceed risk thresholds
    or trigger policy violations.
    """

    def __init__(
        self,
        min_risk_score: float = 60.0,
        channels: Optional[List[Dict[str, Any]]] = None,
    ):
        self.min_risk_score = min_risk_score
        self.channels = channels or [{"type": "log", "min_risk_score": 0.0}]
        self.notifiers = {}

    def register_notifier(self, channel_type: str, notifier):
        """Register a notifier for a specific channel type."""
        self.notifiers[channel_type] = notifier
        logger.info(f"Registered notifier for channel: {channel_type}")

    def evaluate_and_alert(
        self,
        scan_result: Dict[str, Any],
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Evaluate a scan result and generate alerts if necessary.

        Returns list of alert records generated.
        """
        risk_score = scan_result.get("risk", {}).get("score", 0)
        risk_level = scan_result.get("risk", {}).get("level", "low")
        policy_result = scan_result.get("policy", {})
        should_alert = policy_result.get("should_alert", False)

        alerts_generated = []

        # Check if alert threshold is met
        if risk_score < self.min_risk_score and not should_alert:
            return alerts_generated

        # Generate alert
        alert = self._build_alert(scan_result, scan_id)

        # Route to configured channels
        for channel_config in self.channels:
            channel_type = channel_config.get("type", "log")
            channel_min_score = channel_config.get("min_risk_score", 0.0)

            if risk_score >= channel_min_score:
                delivery_result = self._deliver_alert(alert, channel_type)
                alerts_generated.append({
                    **alert,
                    "channel": channel_type,
                    "delivery_status": delivery_result.get("status", "unknown"),
                    "delivered_at": datetime.utcnow().isoformat(),
                })

        return alerts_generated

    def _build_alert(
        self,
        scan_result: Dict[str, Any],
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build an alert record from scan results."""
        risk = scan_result.get("risk", {})
        policy = scan_result.get("policy", {})
        entity_count = scan_result.get("entity_count", 0)

        # Determine severity
        risk_level = risk.get("level", "low")
        if policy.get("should_block"):
            severity = "critical"
        elif risk_level in ("high", "critical"):
            severity = risk_level
        else:
            severity = "medium"

        # Build message
        message_parts = [
            f"🚨 Healthcare Privacy Firewall Alert",
            f"Risk Score: {risk.get('score', 0)}/100 ({risk_level.upper()})",
            f"Entities Detected: {entity_count}",
        ]

        if policy.get("violations", 0) > 0:
            message_parts.append(f"Policy Violations: {policy['violations']}")

        high_risk = risk.get("high_risk_entities", [])
        if high_risk:
            types = ", ".join(set(e["entity_type"] for e in high_risk[:5]))
            message_parts.append(f"High Risk Entities: {types}")

        recommendations = risk.get("recommendations", [])
        if recommendations:
            message_parts.append(f"Recommendation: {recommendations[0]}")

        return {
            "alert_type": "privacy_violation",
            "severity": severity,
            "scan_id": scan_id,
            "message": "\n".join(message_parts),
            "risk_score": risk.get("score", 0),
            "risk_level": risk_level,
            "entity_count": entity_count,
            "policy_violated": policy.get("result", "pass") == "fail",
            "created_at": datetime.utcnow().isoformat(),
        }

    def _deliver_alert(
        self, alert: Dict[str, Any], channel_type: str
    ) -> Dict[str, Any]:
        """Deliver an alert through the specified channel."""
        if channel_type == "log":
            logger.warning(f"ALERT [{alert['severity'].upper()}]: {alert['message']}")
            return {"status": "sent"}

        notifier = self.notifiers.get(channel_type)
        if notifier:
            try:
                return notifier.send(alert)
            except Exception as e:
                logger.error(f"Failed to deliver alert via {channel_type}: {e}")
                return {"status": "failed", "error": str(e)}

        logger.warning(f"No notifier registered for channel: {channel_type}")
        return {"status": "skipped", "reason": "no_notifier"}
