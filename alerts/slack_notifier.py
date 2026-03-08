"""
Healthcare Privacy Firewall — Slack Notifier
Sends alert notifications to Slack channels via webhook.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


class SlackNotifier:
    """Sends formatted alert notifications to Slack via incoming webhooks."""

    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or SLACK_WEBHOOK_URL

    def send(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send an alert to Slack.

        Returns delivery status dict.
        """
        if not self.webhook_url or self.webhook_url.startswith("https://hooks.slack.com/services/YOUR"):
            logger.warning("Slack webhook URL not configured, skipping notification")
            return {"status": "skipped", "reason": "webhook_not_configured"}

        payload = self._build_slack_payload(alert)

        try:
            import httpx

            response = httpx.post(
                self.webhook_url,
                json=payload,
                timeout=10.0,
            )

            if response.status_code == 200:
                logger.info("Slack alert sent successfully")
                return {"status": "sent", "response_code": 200}
            else:
                logger.error(f"Slack webhook returned {response.status_code}: {response.text}")
                return {
                    "status": "failed",
                    "response_code": response.status_code,
                    "error": response.text,
                }

        except ImportError:
            # Fallback to urllib if httpx not available
            return self._send_urllib(payload)
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return {"status": "failed", "error": str(e)}

    def _send_urllib(self, payload: Dict) -> Dict[str, Any]:
        """Fallback sender using urllib."""
        import urllib.request
        import urllib.error

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    return {"status": "sent", "response_code": 200}
                return {"status": "failed", "response_code": response.status}
        except urllib.error.URLError as e:
            return {"status": "failed", "error": str(e)}

    def _build_slack_payload(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Build a rich Slack message payload using Block Kit."""
        severity = alert.get("severity", "medium")
        severity_emoji = {
            "low": "🟢",
            "medium": "🟡",
            "high": "🟠",
            "critical": "🔴",
        }.get(severity, "⚪")

        risk_score = alert.get("risk_score", 0)
        entity_count = alert.get("entity_count", 0)

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji} Healthcare Privacy Firewall Alert",
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{severity.upper()}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Score:*\n{risk_score}/100",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Entities Detected:*\n{entity_count}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Policy Violated:*\n{'Yes ⚠️' if alert.get('policy_violated') else 'No ✅'}",
                    },
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```{alert.get('message', 'No details available')}```",
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"🕐 {alert.get('created_at', datetime.utcnow().isoformat())} UTC | Scan ID: {alert.get('scan_id', 'N/A')}",
                    }
                ],
            },
        ]

        return {"blocks": blocks}
