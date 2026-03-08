"""
Healthcare Privacy Firewall — Metrics Engine
Aggregates and exposes metrics for the analytics dashboard and Prometheus.
"""

import logging
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


class MetricsEngine:
    """
    Aggregates scan, detection, and alert metrics for dashboard and monitoring.
    Supports in-memory counters and Prometheus-compatible export.
    """

    def __init__(self):
        self._counters = defaultdict(int)
        self._gauges = defaultdict(float)
        self._histograms = defaultdict(list)
        self._recent_scans = []
        self._max_recent = 1000
        self._start_time = time.time()

    def record_scan(self, scan_result: Dict[str, Any]):
        """Record metrics from a completed scan."""
        scan_type = scan_result.get("scan_type", "text")
        risk_level = scan_result.get("risk", {}).get("level", "low")
        risk_score = scan_result.get("risk", {}).get("score", 0)
        entity_count = scan_result.get("entity_count", 0)
        processing_time = scan_result.get("processing_time_ms", 0)
        policy_result = scan_result.get("policy", {}).get("result", "pass")

        # Update counters
        self._counters["total_scans"] += 1
        self._counters[f"scans_by_type_{scan_type}"] += 1
        self._counters[f"scans_by_risk_{risk_level}"] += 1
        self._counters["total_entities_detected"] += entity_count

        if policy_result == "fail":
            self._counters["policy_violations"] += 1
        if scan_result.get("policy", {}).get("should_block"):
            self._counters["blocked_requests"] += 1

        # Update gauges
        self._gauges["last_risk_score"] = risk_score
        self._gauges["last_entity_count"] = entity_count

        # Update histograms
        self._histograms["risk_scores"].append(risk_score)
        self._histograms["processing_times"].append(processing_time)
        self._histograms["entity_counts"].append(entity_count)

        # Trim histograms
        for key in self._histograms:
            if len(self._histograms[key]) > self._max_recent:
                self._histograms[key] = self._histograms[key][-self._max_recent:]

        # Record recent scan
        self._recent_scans.append({
            "timestamp": datetime.utcnow().isoformat(),
            "scan_type": scan_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "entity_count": entity_count,
            "policy_result": policy_result,
            "processing_time_ms": processing_time,
        })
        if len(self._recent_scans) > self._max_recent:
            self._recent_scans = self._recent_scans[-self._max_recent:]

    def record_alert(self, alert: Dict[str, Any]):
        """Record an alert event."""
        self._counters["total_alerts"] += 1
        severity = alert.get("severity", "medium")
        self._counters[f"alerts_by_severity_{severity}"] += 1
        channel = alert.get("channel", "unknown")
        self._counters[f"alerts_by_channel_{channel}"] += 1

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics for the analytics dashboard."""
        uptime_seconds = time.time() - self._start_time

        risk_scores = self._histograms.get("risk_scores", [])
        processing_times = self._histograms.get("processing_times", [])
        entity_counts = self._histograms.get("entity_counts", [])

        return {
            "overview": {
                "total_scans": self._counters["total_scans"],
                "total_entities_detected": self._counters["total_entities_detected"],
                "total_alerts": self._counters["total_alerts"],
                "policy_violations": self._counters["policy_violations"],
                "blocked_requests": self._counters["blocked_requests"],
                "uptime_seconds": round(uptime_seconds, 0),
            },
            "scans_by_type": {
                "text": self._counters.get("scans_by_type_text", 0),
                "image": self._counters.get("scans_by_type_image", 0),
                "audio": self._counters.get("scans_by_type_audio", 0),
            },
            "scans_by_risk": {
                "low": self._counters.get("scans_by_risk_low", 0),
                "medium": self._counters.get("scans_by_risk_medium", 0),
                "high": self._counters.get("scans_by_risk_high", 0),
                "critical": self._counters.get("scans_by_risk_critical", 0),
            },
            "averages": {
                "avg_risk_score": round(
                    sum(risk_scores) / len(risk_scores), 2
                ) if risk_scores else 0,
                "avg_processing_time_ms": round(
                    sum(processing_times) / len(processing_times), 2
                ) if processing_times else 0,
                "avg_entities_per_scan": round(
                    sum(entity_counts) / len(entity_counts), 2
                ) if entity_counts else 0,
            },
            "peaks": {
                "max_risk_score": max(risk_scores) if risk_scores else 0,
                "max_processing_time_ms": round(max(processing_times), 2) if processing_times else 0,
                "max_entities_in_scan": max(entity_counts) if entity_counts else 0,
            },
            "recent_scans": self._recent_scans[-20:],
        }

    def get_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = [
            "# HELP firewall_scans_total Total number of scans processed",
            "# TYPE firewall_scans_total counter",
            f'firewall_scans_total {self._counters["total_scans"]}',
            "",
            "# HELP firewall_entities_total Total entities detected",
            "# TYPE firewall_entities_total counter",
            f'firewall_entities_total {self._counters["total_entities_detected"]}',
            "",
            "# HELP firewall_alerts_total Total alerts generated",
            "# TYPE firewall_alerts_total counter",
            f'firewall_alerts_total {self._counters["total_alerts"]}',
            "",
            "# HELP firewall_policy_violations_total Total policy violations",
            "# TYPE firewall_policy_violations_total counter",
            f'firewall_policy_violations_total {self._counters["policy_violations"]}',
            "",
            "# HELP firewall_blocked_total Total blocked requests",
            "# TYPE firewall_blocked_total counter",
            f'firewall_blocked_total {self._counters["blocked_requests"]}',
            "",
        ]

        # Scan type breakdown
        for scan_type in ["text", "image", "audio"]:
            count = self._counters.get(f"scans_by_type_{scan_type}", 0)
            lines.append(f'firewall_scans_by_type{{type="{scan_type}"}} {count}')

        # Risk level breakdown
        lines.append("")
        for risk in ["low", "medium", "high", "critical"]:
            count = self._counters.get(f"scans_by_risk_{risk}", 0)
            lines.append(f'firewall_scans_by_risk{{level="{risk}"}} {count}')

        return "\n".join(lines) + "\n"

    def reset(self):
        """Reset all metrics (for testing)."""
        self._counters.clear()
        self._gauges.clear()
        self._histograms.clear()
        self._recent_scans.clear()
        self._start_time = time.time()


# Module-level singleton
_engine: Optional[MetricsEngine] = None


def get_metrics_engine() -> MetricsEngine:
    global _engine
    if _engine is None:
        _engine = MetricsEngine()
    return _engine
