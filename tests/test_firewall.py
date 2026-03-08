"""
Healthcare Privacy Firewall — API Smoke Tests
Validates core scanning, risk scoring, and policy enforcement.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestTextScanning:
    """Test the text PII detection and masking pipeline."""

    def setup_method(self):
        from masking.pii_masker import PIIMasker
        self.masker = PIIMasker()

    def test_dob_detection(self):
        result = self.masker.process_text("Patient DOB 01/15/1980, MRN: AB-123456")
        assert result["entity_count"] > 0
        # Original PII should be masked
        assert "AB-123456" not in result["masked_text"] or "01/15/1980" not in result["masked_text"]

    def test_empty_text(self):
        result = self.masker.process_text("Hello, this is a normal message with no PII.")
        assert result["entity_count"] == 0
        assert result["risk"]["score"] == 0

    def test_risk_scoring(self):
        result = self.masker.process_text(
            "Patient SSN 123-45-6789, DOB 01/15/1980, MRN: AB-123456"
        )
        assert result["risk"]["score"] > 0
        assert result["risk"]["level"] in ("low", "medium", "high", "critical")

    def test_policy_evaluation(self):
        result = self.masker.process_text("SSN 123-45-6789")
        assert "result" in result["policy"]
        assert "should_block" in result["policy"]

    def test_masking_applied(self):
        text = "Contact john@example.com or call 555-123-4567"
        result = self.masker.process_text(text)
        # Original PII should not appear in masked text if detected
        if result["entity_count"] > 0:
            for det in result["detections"]:
                original = text[det["start"]:det["end"]]
                assert original not in result["masked_text"]

    def test_processing_time(self):
        result = self.masker.process_text("Patient John Doe, SSN 999-88-7777")
        assert result["processing_time_ms"] > 0
        assert result["processing_time_ms"] < 5000  # Should complete in under 5s


class TestRiskEngine:
    """Test the risk scoring engine."""

    def setup_method(self):
        from intelligence.risk_engine import RiskEngine
        self.engine = RiskEngine()

    def test_no_detections(self):
        result = self.engine.calculate_risk([])
        assert result["risk_score"] == 0.0
        assert result["risk_level"] == "low"

    def test_high_risk_entities(self):
        detections = [
            {"entity_type": "US_SSN", "score": 0.95, "start": 0, "end": 11},
            {"entity_type": "CREDIT_CARD", "score": 0.9, "start": 20, "end": 36},
        ]
        result = self.engine.calculate_risk(detections)
        assert result["risk_score"] > 50
        assert len(result["high_risk_entities"]) > 0

    def test_context_modifier(self):
        detections = [{"entity_type": "PERSON", "score": 0.8, "start": 0, "end": 8}]
        result_no_ctx = self.engine.calculate_risk(detections)
        result_with_ctx = self.engine.calculate_risk(
            detections, context={"endpoint": "/patient/records"}
        )
        assert result_with_ctx["risk_score"] >= result_no_ctx["risk_score"]


class TestPolicyEngine:
    """Test the policy engine."""

    def setup_method(self):
        from intelligence.policy_engine import PolicyEngine
        self.engine = PolicyEngine()

    def test_pass_no_detections(self):
        result = self.engine.evaluate([], risk_score=0, risk_level="low")
        assert result["overall_result"] == "pass"
        assert result["should_block"] is False

    def test_critical_risk_blocks(self):
        detections = [{"entity_type": "US_SSN", "score": 0.95, "start": 0, "end": 11}]
        result = self.engine.evaluate(detections, risk_score=90, risk_level="critical")
        assert result["should_block"] is True

    def test_rules_count(self):
        assert len(self.engine.rules) > 0


class TestRegexDetector:
    """Test the regex pattern detector."""

    def setup_method(self):
        from workers.text_worker.regex_detector import RegexDetector
        self.detector = RegexDetector()

    def test_dob_pattern(self):
        results = self.detector.detect("Patient DOB 01/15/1980")
        dob_found = any(d["entity_type"] == "DATE_OF_BIRTH" for d in results)
        assert dob_found, f"Expected DATE_OF_BIRTH but got: {[d['entity_type'] for d in results]}"

    def test_no_false_positives_on_clean(self):
        results = self.detector.detect("The weather is sunny today.")
        assert len(results) == 0

    def test_loaded_entities(self):
        entities = self.detector.get_loaded_entities()
        assert len(entities) > 0


class TestRequestInterceptor:
    """Test the request interceptor."""

    def setup_method(self):
        from gateway.request_interceptor import RequestInterceptor
        self.interceptor = RequestInterceptor()

    def test_valid_text(self):
        result = self.interceptor.validate_text_request("Hello world")
        assert result["valid"] is True

    def test_empty_text(self):
        result = self.interceptor.validate_text_request("")
        assert result["valid"] is False

    def test_oversized_text(self):
        result = self.interceptor.validate_text_request("x" * 2_000_000)
        assert result["valid"] is False

    def test_rate_limiting(self):
        for i in range(5):
            allowed, info = self.interceptor.check_rate_limit("192.168.1.1")
            assert allowed is True
        assert info["remaining"] >= 0
