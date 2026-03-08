"""
Healthcare Privacy Firewall — Policy Engine
Evaluates scan results against configurable compliance policies.
"""

import os
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime

import yaml

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent


class PolicyRule:
    """A single policy rule for evaluation."""

    def __init__(
        self,
        name: str,
        description: str = "",
        condition: str = "always",
        entity_types: Optional[List[str]] = None,
        max_risk_score: Optional[float] = None,
        max_entity_count: Optional[int] = None,
        required_masking: Optional[str] = None,
        action: str = "warn",
    ):
        self.name = name
        self.description = description
        self.condition = condition
        self.entity_types = entity_types or []
        self.max_risk_score = max_risk_score
        self.max_entity_count = max_entity_count
        self.required_masking = required_masking
        self.action = action  # warn, block, alert, log


class PolicyEngine:
    """
    Evaluates scan results against a set of compliance policies.
    Supports HIPAA, PCI-DSS, and custom organizational policies.
    """

    def __init__(self, policies_path: Optional[str] = None):
        self.policies: Dict[str, Any] = {}
        self.rules: List[PolicyRule] = []
        self._load_policies(policies_path)
        self._build_rules()

    def _load_policies(self, policies_path: Optional[str] = None):
        """Load policy configuration from YAML."""
        path = Path(policies_path) if policies_path else BASE_DIR / "config" / "policies.yaml"

        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                self.policies = yaml.safe_load(f) or {}
            logger.info(f"Loaded policies from {path}")
        else:
            logger.warning(f"Policy file not found: {path}, using defaults")
            self.policies = {}

    def _build_rules(self):
        """Build evaluation rules from policy configuration."""
        # HIPAA Rule: No unmasked PHI in responses
        self.rules.append(PolicyRule(
            name="HIPAA_PHI_Protection",
            description="Ensure all PHI entities are properly masked per HIPAA requirements",
            entity_types=[
                "MEDICAL_RECORD_NUMBER", "NPI_NUMBER", "DATE_OF_BIRTH",
                "HEALTH_PLAN_ID", "US_SSN", "PERSON",
            ],
            required_masking="redact",
            action="block",
        ))

        # PCI-DSS Rule: Credit card data must be masked
        self.rules.append(PolicyRule(
            name="PCI_DSS_Card_Protection",
            description="Credit card numbers must be hashed or redacted",
            entity_types=["CREDIT_CARD", "IBAN_CODE", "US_BANK_NUMBER"],
            required_masking="hash",
            action="block",
        ))

        # Credential Leak Rule
        self.rules.append(PolicyRule(
            name="Credential_Leak_Prevention",
            description="Prevent credential exposure in API responses",
            entity_types=["API_KEY", "PASSWORD", "AWS_CREDENTIALS", "JWT_TOKEN", "PRIVATE_KEY", "DATABASE_URL"],
            action="alert",
        ))

        # High Risk Threshold Rule
        risk_thresholds = self.policies.get("risk_thresholds", {})
        critical_threshold = risk_thresholds.get("critical", 85.0)
        self.rules.append(PolicyRule(
            name="Critical_Risk_Threshold",
            description=f"Block payloads with risk score >= {critical_threshold}",
            max_risk_score=critical_threshold,
            action="block",
        ))

        # Volume Rule
        self.rules.append(PolicyRule(
            name="Excessive_PII_Volume",
            description="Alert when more than 10 PII entities detected in single payload",
            max_entity_count=10,
            action="alert",
        ))

        # Entity policies from config
        for entity_type, policy in self.policies.get("entity_policies", {}).items():
            if policy.get("alert", False):
                self.rules.append(PolicyRule(
                    name=f"Alert_On_{entity_type}",
                    description=f"Alert when {entity_type} is detected",
                    entity_types=[entity_type],
                    action="alert",
                ))

    def evaluate(
        self,
        detections: List[Dict[str, Any]],
        risk_score: float,
        risk_level: str,
        masking_applied: bool = True,
    ) -> Dict[str, Any]:
        """
        Evaluate scan results against all policy rules.

        Returns evaluation summary with pass/fail/warn results and actions.
        """
        results = []
        violations = []
        warnings = []
        actions = set()
        overall_result = "pass"

        detected_entity_types = {d.get("entity_type") for d in detections}
        entity_count = len(detections)

        for rule in self.rules:
            eval_result = self._evaluate_rule(
                rule, detected_entity_types, entity_count, risk_score, masking_applied
            )
            results.append(eval_result)

            if eval_result["result"] == "fail":
                overall_result = "fail"
                violations.append(eval_result)
                actions.add(eval_result["action"])
            elif eval_result["result"] == "warn":
                if overall_result != "fail":
                    overall_result = "warn"
                warnings.append(eval_result)
                actions.add(eval_result["action"])

        return {
            "overall_result": overall_result,
            "evaluated_at": datetime.utcnow().isoformat(),
            "total_rules": len(self.rules),
            "violations": len(violations),
            "warnings": len(warnings),
            "actions": list(actions),
            "should_block": "block" in actions,
            "should_alert": "alert" in actions or "block" in actions,
            "rule_results": results,
            "violation_details": violations,
            "warning_details": warnings,
        }

    def _evaluate_rule(
        self,
        rule: PolicyRule,
        detected_types: set,
        entity_count: int,
        risk_score: float,
        masking_applied: bool,
    ) -> Dict[str, Any]:
        """Evaluate a single policy rule."""
        result = {
            "rule_name": rule.name,
            "description": rule.description,
            "action": rule.action,
            "result": "pass",
            "details": "",
        }

        # Check entity type matches
        if rule.entity_types:
            matching = detected_types & set(rule.entity_types)
            if matching:
                if rule.required_masking and not masking_applied:
                    result["result"] = "fail"
                    result["details"] = (
                        f"Entities {matching} require {rule.required_masking} masking"
                    )
                elif rule.action == "alert":
                    result["result"] = "warn"
                    result["details"] = f"Sensitive entities detected: {matching}"

        # Check risk score threshold
        if rule.max_risk_score is not None and risk_score >= rule.max_risk_score:
            result["result"] = "fail"
            result["details"] = (
                f"Risk score {risk_score} exceeds threshold {rule.max_risk_score}"
            )

        # Check entity count threshold
        if rule.max_entity_count is not None and entity_count > rule.max_entity_count:
            if result["result"] != "fail":
                result["result"] = "warn"
            result["details"] = (
                f"Entity count {entity_count} exceeds threshold {rule.max_entity_count}"
            )

        return result

    def get_masking_action(self, entity_type: str) -> str:
        """Get the configured masking action for an entity type."""
        entity_policies = self.policies.get("entity_policies", {})
        if entity_type in entity_policies:
            return entity_policies[entity_type].get("action", "redact")
        return "redact"

    def get_risk_weight(self, entity_type: str) -> int:
        """Get the configured risk weight for an entity type."""
        entity_policies = self.policies.get("entity_policies", {})
        if entity_type in entity_policies:
            return entity_policies[entity_type].get("risk_weight", 10)
        return 10
