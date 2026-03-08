"""
Healthcare Privacy Firewall — Text Masker
Applies masking strategies (redact, hash, partial) to detected PII/PHI entities.
"""

import hashlib
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_PLACEHOLDER = "[REDACTED]"
DEFAULT_HASH_SALT = "healthcare-firewall-salt-2024"
DEFAULT_MASK_CHAR = "*"
DEFAULT_VISIBLE_CHARS = 4


class TextMasker:
    """Masks detected PII/PHI entities in text using configurable strategies."""

    def __init__(
        self,
        default_action: str = "redact",
        placeholder: str = DEFAULT_PLACEHOLDER,
        hash_salt: str = DEFAULT_HASH_SALT,
        mask_char: str = DEFAULT_MASK_CHAR,
        visible_chars: int = DEFAULT_VISIBLE_CHARS,
        entity_policies: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.default_action = default_action
        self.placeholder = placeholder
        self.hash_salt = hash_salt
        self.mask_char = mask_char
        self.visible_chars = visible_chars
        self.entity_policies = entity_policies or {}

    def mask_text(
        self,
        text: str,
        detections: List[Dict[str, Any]],
        action_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Apply masking to all detected entities in text.

        Returns dict with masked_text, masking_details list, and entity_count.
        """
        if not detections:
            return {
                "masked_text": text,
                "masking_details": [],
                "entity_count": 0,
            }

        # Sort detections by start position (reverse for replacement)
        sorted_detections = sorted(detections, key=lambda x: x["start"], reverse=True)

        masked_text = text
        masking_details = []

        for det in sorted_detections:
            entity_type = det.get("entity_type", "UNKNOWN")
            original = det.get("text", masked_text[det["start"]:det["end"]])
            start = det["start"]
            end = det["end"]

            # Determine masking action
            action = action_override or self._get_action_for_entity(entity_type)

            # Apply masking
            masked_value = self._apply_mask(original, action, entity_type)

            # Replace in text
            masked_text = masked_text[:start] + masked_value + masked_text[end:]

            masking_details.append({
                "entity_type": entity_type,
                "original_length": len(original),
                "masked_value": masked_value,
                "action": action,
                "start": start,
                "end": end,
                "confidence": det.get("score", 0.0),
            })

        # Reverse to get chronological order
        masking_details.reverse()

        return {
            "masked_text": masked_text,
            "masking_details": masking_details,
            "entity_count": len(masking_details),
        }

    def _get_action_for_entity(self, entity_type: str) -> str:
        """Get the masking action for a specific entity type from policy."""
        if entity_type in self.entity_policies:
            return self.entity_policies[entity_type].get("action", self.default_action)
        return self.default_action

    def _apply_mask(self, value: str, action: str, entity_type: str) -> str:
        """Apply a specific masking strategy to a value."""
        if action == "redact":
            return f"[{entity_type}]"
        elif action == "hash":
            return self._hash_value(value)
        elif action == "partial_mask":
            return self._partial_mask(value)
        else:
            return self.placeholder

    def _hash_value(self, value: str) -> str:
        """Hash a value using SHA-256 with salt."""
        salted = f"{self.hash_salt}:{value}"
        hashed = hashlib.sha256(salted.encode("utf-8")).hexdigest()
        return f"[HASH:{hashed[:16]}]"

    def _partial_mask(self, value: str) -> str:
        """Partially mask a value, keeping the last N characters visible."""
        if len(value) <= self.visible_chars:
            return self.mask_char * len(value)
        masked_len = len(value) - self.visible_chars
        return self.mask_char * masked_len + value[-self.visible_chars:]

    def mask_single(self, value: str, entity_type: str = "UNKNOWN") -> str:
        """Mask a single value using the policy for its entity type."""
        action = self._get_action_for_entity(entity_type)
        return self._apply_mask(value, action, entity_type)


def create_masker_from_config(policies: Dict[str, Any]) -> TextMasker:
    """Create a TextMasker from a policy configuration dict."""
    masking_config = policies.get("masking_strategies", {})
    entity_policies = policies.get("entity_policies", {})

    default_strategy = masking_config.get("default", "redact")
    strategies = masking_config.get("strategies", {})

    redact_config = strategies.get("redact", {})
    hash_config = strategies.get("hash", {})
    partial_config = strategies.get("partial_mask", {})

    return TextMasker(
        default_action=default_strategy,
        placeholder=redact_config.get("placeholder", DEFAULT_PLACEHOLDER),
        hash_salt=hash_config.get("salt", DEFAULT_HASH_SALT),
        mask_char=partial_config.get("mask_char", DEFAULT_MASK_CHAR),
        visible_chars=partial_config.get("visible_chars", DEFAULT_VISIBLE_CHARS),
        entity_policies=entity_policies,
    )
