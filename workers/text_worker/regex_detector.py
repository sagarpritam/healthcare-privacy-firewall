"""
Healthcare Privacy Firewall — Regex-based PII/PHI Detector
Loads patterns from YAML configuration and detects entities using regex.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class RegexDetector:
    """Detects PII/PHI using configurable regex patterns from YAML files."""

    def __init__(self, pattern_files: Optional[List[str]] = None):
        self.patterns: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

        if pattern_files:
            for pf in pattern_files:
                self.load_patterns(pf)
        else:
            # Load default pattern files
            self.load_patterns(str(BASE_DIR / "detection" / "medical_patterns.yaml"))
            self.load_patterns(str(BASE_DIR / "detection" / "credential_patterns.yaml"))

    def load_patterns(self, filepath: str):
        """Load regex patterns from a YAML file."""
        path = Path(filepath)
        if not path.is_absolute():
            path = BASE_DIR / filepath

        if not path.exists():
            logger.warning(f"Pattern file not found: {path}")
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if data and "patterns" in data:
                for entity_name, entity_config in data["patterns"].items():
                    self.patterns[entity_name] = {
                        "description": entity_config.get("description", ""),
                        "patterns": [
                            {
                                "regex": re.compile(p["regex"], re.IGNORECASE | re.MULTILINE),
                                "score": p.get("score", 0.7),
                                "raw_regex": p["regex"],
                            }
                            for p in entity_config.get("patterns", [])
                        ],
                        "context_words": entity_config.get("context_words", []),
                        "validation": entity_config.get("validation"),
                    }
                logger.info(f"Loaded {len(data['patterns'])} patterns from {path.name}")
            self._loaded = True
        except Exception as e:
            logger.error(f"Failed to load patterns from {path}: {e}")

    def detect(
        self, text: str, entity_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Detect PII/PHI in text using regex patterns.

        Returns list of detected entities with type, position, score, and matched text.
        """
        if not self._loaded and not self.patterns:
            self.load_patterns(str(BASE_DIR / "detection" / "medical_patterns.yaml"))
            self.load_patterns(str(BASE_DIR / "detection" / "credential_patterns.yaml"))

        detections = []
        target_entities = entity_types or list(self.patterns.keys())

        for entity_name in target_entities:
            if entity_name not in self.patterns:
                continue

            entity_config = self.patterns[entity_name]

            for pattern_info in entity_config["patterns"]:
                compiled_regex = pattern_info["regex"]
                base_score = pattern_info["score"]

                try:
                    for match in compiled_regex.finditer(text):
                        # Check for context words to boost confidence
                        score = base_score
                        context_window = text[
                            max(0, match.start() - 100) : min(len(text), match.end() + 100)
                        ].lower()

                        context_words = entity_config.get("context_words", [])
                        context_hits = sum(
                            1 for word in context_words if word.lower() in context_window
                        )
                        if context_hits > 0:
                            score = min(1.0, score + (context_hits * 0.05))

                        # Validate if validation rule exists
                        if entity_config.get("validation") == "luhn":
                            matched_text = match.group(1) if match.lastindex else match.group()
                            if not self._luhn_check(matched_text):
                                continue

                        detections.append({
                            "entity_type": entity_name,
                            "start": match.start(),
                            "end": match.end(),
                            "score": round(score, 4),
                            "text": match.group(),
                            "detection_engine": "regex",
                            "pattern": pattern_info["raw_regex"],
                        })

                except re.error as e:
                    logger.error(f"Regex error for {entity_name}: {e}")

        # Remove overlapping detections (keep highest score)
        detections = self._resolve_overlaps(detections)

        logger.info(f"Regex detector found {len(detections)} entities in text ({len(text)} chars)")
        return detections

    def _resolve_overlaps(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove overlapping detections, keeping the one with highest score."""
        if not detections:
            return []

        # Sort by start position, then by score descending
        sorted_dets = sorted(detections, key=lambda x: (x["start"], -x["score"]))
        resolved = [sorted_dets[0]]

        for det in sorted_dets[1:]:
            last = resolved[-1]
            if det["start"] >= last["end"]:
                resolved.append(det)
            elif det["score"] > last["score"]:
                resolved[-1] = det

        return resolved

    @staticmethod
    def _luhn_check(number_str: str) -> bool:
        """Validate a number using the Luhn algorithm."""
        try:
            digits = [int(d) for d in number_str if d.isdigit()]
            if len(digits) < 2:
                return False
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            total = sum(odd_digits)
            for d in even_digits:
                total += sum(divmod(d * 2, 10))
            return total % 10 == 0
        except (ValueError, IndexError):
            return False

    def get_loaded_entities(self) -> List[str]:
        """Return list of entity types that have patterns loaded."""
        return list(self.patterns.keys())


# Module-level singleton
_detector: Optional[RegexDetector] = None


def get_regex_detector() -> RegexDetector:
    """Get or create the global regex detector singleton."""
    global _detector
    if _detector is None:
        _detector = RegexDetector()
    return _detector
