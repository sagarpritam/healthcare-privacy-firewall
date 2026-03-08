"""
Healthcare Privacy Firewall — Presidio NLP Detection Engine
Uses Microsoft Presidio with spaCy NLP for entity recognition.
Gracefully degrades if Presidio/spaCy are not installed.
"""

import os
import logging
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

# Check if Presidio is available
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerResult, PatternRecognizer, Pattern
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    HAS_PRESIDIO = True
except ImportError:
    HAS_PRESIDIO = False
    logger.warning("Presidio not installed — NLP-based detection disabled")

SPACY_MODEL = os.getenv("SPACY_MODEL", "en_core_web_sm")
SCORE_THRESHOLD = float(os.getenv("PRESIDIO_SCORE_THRESHOLD", "0.5"))

DEFAULT_ENTITIES = [
    "PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "US_SSN",
    "CREDIT_CARD", "DATE_TIME", "IP_ADDRESS", "US_DRIVER_LICENSE",
    "LOCATION", "IBAN_CODE", "US_BANK_NUMBER", "US_PASSPORT",
]


class PresidioEngine:
    """Wrapper around Microsoft Presidio Analyzer for PHI/PII detection."""

    def __init__(
        self,
        spacy_model: Optional[str] = None,
        score_threshold: Optional[float] = None,
        entities: Optional[List[str]] = None,
    ):
        self.spacy_model = spacy_model or SPACY_MODEL
        self.score_threshold = score_threshold or SCORE_THRESHOLD
        self.entities = entities or DEFAULT_ENTITIES
        self._analyzer = None
        self._available = HAS_PRESIDIO

    def _initialize(self):
        """Lazy-initialize the Presidio analyzer with spaCy NLP."""
        if not self._available:
            logger.warning("Presidio not available — skipping initialization")
            return None

        if self._analyzer is not None:
            return self._analyzer

        logger.info(f"Initializing Presidio engine with spaCy model: {self.spacy_model}")

        try:
            nlp_config = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": self.spacy_model}],
            }
            nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()
            self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
            self._register_healthcare_recognizers()
            logger.info("Presidio engine initialized successfully")
        except Exception as e:
            logger.error(f"Presidio initialization failed: {e}")
            self._available = False
            return None

        return self._analyzer

    def _register_healthcare_recognizers(self):
        """Register custom recognizers for healthcare-specific entities."""
        if not self._analyzer or not HAS_PRESIDIO:
            return

        mrn_recognizer = PatternRecognizer(
            supported_entity="MEDICAL_RECORD_NUMBER",
            name="MRN Recognizer",
            patterns=[
                Pattern(name="mrn_pattern", regex=r"\b(?:MRN|Medical Record (?:No|Number|#))[\s:]*([A-Z0-9]{6,12})\b", score=0.85),
                Pattern(name="mrn_code_pattern", regex=r"\b[A-Z]{2,3}-\d{6,10}\b", score=0.6),
            ],
            context=["medical record", "MRN", "patient id", "chart number"],
        )

        npi_recognizer = PatternRecognizer(
            supported_entity="NPI_NUMBER",
            name="NPI Recognizer",
            patterns=[
                Pattern(name="npi_explicit", regex=r"\b(?:NPI)[\s:#]*(\d{10})\b", score=0.9),
                Pattern(name="npi_number", regex=r"\b(1[0-9]{9})\b", score=0.4),
            ],
            context=["NPI", "national provider", "provider identifier"],
        )

        icd_recognizer = PatternRecognizer(
            supported_entity="ICD_CODE",
            name="ICD-10 Recognizer",
            patterns=[
                Pattern(name="icd_explicit", regex=r"\b(?:ICD[-\s]?10)[\s:]*([A-Z]\d{2}(?:\.\d{1,4})?)\b", score=0.9),
                Pattern(name="icd_code", regex=r"\b([A-TV-Z]\d{2}\.\d{1,4})\b", score=0.6),
            ],
            context=["diagnosis", "ICD", "diagnostic code", "condition"],
        )

        dob_recognizer = PatternRecognizer(
            supported_entity="DATE_OF_BIRTH",
            name="DOB Recognizer",
            patterns=[
                Pattern(name="dob_explicit", regex=r"\b(?:DOB|Date of Birth|Birth Date|D\.O\.B\.)[\s:]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b", score=0.95),
            ],
            context=["date of birth", "DOB", "born", "birthday"],
        )

        custom_recognizers = [mrn_recognizer, npi_recognizer, icd_recognizer, dob_recognizer]
        for recognizer in custom_recognizers:
            self._analyzer.registry.add_recognizer(recognizer)

        logger.info(f"Registered {len(custom_recognizers)} custom healthcare recognizers")

    def analyze(
        self,
        text: str,
        entities: Optional[List[str]] = None,
        language: str = "en",
        score_threshold: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Analyze text for PII/PHI entities."""
        analyzer = self._initialize()
        if analyzer is None:
            return []

        threshold = score_threshold or self.score_threshold
        detect_entities = entities or self.entities + [
            "MEDICAL_RECORD_NUMBER", "NPI_NUMBER", "ICD_CODE", "DATE_OF_BIRTH",
        ]

        try:
            results = analyzer.analyze(
                text=text, entities=detect_entities,
                language=language, score_threshold=threshold,
            )
        except Exception as e:
            logger.error(f"Presidio analysis failed: {e}")
            return []

        detections = []
        for result in results:
            detections.append({
                "entity_type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "score": round(result.score, 4),
                "text": text[result.start:result.end],
                "detection_engine": "presidio",
                "recognizer": result.recognition_metadata.get("recognizer_name", "unknown")
                if result.recognition_metadata else "unknown",
            })

        detections.sort(key=lambda x: x["start"])
        logger.info(f"Presidio detected {len(detections)} entities in text ({len(text)} chars)")
        return detections

    def get_supported_entities(self) -> List[str]:
        """Return all supported entity types."""
        analyzer = self._initialize()
        if analyzer is None:
            return self.entities
        return analyzer.get_supported_entities()


_engine: Optional[PresidioEngine] = None


def get_presidio_engine() -> PresidioEngine:
    """Get or create the global Presidio engine singleton."""
    global _engine
    if _engine is None:
        _engine = PresidioEngine()
    return _engine
