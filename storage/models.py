"""
Healthcare Privacy Firewall — Database Models
SQLAlchemy ORM models for scan logs, detection results, alerts, and policy audits.
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Text,
    Float,
    Integer,
    Boolean,
    DateTime,
    JSON,
    ForeignKey,
    Index,
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from storage.db import Base
import enum


class ScanType(str, enum.Enum):
    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MaskingAction(str, enum.Enum):
    REDACT = "redact"
    HASH = "hash"
    PARTIAL_MASK = "partial_mask"


class AlertStatus(str, enum.Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    ACKNOWLEDGED = "acknowledged"


class ScanLog(Base):
    """Primary record of each scan request processed by the firewall."""
    __tablename__ = "scan_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_type = Column(SAEnum(ScanType), nullable=False, index=True)
    source_ip = Column(String(45), nullable=True)
    endpoint = Column(String(512), nullable=True)
    original_payload_hash = Column(String(64), nullable=False)
    masked_payload = Column(Text, nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(SAEnum(RiskLevel), nullable=False, default=RiskLevel.LOW)
    entities_detected = Column(Integer, nullable=False, default=0)
    policy_violated = Column(Boolean, nullable=False, default=False)
    processing_time_ms = Column(Float, nullable=True)
    metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    detections = relationship("DetectionResult", back_populates="scan_log", cascade="all, delete-orphan")
    alerts = relationship("AlertRecord", back_populates="scan_log", cascade="all, delete-orphan")
    policy_audits = relationship("PolicyAudit", back_populates="scan_log", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scan_logs_created", "created_at"),
        Index("idx_scan_logs_risk", "risk_level", "risk_score"),
    )


class DetectionResult(Base):
    """Individual PII/PHI entity detected within a scan."""
    __tablename__ = "detection_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_log_id = Column(UUID(as_uuid=True), ForeignKey("scan_logs.id", ondelete="CASCADE"), nullable=False)
    entity_type = Column(String(100), nullable=False, index=True)
    original_text = Column(Text, nullable=True)  # Only stored if audit mode is on
    masked_text = Column(Text, nullable=True)
    confidence_score = Column(Float, nullable=False)
    start_position = Column(Integer, nullable=True)
    end_position = Column(Integer, nullable=True)
    masking_action = Column(SAEnum(MaskingAction), nullable=False, default=MaskingAction.REDACT)
    detection_engine = Column(String(50), nullable=False, default="presidio")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    scan_log = relationship("ScanLog", back_populates="detections")

    __table_args__ = (
        Index("idx_detection_entity", "entity_type"),
        Index("idx_detection_scan", "scan_log_id"),
    )


class AlertRecord(Base):
    """Alert generated when risk thresholds are exceeded."""
    __tablename__ = "alert_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_log_id = Column(UUID(as_uuid=True), ForeignKey("scan_logs.id", ondelete="CASCADE"), nullable=False)
    alert_type = Column(String(50), nullable=False)
    severity = Column(SAEnum(RiskLevel), nullable=False)
    message = Column(Text, nullable=False)
    channel = Column(String(50), nullable=False, default="slack")
    status = Column(SAEnum(AlertStatus), nullable=False, default=AlertStatus.PENDING)
    response_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    sent_at = Column(DateTime, nullable=True)

    scan_log = relationship("ScanLog", back_populates="alerts")

    __table_args__ = (
        Index("idx_alert_status", "status"),
        Index("idx_alert_severity", "severity"),
    )


class PolicyAudit(Base):
    """Audit log for policy evaluations."""
    __tablename__ = "policy_audits"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_log_id = Column(UUID(as_uuid=True), ForeignKey("scan_logs.id", ondelete="CASCADE"), nullable=False)
    policy_name = Column(String(200), nullable=False)
    policy_version = Column(String(50), nullable=True)
    evaluation_result = Column(String(50), nullable=False)  # pass, fail, warn
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    scan_log = relationship("ScanLog", back_populates="policy_audits")

    __table_args__ = (
        Index("idx_policy_audit_scan", "scan_log_id"),
    )
