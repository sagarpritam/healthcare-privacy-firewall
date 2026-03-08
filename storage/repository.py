"""
Healthcare Privacy Firewall — Data Repository
CRUD operations for scan logs, detections, alerts, and analytics queries.
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from sqlalchemy import select, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from storage.models import (
    ScanLog,
    DetectionResult,
    AlertRecord,
    PolicyAudit,
    ScanType,
    RiskLevel,
    AlertStatus,
    MaskingAction,
)


class ScanRepository:
    """Repository for scan log operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_scan_log(
        self,
        scan_type: ScanType,
        original_payload_hash: str,
        masked_payload: Optional[str] = None,
        risk_score: float = 0.0,
        risk_level: RiskLevel = RiskLevel.LOW,
        entities_detected: int = 0,
        policy_violated: bool = False,
        processing_time_ms: Optional[float] = None,
        source_ip: Optional[str] = None,
        endpoint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ScanLog:
        scan_log = ScanLog(
            id=uuid.uuid4(),
            scan_type=scan_type,
            source_ip=source_ip,
            endpoint=endpoint,
            original_payload_hash=original_payload_hash,
            masked_payload=masked_payload,
            risk_score=risk_score,
            risk_level=risk_level,
            entities_detected=entities_detected,
            policy_violated=policy_violated,
            processing_time_ms=processing_time_ms,
            metadata=metadata,
            created_at=datetime.utcnow(),
        )
        self.session.add(scan_log)
        await self.session.flush()
        return scan_log

    async def add_detection(
        self,
        scan_log_id: uuid.UUID,
        entity_type: str,
        confidence_score: float,
        masking_action: MaskingAction = MaskingAction.REDACT,
        original_text: Optional[str] = None,
        masked_text: Optional[str] = None,
        start_position: Optional[int] = None,
        end_position: Optional[int] = None,
        detection_engine: str = "presidio",
    ) -> DetectionResult:
        detection = DetectionResult(
            id=uuid.uuid4(),
            scan_log_id=scan_log_id,
            entity_type=entity_type,
            original_text=original_text,
            masked_text=masked_text,
            confidence_score=confidence_score,
            start_position=start_position,
            end_position=end_position,
            masking_action=masking_action,
            detection_engine=detection_engine,
            created_at=datetime.utcnow(),
        )
        self.session.add(detection)
        await self.session.flush()
        return detection

    async def add_alert(
        self,
        scan_log_id: uuid.UUID,
        alert_type: str,
        severity: RiskLevel,
        message: str,
        channel: str = "slack",
    ) -> AlertRecord:
        alert = AlertRecord(
            id=uuid.uuid4(),
            scan_log_id=scan_log_id,
            alert_type=alert_type,
            severity=severity,
            message=message,
            channel=channel,
            status=AlertStatus.PENDING,
            created_at=datetime.utcnow(),
        )
        self.session.add(alert)
        await self.session.flush()
        return alert

    async def add_policy_audit(
        self,
        scan_log_id: uuid.UUID,
        policy_name: str,
        evaluation_result: str,
        policy_version: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> PolicyAudit:
        audit = PolicyAudit(
            id=uuid.uuid4(),
            scan_log_id=scan_log_id,
            policy_name=policy_name,
            policy_version=policy_version,
            evaluation_result=evaluation_result,
            details=details,
            created_at=datetime.utcnow(),
        )
        self.session.add(audit)
        await self.session.flush()
        return audit

    async def get_scan_log(self, scan_id: uuid.UUID) -> Optional[ScanLog]:
        result = await self.session.execute(
            select(ScanLog).where(ScanLog.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def get_recent_scans(
        self, limit: int = 50, offset: int = 0
    ) -> List[ScanLog]:
        result = await self.session.execute(
            select(ScanLog)
            .order_by(desc(ScanLog.created_at))
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def get_scan_detections(
        self, scan_log_id: uuid.UUID
    ) -> List[DetectionResult]:
        result = await self.session.execute(
            select(DetectionResult)
            .where(DetectionResult.scan_log_id == scan_log_id)
            .order_by(DetectionResult.start_position)
        )
        return list(result.scalars().all())

    async def update_alert_status(
        self,
        alert_id: uuid.UUID,
        status: AlertStatus,
        response_data: Optional[Dict[str, Any]] = None,
    ):
        result = await self.session.execute(
            select(AlertRecord).where(AlertRecord.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        if alert:
            alert.status = status
            alert.response_data = response_data
            if status == AlertStatus.SENT:
                alert.sent_at = datetime.utcnow()
            await self.session.flush()

    async def get_pending_alerts(self) -> List[AlertRecord]:
        result = await self.session.execute(
            select(AlertRecord)
            .where(AlertRecord.status == AlertStatus.PENDING)
            .order_by(AlertRecord.created_at)
        )
        return list(result.scalars().all())


class AnalyticsRepository:
    """Repository for analytics queries."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_scan_stats(self, days: int = 30) -> Dict[str, Any]:
        since = datetime.utcnow() - timedelta(days=days)

        total_result = await self.session.execute(
            select(func.count(ScanLog.id)).where(ScanLog.created_at >= since)
        )
        total_scans = total_result.scalar() or 0

        by_type = await self.session.execute(
            select(ScanLog.scan_type, func.count(ScanLog.id))
            .where(ScanLog.created_at >= since)
            .group_by(ScanLog.scan_type)
        )

        by_risk = await self.session.execute(
            select(ScanLog.risk_level, func.count(ScanLog.id))
            .where(ScanLog.created_at >= since)
            .group_by(ScanLog.risk_level)
        )

        avg_risk = await self.session.execute(
            select(func.avg(ScanLog.risk_score)).where(ScanLog.created_at >= since)
        )

        total_entities = await self.session.execute(
            select(func.count(DetectionResult.id))
            .join(ScanLog, DetectionResult.scan_log_id == ScanLog.id)
            .where(ScanLog.created_at >= since)
        )

        top_entities = await self.session.execute(
            select(DetectionResult.entity_type, func.count(DetectionResult.id))
            .join(ScanLog, DetectionResult.scan_log_id == ScanLog.id)
            .where(ScanLog.created_at >= since)
            .group_by(DetectionResult.entity_type)
            .order_by(func.count(DetectionResult.id).desc())
            .limit(10)
        )

        return {
            "period_days": days,
            "total_scans": total_scans,
            "scans_by_type": {row[0]: row[1] for row in by_type.all()},
            "scans_by_risk_level": {row[0]: row[1] for row in by_risk.all()},
            "average_risk_score": round(float(avg_risk.scalar() or 0), 2),
            "total_entities_detected": total_entities.scalar() or 0,
            "top_entity_types": {row[0]: row[1] for row in top_entities.all()},
        }

    async def get_daily_scan_counts(self, days: int = 30) -> List[Dict[str, Any]]:
        since = datetime.utcnow() - timedelta(days=days)
        result = await self.session.execute(
            select(
                func.date_trunc("day", ScanLog.created_at).label("day"),
                func.count(ScanLog.id),
                func.avg(ScanLog.risk_score),
            )
            .where(ScanLog.created_at >= since)
            .group_by("day")
            .order_by("day")
        )
        return [
            {
                "date": row[0].isoformat() if row[0] else None,
                "count": row[1],
                "avg_risk_score": round(float(row[2] or 0), 2),
            }
            for row in result.all()
        ]
