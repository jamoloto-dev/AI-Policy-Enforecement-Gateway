"""
Tests for persistent SQLite audit logger, querying, and export.
"""

import json
from gateway.models import (
    InspectionResult,
    EnforcementAction,
    SeverityLevel,
    DetectorFinding,
    ThreatCategory,
)
from gateway.audit import AuditLogger


def test_audit_logging_and_querying(tmp_path):
    db_file = str(tmp_path / "test_audit.db")
    logger = AuditLogger(db_path=db_file)

    res = InspectionResult(
        request_id="req_test_123",
        timestamp="2026-10-29T12:00:00Z",
        raw_input="Test prompt with user@example.com",
        normalized_input="Test prompt with user@example.com",
        final_decision=EnforcementAction.REDACT,
        risk_score=25,
        risk_level=SeverityLevel.MEDIUM,
        findings=[
            DetectorFinding(
                rule_id="SD-001",
                rule_name="Email Exposure",
                category=ThreatCategory.SENSITIVE_DATA,
                severity=SeverityLevel.LOW,
                action=EnforcementAction.REDACT,
                explanation="Email detected",
                matched_snippet="user@example.com",
                start_pos=17,
                end_pos=33,
            )
        ],
        triggered_rules=["SD-001"],
        redacted_output="Test prompt with [REDACTED_EMAIL_1]",
        forwarded_to_model=True,
        execution_time_ms=1.5,
        decision_reason="Redacted email",
    )

    event = logger.record_inspection(res)
    assert event is not None
    assert event.request_id == "req_test_123"

    # Query events
    events = logger.query_events(decision="REDACT")
    assert len(events) == 1
    assert events[0]["request_id"] == "req_test_123"
    assert events[0]["risk_score"] == 25


def test_audit_statistics(tmp_path):
    db_file = str(tmp_path / "test_stats.db")
    logger = AuditLogger(db_path=db_file)

    for decision, score in [(EnforcementAction.ALLOW, 0), (EnforcementAction.BLOCK, 80)]:
        res = InspectionResult(
            request_id=f"req_{decision.value}",
            timestamp="2026-10-29T12:00:00Z",
            raw_input="Input text",
            normalized_input="Input text",
            final_decision=decision,
            risk_score=score,
            risk_level=SeverityLevel.LOW if score == 0 else SeverityLevel.CRITICAL,
            findings=[],
            triggered_rules=[] if score == 0 else ["PI-001"],
            redacted_output="Input text" if decision == EnforcementAction.ALLOW else None,
            forwarded_to_model=(decision != EnforcementAction.BLOCK),
            execution_time_ms=1.0,
            decision_reason=f"Decided {decision.value}",
        )
        logger.record_inspection(res)

    stats = logger.get_statistics()
    assert stats["total_requests"] == 2
    assert stats["allowed"] == 1
    assert stats["blocked"] == 1
    assert stats["threat_detection_rate"] == 50.0


def test_audit_exports(tmp_path):
    db_file = str(tmp_path / "test_export.db")
    logger = AuditLogger(db_path=db_file)

    res = InspectionResult(
        request_id="req_export_1",
        timestamp="2026-10-29T12:00:00Z",
        raw_input="Export test",
        normalized_input="Export test",
        final_decision=EnforcementAction.ALLOW,
        risk_score=0,
        risk_level=SeverityLevel.LOW,
        findings=[],
        triggered_rules=[],
        redacted_output="Export test",
        forwarded_to_model=True,
        execution_time_ms=0.8,
        decision_reason="Allowed",
    )
    logger.record_inspection(res)

    json_export = logger.export_json()
    data = json.loads(json_export)
    assert len(data) == 1
    assert data[0]["request_id"] == "req_export_1"

    csv_export = logger.export_csv()
    assert "req_export_1" in csv_export
    assert "event_id,timestamp,request_id" in csv_export
