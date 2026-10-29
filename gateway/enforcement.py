"""
Inspection and Enforcement Coordinator.

Glues input validation, normalization, detector execution, policy evaluation,
redaction, and persistent audit recording into an end-to-end security pipeline.
Guarantees that blocked inputs are rejected prior to any downstream AI processing.
"""

from __future__ import annotations
import time
import uuid
import datetime
from typing import Optional
from gateway.models import (
    InspectionResult,
    EnforcementAction,
    SeverityLevel,
    DetectorFinding,
)
from gateway.detectors import SecurityDetectorEngine, normalize_text
from gateway.policy_engine import PolicyEngine
from gateway.redaction import RedactionEngine
from gateway.audit import AuditLogger


class EnforcementGateway:
    """
    Core AI Policy Enforcement Gateway facade.
    """

    def __init__(
        self,
        config_path: str = "config/policies.json",
        db_path: str = "data/audit_history.db",
    ):
        self.policy_engine = PolicyEngine(config_path=config_path)
        self.detector_engine = SecurityDetectorEngine(self.policy_engine.policies)
        self.audit_logger = AuditLogger(db_path=db_path)

    def reload_policies(self) -> None:
        """
        Reloads policy configuration from disk and refreshes detector state.
        """
        self.policy_engine.load_policies()
        self.detector_engine.update_policies(self.policy_engine.policies)

    def inspect_and_enforce(self, input_text: str, record_audit: bool = True) -> InspectionResult:
        """
        Executes complete 10-step inspection workflow on untrusted input text.
        """
        start_time = time.perf_counter()
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Step 1 & 2: Input Validation
        if not isinstance(input_text, str):
            input_text = str(input_text or "")

        # Step 3: Normalization
        normalized = normalize_text(input_text)

        # Step 4 & 5: Run Detectors & Collect Findings
        findings = self.detector_engine.inspect(normalized)

        # Step 6 & 7: Policy Evaluation & Risk Scoring
        decision, risk_score, risk_level, reason = self.policy_engine.evaluate(findings)

        # Step 8: Apply Enforcement Actions (Redaction / Blocking)
        redacted_output: Optional[str] = None
        forwarded_to_model = False

        if decision == EnforcementAction.BLOCK:
            # Under BLOCK decision: Never forward to downstream model; do not perform partial redaction
            redacted_output = None
            forwarded_to_model = False
        elif decision == EnforcementAction.REDACT:
            redacted_text, _ = RedactionEngine.redact(input_text, findings)
            redacted_output = redacted_text
            forwarded_to_model = True
        elif decision in (EnforcementAction.ALLOW, EnforcementAction.WARN):
            redacted_output = input_text
            forwarded_to_model = True

        execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        triggered_rules = list(dict.fromkeys(f.rule_id for f in findings))

        result = InspectionResult(
            request_id=request_id,
            timestamp=timestamp,
            raw_input=input_text,
            normalized_input=normalized,
            final_decision=decision,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            triggered_rules=triggered_rules,
            redacted_output=redacted_output,
            forwarded_to_model=forwarded_to_model,
            execution_time_ms=execution_time_ms,
            decision_reason=reason,
        )

        # Step 9: Persistent Audit Logging
        if record_audit:
            self.audit_logger.record_inspection(result)

        return result
