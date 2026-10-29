"""
Domain models and schema definitions for the AI Policy Enforcement Gateway.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any
import datetime
import uuid


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EnforcementAction(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    SENSITIVE_DATA = "SENSITIVE_DATA"
    CREDENTIAL_EXPOSURE = "CREDENTIAL_EXPOSURE"
    GUARDRAIL_BYPASS = "GUARDRAIL_BYPASS"
    BENIGN = "BENIGN"


@dataclass
class DetectorFinding:
    rule_id: str
    rule_name: str
    category: ThreatCategory
    severity: SeverityLevel
    action: EnforcementAction
    explanation: str
    matched_snippet: str
    start_pos: int
    end_pos: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["action"] = self.action.value
        return d


@dataclass
class PolicyRule:
    id: str
    name: str
    description: str
    category: ThreatCategory
    severity: SeverityLevel
    action: EnforcementAction
    enabled: bool = True
    patterns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["action"] = self.action.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PolicyRule:
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            category=ThreatCategory(data["category"]),
            severity=SeverityLevel(data["severity"]),
            action=EnforcementAction(data["action"]),
            enabled=data.get("enabled", True),
            patterns=data.get("patterns", []),
        )


@dataclass
class InspectionResult:
    request_id: str
    timestamp: str
    raw_input: str
    normalized_input: str
    final_decision: EnforcementAction
    risk_score: int  # 0 to 100
    risk_level: SeverityLevel
    findings: List[DetectorFinding]
    triggered_rules: List[str]
    redacted_output: Optional[str]
    forwarded_to_model: bool
    execution_time_ms: float
    decision_reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "raw_input": self.raw_input,
            "normalized_input": self.normalized_input,
            "final_decision": self.final_decision.value,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "findings": [f.to_dict() for f in self.findings],
            "triggered_rules": self.triggered_rules,
            "redacted_output": self.redacted_output,
            "forwarded_to_model": self.forwarded_to_model,
            "execution_time_ms": self.execution_time_ms,
            "decision_reason": self.decision_reason,
        }


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    request_id: str
    decision: str
    risk_score: int
    risk_level: str
    triggered_rules: str  # Comma-separated or JSON
    categories: str
    input_length: int
    masked_snippet: str
    redacted_preview: Optional[str] = None
    execution_time_ms: float = 0.0

    @classmethod
    def from_inspection(cls, result: InspectionResult, masked_input: str) -> AuditEvent:
        return cls(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            timestamp=result.timestamp,
            request_id=result.request_id,
            decision=result.final_decision.value,
            risk_score=result.risk_score,
            risk_level=result.risk_level.value,
            triggered_rules=",".join(result.triggered_rules),
            categories=",".join(list({f.category.value for f in result.findings})),
            input_length=len(result.raw_input),
            masked_snippet=masked_input[:160],
            redacted_preview=(result.redacted_output[:160] if result.redacted_output else None),
            execution_time_ms=result.execution_time_ms,
        )
