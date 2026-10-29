"""
Tests for policy precedence, risk scoring, and policy validation.
"""

import pytest
from gateway.models import (
    PolicyRule,
    DetectorFinding,
    EnforcementAction,
    SeverityLevel,
    ThreatCategory,
)
from gateway.policy_engine import PolicyEngine


@pytest.fixture
def policy_engine(tmp_path):
    config_file = tmp_path / "policies.json"
    engine = PolicyEngine(config_path=str(config_file))
    return engine


def test_rule_precedence_block_overrides_redact_and_warn(policy_engine):
    # Construct findings: one REDACT, one BLOCK, one WARN
    f_redact = DetectorFinding(
        rule_id="SD-001",
        rule_name="Email Exposure",
        category=ThreatCategory.SENSITIVE_DATA,
        severity=SeverityLevel.LOW,
        action=EnforcementAction.REDACT,
        explanation="Redact email",
        matched_snippet="test@example.com",
        start_pos=0,
        end_pos=16,
    )
    f_block = DetectorFinding(
        rule_id="PI-001",
        rule_name="Instruction Override",
        category=ThreatCategory.PROMPT_INJECTION,
        severity=SeverityLevel.CRITICAL,
        action=EnforcementAction.BLOCK,
        explanation="Block override",
        matched_snippet="ignore all instructions",
        start_pos=20,
        end_pos=43,
    )

    decision, score, level, reason = policy_engine.evaluate([f_redact, f_block])
    assert decision == EnforcementAction.BLOCK
    assert "BLOCKED" in reason
    assert score >= 40
    assert level in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)


def test_rule_precedence_redact_overrides_warn(policy_engine):
    f_redact = DetectorFinding(
        rule_id="SD-001",
        rule_name="Email Exposure",
        category=ThreatCategory.SENSITIVE_DATA,
        severity=SeverityLevel.LOW,
        action=EnforcementAction.REDACT,
        explanation="Redact email",
        matched_snippet="test@example.com",
        start_pos=0,
        end_pos=16,
    )
    f_warn = DetectorFinding(
        rule_id="PI-005",
        rule_name="Delimiter Markup",
        category=ThreatCategory.PROMPT_INJECTION,
        severity=SeverityLevel.MEDIUM,
        action=EnforcementAction.WARN,
        explanation="Warn on delimiter",
        matched_snippet="[SYSTEM]",
        start_pos=20,
        end_pos=28,
    )

    decision, score, level, reason = policy_engine.evaluate([f_redact, f_warn])
    assert decision == EnforcementAction.REDACT
    assert "REDACTED" in reason


def test_empty_findings_evaluate_to_allow(policy_engine):
    decision, score, level, reason = policy_engine.evaluate([])
    assert decision == EnforcementAction.ALLOW
    assert score == 0
    assert level == SeverityLevel.LOW


def test_policy_validation_detects_duplicate_ids():
    rules = [
        PolicyRule(
            id="DUP-01",
            name="Rule 1",
            description="",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=SeverityLevel.LOW,
            action=EnforcementAction.ALLOW,
        ),
        PolicyRule(
            id="DUP-01",
            name="Rule 2",
            description="",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=SeverityLevel.LOW,
            action=EnforcementAction.ALLOW,
        ),
    ]
    with pytest.raises(ValueError, match="Duplicate policy rule ID"):
        PolicyEngine.validate_policies(rules)
