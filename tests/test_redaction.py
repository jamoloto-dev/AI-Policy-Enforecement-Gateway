"""
Tests for sensitive data redaction and audit masking.
"""

from gateway.models import (
    DetectorFinding,
    EnforcementAction,
    SeverityLevel,
    ThreatCategory,
)
from gateway.redaction import RedactionEngine


def test_single_email_redaction():
    text = "Please reach out to support@mycorp.com immediately."
    findings = [
        DetectorFinding(
            rule_id="SD-001",
            rule_name="Email Address Exposure",
            category=ThreatCategory.SENSITIVE_DATA,
            severity=SeverityLevel.LOW,
            action=EnforcementAction.REDACT,
            explanation="Found email",
            matched_snippet="support@mycorp.com",
            start_pos=20,
            end_pos=38,
        )
    ]
    redacted, count = RedactionEngine.redact(text, findings)
    assert count == 1
    assert redacted == "Please reach out to [REDACTED_EMAIL_1] immediately."


def test_multiple_redactions_with_stable_offsets():
    text = "Send to bob@test.com or call 0821234567 today."
    findings = [
        DetectorFinding(
            rule_id="SD-001",
            rule_name="Email Address Exposure",
            category=ThreatCategory.SENSITIVE_DATA,
            severity=SeverityLevel.LOW,
            action=EnforcementAction.REDACT,
            explanation="Email",
            matched_snippet="bob@test.com",
            start_pos=8,
            end_pos=20,
        ),
        DetectorFinding(
            rule_id="SD-002",
            rule_name="Telephone Number Disclosure",
            category=ThreatCategory.SENSITIVE_DATA,
            severity=SeverityLevel.LOW,
            action=EnforcementAction.REDACT,
            explanation="Phone",
            matched_snippet="0821234567",
            start_pos=29,
            end_pos=39,
        ),
    ]
    redacted, count = RedactionEngine.redact(text, findings)
    assert count == 2
    assert "[REDACTED_EMAIL_1]" in redacted
    assert "[REDACTED_PHONE_1]" in redacted
    assert "Send to [REDACTED_EMAIL_1] or call [REDACTED_PHONE_1] today." == redacted


def test_redaction_does_not_modify_unrelated_text():
    text = "A simple question about ancient history."
    redacted, count = RedactionEngine.redact(text, [])
    assert count == 0
    assert redacted == text


def test_mask_snippet_for_audit_removes_api_keys():
    raw_prompt = "My OpenAI secret is sk-abcd1234567890efghij and password='SuperSecret'."
    masked = RedactionEngine.mask_snippet_for_audit(raw_prompt)
    assert "sk-abcd1234567890efghij" not in masked
    assert "sk-***MASKED***" in masked
    assert "SuperSecret" not in masked
