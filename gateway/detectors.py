"""
Security Detection Engine.

Deterministic regex and heuristic detection rules for prompt injection,
sensitive data leakage (emails, phones, South African ID numbers with Luhn check),
cloud API keys, and credential exposures.
"""

from __future__ import annotations
import re
import unicodedata
from typing import List, Tuple, Optional
from gateway.models import (
    DetectorFinding,
    PolicyRule,
    ThreatCategory,
    SeverityLevel,
    EnforcementAction,
)


def validate_south_african_id(id_str: str) -> bool:
    """
    Validates a 13-digit South African ID number using structure and Luhn checksum.
    Format: YYMMDD GSSS C A Z
    - YYMMDD: Date of birth
    - GSSS: Gender (0000-4999 female, 5000-9999 male)
    - C: Citizenship (0 = SA citizen, 1 = permanent resident)
    - A: Usually 8
    - Z: Checksum digit calculated via Luhn algorithm
    """
    clean_id = re.sub(r"\D", "", id_str)
    if len(clean_id) != 13:
        return False

    # Basic date validation for month and day
    month = int(clean_id[2:4])
    day = int(clean_id[4:6])
    if month < 1 or month > 12 or day < 1 or day > 31:
        return False

    # Luhn checksum calculation
    total = 0
    reverse_digits = clean_id[::-1]
    for idx, char in enumerate(reverse_digits):
        digit = int(char)
        if idx % 2 == 1:
            doubled = digit * 2
            total += doubled if doubled < 10 else (doubled - 9)
        else:
            total += digit

    return total % 10 == 0


def normalize_text(text: str) -> str:
    """
    Normalizes input text for inspection:
    - Unicode NFKC normalization (resolves homoglyphs and compatibility characters)
    - Strips zero-width and control characters
    - Preserves standard newlines and case for downstream display
    """
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text)
    # Strip null bytes and non-printable control characters except whitespace
    normalized = "".join(ch for ch in normalized if ch == "\n" or ch == "\r" or ch == "\t" or unicodedata.category(ch)[0] != "C")
    return normalized


class SecurityDetectorEngine:
    """
    Executes all enabled deterministic detection rules against input text.
    """

    def __init__(self, policies: List[PolicyRule]):
        self.policies = {p.id: p for p in policies if p.enabled}

    def update_policies(self, policies: List[PolicyRule]):
        self.policies = {p.id: p for p in policies if p.enabled}

    def inspect(self, text: str) -> List[DetectorFinding]:
        findings: List[DetectorFinding] = []
        if not text or not text.strip():
            return findings

        # Check for input length threshold (basic DoS protection)
        if len(text) > 100_000:
            findings.append(
                DetectorFinding(
                    rule_id="SYS-001",
                    rule_name="Payload Size Limit Exceeded",
                    category=ThreatCategory.GUARDRAIL_BYPASS,
                    severity=SeverityLevel.CRITICAL,
                    action=EnforcementAction.BLOCK,
                    explanation="Input exceeds maximum allowed length of 100,000 characters.",
                    matched_snippet=text[:64] + "...",
                    start_pos=0,
                    end_pos=len(text),
                )
            )
            return findings

        normalized = normalize_text(text)

        # 1. Evaluate Prompt Injection & Delimiter Policies
        findings.extend(self._check_prompt_injection(normalized))

        # 2. Evaluate Sensitive Data Policies (Emails, Phones, SA ID)
        findings.extend(self._check_sensitive_data(normalized))

        # 3. Evaluate Credential & API Key Policies
        findings.extend(self._check_credentials(normalized))

        # Sort findings by start position
        findings.sort(key=lambda f: f.start_pos)
        return findings

    def _check_prompt_injection(self, text: str) -> List[DetectorFinding]:
        findings: List[DetectorFinding] = []

        pi_rules = ["PI-001", "PI-002", "PI-003", "PI-004", "PI-005", "PI-006"]
        for rule_id in pi_rules:
            policy = self.policies.get(rule_id)
            if not policy:
                continue

            for pattern in policy.patterns:
                try:
                    for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
                        snippet = match.group(0)
                        findings.append(
                            DetectorFinding(
                                rule_id=policy.id,
                                rule_name=policy.name,
                                category=policy.category,
                                severity=policy.severity,
                                action=policy.action,
                                explanation=f"Triggered by rule '{policy.name}': match on pattern '{snippet}'.",
                                matched_snippet=snippet,
                                start_pos=match.start(),
                                end_pos=match.end(),
                            )
                        )
                except re.error:
                    continue

        return findings

    def _check_sensitive_data(self, text: str) -> List[DetectorFinding]:
        findings: List[DetectorFinding] = []

        # SD-001: Email Address
        p_email = self.policies.get("SD-001")
        if p_email:
            for pattern in p_email.patterns:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    findings.append(
                        DetectorFinding(
                            rule_id=p_email.id,
                            rule_name=p_email.name,
                            category=p_email.category,
                            severity=p_email.severity,
                            action=p_email.action,
                            explanation=f"Detected sensitive email address: '{match.group(0)}'.",
                            matched_snippet=match.group(0),
                            start_pos=match.start(),
                            end_pos=match.end(),
                        )
                    )

        # SD-002: Phone Numbers
        p_phone = self.policies.get("SD-002")
        if p_phone:
            for pattern in p_phone.patterns:
                for match in re.finditer(pattern, text):
                    # Filter out short pure numbers or numbers that are part of words
                    val = match.group(0).strip()
                    # Exclude matches that are obviously not phone numbers (e.g. less than 7 digits)
                    digit_count = sum(c.isdigit() for c in val)
                    if 7 <= digit_count <= 15:
                        findings.append(
                            DetectorFinding(
                                rule_id=p_phone.id,
                                rule_name=p_phone.name,
                                category=p_phone.category,
                                severity=p_phone.severity,
                                action=p_phone.action,
                                explanation=f"Detected telephone number disclosure: '{val}'.",
                                matched_snippet=val,
                                start_pos=match.start(),
                                end_pos=match.end(),
                            )
                        )

        # SD-003: South African ID Number (Requires Luhn Check Validation)
        p_said = self.policies.get("SD-003")
        if p_said:
            for pattern in p_said.patterns:
                for match in re.finditer(pattern, text):
                    candidate = match.group(0)
                    if validate_south_african_id(candidate):
                        findings.append(
                            DetectorFinding(
                                rule_id=p_said.id,
                                rule_name=p_said.name,
                                category=p_said.category,
                                severity=p_said.severity,
                                action=p_said.action,
                                explanation=f"Detected 13-digit South African ID number validated by Luhn checksum.",
                                matched_snippet=candidate,
                                start_pos=match.start(),
                                end_pos=match.end(),
                                metadata={"id_prefix": candidate[:6]},
                            )
                        )

        return findings

    def _check_credentials(self, text: str) -> List[DetectorFinding]:
        findings: List[DetectorFinding] = []

        # SD-004: API Keys & Cloud Credentials
        p_keys = self.policies.get("SD-004")
        if p_keys:
            for pattern in p_keys.patterns:
                for match in re.finditer(pattern, text):
                    snippet = match.group(0)
                    findings.append(
                        DetectorFinding(
                            rule_id=p_keys.id,
                            rule_name=p_keys.name,
                            category=p_keys.category,
                            severity=p_keys.severity,
                            action=p_keys.action,
                            explanation=f"Detected API key or cloud token credential format.",
                            matched_snippet=snippet,
                            start_pos=match.start(),
                            end_pos=match.end(),
                        )
                    )

        # SD-005: Plaintext Password Assignment
        p_pw = self.policies.get("SD-005")
        if p_pw:
            for pattern in p_pw.patterns:
                for match in re.finditer(pattern, text):
                    snippet = match.group(0)
                    findings.append(
                        DetectorFinding(
                            rule_id=p_pw.id,
                            rule_name=p_pw.name,
                            category=p_pw.category,
                            severity=p_pw.severity,
                            action=p_pw.action,
                            explanation=f"Detected plaintext password assignment variable.",
                            matched_snippet=snippet,
                            start_pos=match.start(),
                            end_pos=match.end(),
                        )
                    )

        return findings
