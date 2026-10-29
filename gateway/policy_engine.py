"""
Policy Configuration and Evaluation Engine.

Evaluates detector findings against configured policies, enforces strict
rule precedence (BLOCK > REDACT > WARN > ALLOW), calculates standardized risk scores,
and generates structured explanations.
"""

from __future__ import annotations
import json
import os
from typing import List, Dict, Any, Tuple
from gateway.models import (
    PolicyRule,
    DetectorFinding,
    EnforcementAction,
    SeverityLevel,
    ThreatCategory,
)


class PolicyEngine:
    """
    Manages security policy configuration and computes enforcement decisions.
    """

    def __init__(self, config_path: str = "config/policies.json"):
        self.config_path = config_path
        self.policies: List[PolicyRule] = []
        self.load_policies()

    def load_policies(self) -> List[PolicyRule]:
        if not os.path.exists(self.config_path):
            self.policies = self._get_fallback_default_policies()
            return self.policies

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                rules_data = data.get("policies", [])
                self.policies = [PolicyRule.from_dict(r) for r in rules_data]
        except Exception as e:
            # Fallback to defaults to prevent silent failure
            self.policies = self._get_fallback_default_policies()

        return self.policies

    def save_policies(self, policies: List[PolicyRule]) -> bool:
        """
        Validates and saves the updated policy configuration.
        """
        self.validate_policies(policies)
        self.policies = policies
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            payload = {
                "version": "1.0.0",
                "policies": [p.to_dict() for p in policies],
            }
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            return True
        except Exception:
            return False

    @staticmethod
    def validate_policies(policies: List[PolicyRule]) -> None:
        """
        Ensures rule IDs are unique, actions are valid, and patterns are valid regex.
        Raises ValueError if invalid.
        """
        import re

        seen_ids = set()
        for p in policies:
            if not p.id or not p.name:
                raise ValueError(f"Policy missing id or name: {p}")
            if p.id in seen_ids:
                raise ValueError(f"Duplicate policy rule ID detected: {p.id}")
            seen_ids.add(p.id)

            if p.action not in EnforcementAction:
                raise ValueError(f"Invalid enforcement action '{p.action}' in rule {p.id}")

            for pat in p.patterns:
                try:
                    re.compile(pat)
                except re.error as err:
                    raise ValueError(f"Invalid regex pattern '{pat}' in rule {p.id}: {err}")

    def evaluate(self, findings: List[DetectorFinding]) -> Tuple[EnforcementAction, int, SeverityLevel, str]:
        """
        Evaluates findings against active policies and determines:
        1. Final Decision: BLOCK > REDACT > WARN > ALLOW
        2. Risk Score: 0 to 100
        3. Risk Level: LOW, MEDIUM, HIGH, CRITICAL
        4. Human-readable decision reason
        """
        if not findings:
            return EnforcementAction.ALLOW, 0, SeverityLevel.LOW, "Input inspected. No security policy violations or sensitive entities detected."

        # Filter findings to only enabled rules
        enabled_rule_ids = {p.id for p in self.policies if p.enabled}
        active_findings = [f for f in findings if f.rule_id in enabled_rule_ids]

        if not active_findings:
            return EnforcementAction.ALLOW, 0, SeverityLevel.LOW, "Findings occurred only on disabled policies. Permitted under current active configuration."

        # 1. Determine Final Decision based on Precedence
        # Rule precedence: BLOCK overrides everything. REDACT follows. Then WARN. Default is ALLOW.
        has_block = any(f.action == EnforcementAction.BLOCK for f in active_findings)
        has_redact = any(f.action == EnforcementAction.REDACT for f in active_findings)
        has_warn = any(f.action == EnforcementAction.WARN for f in active_findings)

        if has_block:
            final_decision = EnforcementAction.BLOCK
            blocking_rules = [f.rule_name for f in active_findings if f.action == EnforcementAction.BLOCK]
            reason = f"BLOCKED: High-risk security policy violation triggered by: {', '.join(set(blocking_rules))}."
        elif has_redact:
            final_decision = EnforcementAction.REDACT
            redact_rules = [f.rule_name for f in active_findings if f.action == EnforcementAction.REDACT]
            reason = f"REDACTED: Sensitive data detected. Replaced entities under policy: {', '.join(set(redact_rules))}."
        elif has_warn:
            final_decision = EnforcementAction.WARN
            warn_rules = [f.rule_name for f in active_findings if f.action == EnforcementAction.WARN]
            reason = f"WARNED: Suspicious pattern detected but not blocked: {', '.join(set(warn_rules))}."
        else:
            final_decision = EnforcementAction.ALLOW
            reason = "ALLOW: All findings permitted under current policy."

        # 2. Calculate Risk Score (0 - 100)
        # Weights: CRITICAL=40, HIGH=25, MEDIUM=15, LOW=5
        severity_weights = {
            SeverityLevel.CRITICAL: 40,
            SeverityLevel.HIGH: 25,
            SeverityLevel.MEDIUM: 15,
            SeverityLevel.LOW: 5,
        }

        raw_score = sum(severity_weights.get(f.severity, 5) for f in active_findings)

        # Compound bonus if multiple categories are targeted in the same prompt (+15 pts)
        categories = {f.category for f in active_findings}
        if len(categories) > 1:
            raw_score += 15

        risk_score = min(100, max(0, raw_score))

        # Risk Level categorisation
        if risk_score >= 70:
            risk_level = SeverityLevel.CRITICAL
        elif risk_score >= 40:
            risk_level = SeverityLevel.HIGH
        elif risk_score >= 20:
            risk_level = SeverityLevel.MEDIUM
        else:
            risk_level = SeverityLevel.LOW

        return final_decision, risk_score, risk_level, reason

    def _get_fallback_default_policies(self) -> List[PolicyRule]:
        return [
            PolicyRule(
                id="PI-001",
                name="Direct Instruction Override",
                description="Detects attempts to override system instructions.",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=SeverityLevel.CRITICAL,
                action=EnforcementAction.BLOCK,
                enabled=True,
                patterns=[r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)"],
            ),
            PolicyRule(
                id="SD-001",
                name="Email Address Exposure",
                description="Detects plain email addresses.",
                category=ThreatCategory.SENSITIVE_DATA,
                severity=SeverityLevel.LOW,
                action=EnforcementAction.REDACT,
                enabled=True,
                patterns=[r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"],
            ),
        ]
