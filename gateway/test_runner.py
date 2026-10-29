"""
Security Test Suite Runner.

Executes benchmark test cases against the enforcement gateway, computes
test pass/fail status, accuracy, precision, false positive rates, and
produces detailed analytical summaries for the Security Test Lab.
"""

from __future__ import annotations
import json
import os
from typing import List, Dict, Any
from gateway.enforcement import EnforcementGateway
from gateway.models import EnforcementAction


class SecurityTestRunner:
    """
    Executes benchmark test fixtures from data/sample_cases.json.
    """

    def __init__(self, gateway: EnforcementGateway, test_cases_path: str = "data/sample_cases.json"):
        self.gateway = gateway
        self.test_cases_path = test_cases_path

    def load_test_cases(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.test_cases_path):
            return []
        try:
            with open(self.test_cases_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def run_suite(self) -> Dict[str, Any]:
        """
        Executes all test cases and returns summary statistics and case-by-case results.
        """
        cases = self.load_test_cases()
        results: List[Dict[str, Any]] = []

        passed_count = 0
        failed_count = 0
        false_positives = 0
        false_negatives = 0

        for case in cases:
            input_text = case.get("input", "")
            expected_decision = case.get("expected_decision", "ALLOW")
            expected_rules = set(case.get("expected_rules", []))
            category = case.get("category", "BENIGN")

            # Run inspection (skip audit recording during test suite to avoid polluting operational metrics)
            inspection = self.gateway.inspect_and_enforce(input_text, record_audit=False)

            actual_decision = inspection.final_decision.value
            actual_rules = set(inspection.triggered_rules)

            # Decision match
            decision_match = (actual_decision == expected_decision)

            # Rule match: for malicious/sensitive, at least one expected rule must be present
            if expected_rules:
                rules_match = bool(expected_rules.intersection(actual_rules))
            else:
                rules_match = len(actual_rules) == 0

            passed = decision_match and rules_match

            # False positive: Benign input mistakenly flagged as WARN/REDACT/BLOCK
            is_false_pos = (category == "BENIGN" and actual_decision != "ALLOW")
            # False negative: Malicious/Sensitive input marked as ALLOW
            is_false_neg = (category != "BENIGN" and actual_decision == "ALLOW")

            if is_false_pos:
                false_positives += 1
            if is_false_neg:
                false_negatives += 1

            if passed:
                passed_count += 1
            else:
                failed_count += 1

            results.append({
                "case_id": case.get("id"),
                "name": case.get("name"),
                "category": category,
                "input_snippet": input_text[:75] + ("..." if len(input_text) > 75 else ""),
                "expected_decision": expected_decision,
                "actual_decision": actual_decision,
                "expected_rules": list(expected_rules),
                "actual_rules": list(actual_rules),
                "risk_score": inspection.risk_score,
                "passed": passed,
                "execution_time_ms": inspection.execution_time_ms,
                "explanation": inspection.decision_reason,
            })

        total = len(cases)
        accuracy = round((passed_count / total * 100) if total > 0 else 0, 1)

        return {
            "total_cases": total,
            "passed": passed_count,
            "failed": failed_count,
            "accuracy_percent": accuracy,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "results": results,
        }
