"""
Sensitive-Data Redaction Engine.

Replaces detected sensitive entities (emails, telephone numbers, South African IDs,
and configured sensitive tokens) with safe, deterministic token placeholders.
Preserves non-sensitive content and formatting.
"""

from __future__ import annotations
from typing import List, Tuple
from gateway.models import DetectorFinding, EnforcementAction


class RedactionEngine:
    """
    Applies deterministic token replacements for findings configured with REDACT action.
    """

    @staticmethod
    def redact(text: str, findings: List[DetectorFinding]) -> Tuple[str, int]:
        """
        Redacts all findings with action REDACT.
        Replaces text from back-to-front by index to maintain offset stability.
        Returns:
            (redacted_text, count_of_redactions)
        """
        redactable_findings = [f for f in findings if f.action == EnforcementAction.REDACT]
        if not redactable_findings:
            return text, 0

        # Sort reverse by start_pos to avoid index invalidation
        # If spans overlap, choose the longer span or deduplicate
        sorted_findings = sorted(redactable_findings, key=lambda f: (f.start_pos, -(f.end_pos - f.start_pos)))

        # Deduplicate overlapping spans
        clean_findings: List[DetectorFinding] = []
        last_end = -1
        for f in sorted_findings:
            if f.start_pos >= last_end:
                clean_findings.append(f)
                last_end = f.end_pos

        # Sort descending by start_pos for replacement
        clean_findings.sort(key=lambda f: f.start_pos, reverse=True)

        result_chars = list(text)
        category_counters = {"EMAIL": 0, "PHONE": 0, "SA_ID": 0, "DATA": 0}

        # First pass to assign sequence labels (forward order)
        token_labels = {}
        for f in sorted(clean_findings, key=lambda f: f.start_pos):
            if "email" in f.rule_name.lower():
                category_counters["EMAIL"] += 1
                token_labels[id(f)] = f"[REDACTED_EMAIL_{category_counters['EMAIL']}]"
            elif "phone" in f.rule_name.lower() or "telephone" in f.rule_name.lower():
                category_counters["PHONE"] += 1
                token_labels[id(f)] = f"[REDACTED_PHONE_{category_counters['PHONE']}]"
            elif "south african" in f.rule_name.lower() or "id" in f.rule_name.lower():
                category_counters["SA_ID"] += 1
                token_labels[id(f)] = f"[REDACTED_SA_ID_{category_counters['SA_ID']}]"
            else:
                category_counters["DATA"] += 1
                token_labels[id(f)] = f"[REDACTED_DATA_{category_counters['DATA']}]"

        # Apply replacements in reverse order
        for f in clean_findings:
            token = token_labels[id(f)]
            result_chars[f.start_pos : f.end_pos] = list(token)

        return "".join(result_chars), len(clean_findings)

    @staticmethod
    def mask_snippet_for_audit(text: str, max_chars: int = 160) -> str:
        """
        Generates a masked snippet suitable for safe audit logging.
        Masks out potential API keys, passwords, and sensitive substrings.
        """
        if not text:
            return ""
        snippet = text[:max_chars].strip()
        # Light heuristic mask for common tokens in audit display
        import re
        masked = re.sub(r"sk-[a-zA-Z0-9]{10,}", "sk-***MASKED***", snippet)
        masked = re.sub(r"AKIA[0-9A-Z]{10,}", "AKIA***MASKED***", masked)
        masked = re.sub(r"gh[pousr]_[A-Za-z0-9_]{10,}", "ghp_***MASKED***", masked)
        masked = re.sub(r"(?i)(password|passwd|secret)\s*[:=]\s*['\"]?[^\s'\";]+['\"]?", r"\1=***MASKED***", masked)
        return masked
