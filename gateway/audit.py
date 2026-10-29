"""
Audit Logging and Persistence Module.

Manages persistent storage in SQLite, safe parameterized queries,
sanitized event records, search/filtering, and export to CSV and JSON.
"""

from __future__ import annotations
import os
import sqlite3
import json
import csv
import io
import datetime
from typing import List, Dict, Any, Optional
from gateway.models import AuditEvent, InspectionResult
from gateway.redaction import RedactionEngine


class AuditLogger:
    """
    Thread-safe, parameterized SQLite audit logger.
    """

    def __init__(self, db_path: str = "data/audit_history.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        risk_level TEXT NOT NULL,
                        triggered_rules TEXT,
                        categories TEXT,
                        input_length INTEGER,
                        masked_snippet TEXT,
                        redacted_preview TEXT,
                        execution_time_ms REAL
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
                    """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision);
                    """
                )
                conn.commit()
        except sqlite3.Error as e:
            # Handle DB init gracefully
            pass

    def record_inspection(self, result: InspectionResult) -> Optional[AuditEvent]:
        """
        Sanitizes and records an inspection event into SQLite.
        Avoids storing raw secrets or unredacted passwords.
        """
        masked = RedactionEngine.mask_snippet_for_audit(result.raw_input)
        event = AuditEvent.from_inspection(result, masked)

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO audit_events (
                        event_id, timestamp, request_id, decision, risk_score,
                        risk_level, triggered_rules, categories, input_length,
                        masked_snippet, redacted_preview, execution_time_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.timestamp,
                        event.request_id,
                        event.decision,
                        event.risk_score,
                        event.risk_level,
                        event.triggered_rules,
                        event.categories,
                        event.input_length,
                        event.masked_snippet,
                        event.redacted_preview,
                        event.execution_time_ms,
                    ),
                )
                conn.commit()
            return event
        except sqlite3.Error:
            return None

    def query_events(
        self,
        decision: Optional[str] = None,
        severity: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Parameterized query with optional filtering.
        """
        query = "SELECT * FROM audit_events WHERE 1=1"
        params: List[Any] = []

        if decision and decision.upper() != "ALL":
            query += " AND decision = ?"
            params.append(decision.upper())

        if severity and severity.upper() != "ALL":
            query += " AND risk_level = ?"
            params.append(severity.upper())

        if search_query and search_query.strip():
            query += " AND (request_id LIKE ? OR masked_snippet LIKE ? OR triggered_rules LIKE ?)"
            term = f"%{search_query.strip()}%"
            params.extend([term, term, term])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error:
            return []

    def get_statistics(self) -> Dict[str, Any]:
        """
        Aggregates inspection metrics from actual persistent SQLite records.
        """
        default_stats = {
            "total_requests": 0,
            "allowed": 0,
            "warned": 0,
            "redacted": 0,
            "blocked": 0,
            "threat_detection_rate": 0.0,
            "category_distribution": {},
            "decision_distribution": {"ALLOW": 0, "WARN": 0, "REDACT": 0, "BLOCK": 0},
        }

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM audit_events")
                total = cursor.fetchone()[0]

                if total == 0:
                    return default_stats

                cursor.execute("SELECT decision, COUNT(*) FROM audit_events GROUP BY decision")
                decisions = dict(cursor.fetchall())

                allowed = decisions.get("ALLOW", 0)
                warned = decisions.get("WARN", 0)
                redacted = decisions.get("REDACT", 0)
                blocked = decisions.get("BLOCK", 0)

                threat_count = warned + redacted + blocked
                detection_rate = round((threat_count / total) * 100, 1)

                # Fetch categories
                cursor.execute("SELECT categories FROM audit_events WHERE categories != ''")
                cat_rows = cursor.fetchall()
                cat_counts: Dict[str, int] = {}
                for row in cat_rows:
                    cats = row[0].split(",")
                    for c in cats:
                        c_clean = c.strip()
                        if c_clean:
                            cat_counts[c_clean] = cat_counts.get(c_clean, 0) + 1

                return {
                    "total_requests": total,
                    "allowed": allowed,
                    "warned": warned,
                    "redacted": redacted,
                    "blocked": blocked,
                    "threat_detection_rate": detection_rate,
                    "category_distribution": cat_counts,
                    "decision_distribution": {
                        "ALLOW": allowed,
                        "WARN": warned,
                        "REDACT": redacted,
                        "BLOCK": blocked,
                    },
                }
        except sqlite3.Error:
            return default_stats

    def export_json(self) -> str:
        """
        Exports all audit records to formatted JSON.
        """
        records = self.query_events(limit=10000)
        return json.dumps(records, indent=2)

    def export_csv(self) -> str:
        """
        Exports all audit records to CSV string.
        """
        records = self.query_events(limit=10000)
        if not records:
            return "event_id,timestamp,request_id,decision,risk_score,risk_level,triggered_rules,categories,input_length,execution_time_ms\n"

        output = io.StringIO()
        fieldnames = [
            "event_id",
            "timestamp",
            "request_id",
            "decision",
            "risk_score",
            "risk_level",
            "triggered_rules",
            "categories",
            "input_length",
            "masked_snippet",
            "redacted_preview",
            "execution_time_ms",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(r)
        return output.getvalue()
