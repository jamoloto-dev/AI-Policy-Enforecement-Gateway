# AI Policy Enforcement Gateway: Architecture Overview

## 1. System Mission & Scope
The **AI Policy Enforcement Gateway** sits as a zero-trust inspection layer between untrusted user clients (or client applications) and LLM inference endpoints. Its purpose is to deterministically validate, sanitize, and enforce organizational security policies before prompts reach upstream AI models.

```
                      +------------------------------------+
                      |       Untrusted User Prompt        |
                      +-----------------+------------------+
                                        |
                                        v
                      +------------------------------------+
                      |     1. Input Validation & Norm     |
                      |   - Payload size limit (<100kB)    |
                      |   - Unicode NFKC & control chars   |
                      +-----------------+------------------+
                                        |
                                        v
                      +------------------------------------+
                      |     2. Security Detectors          |
                      |   - Prompt Injection Heuristics    |
                      |   - PII (Email, Phone, SA ID)      |
                      |   - Credentials & API Keys         |
                      +-----------------+------------------+
                                        | Findings
                                        v
                      +------------------------------------+
                      |     3. Policy Engine Evaluation    |
                      |   - Precedence: BLOCK>REDACT>WARN  |
                      |   - Compound Risk Scoring (0-100)  |
                      +-----------------+------------------+
                                        | Decision
                     +------------------+------------------+
                     |                                     |
              [BLOCK Decision]                   [ALLOW / REDACT / WARN]
                     |                                     |
                     v                                     v
          +----------------------+              +----------------------+
          | Terminate & Reject   |              | 4. Redaction Engine  |
          | (No LLM Handshake)   |              | (Token replacement)  |
          +----------+-----------+              +----------+-----------+
                     |                                     |
                     |                                     v
                     |                          +----------------------+
                     |                          | Forward to AI Model  |
                     |                          +----------+-----------+
                     |                                     |
                     +------------------+------------------+
                                        |
                                        v
                      +------------------------------------+
                      |     5. Parameterized Audit Log     |
                      |   - Masked previews into SQLite    |
                      |   - CSV & JSON export capabilities |
                      +------------------------------------+
```

## 2. Component Breakdown

### A. Normalization & Sanitization (`gateway/detectors.py`)
- Standardizes Unicode representations via **NFKC** to counteract homoglyph attacks and evasions.
- Strips null-bytes and non-printable control characters.
- Maintains original text offsets to ensure precision in downstream token redaction.

### B. Deterministic Detector Engine (`gateway/detectors.py`)
- **Prompt Injection**: Configurable regex patterns for instruction overrides, system prompt exfiltration, roleplay/DAN mode hijacking, filter circumvention, and delimiter injection.
- **Sensitive Data**:
  - Email addresses (RFC 5322 regex subset).
  - Telephones (E.164 and localized South African formats).
  - South African National IDs (13 digits verified against date components and the Luhn checksum algorithm).
- **Credential Harvesting**:
  - Cloud API Keys (OpenAI, AWS Access Keys, GitHub PATs, Google API keys).
  - Direct variable assignments (`password = ...`).

### C. Policy Engine (`gateway/policy_engine.py`)
- Configured via JSON (`config/policies.json`).
- Strict precedence resolution:
  1. `BLOCK`: Absolute rejection.
  2. `REDACT`: Safe placeholder substitution; prompt proceeds to model.
  3. `WARN`: Flagged for review; prompt proceeds to model.
  4. `ALLOW`: No matching policy violation.
- Risk Score Calculation (0 - 100) based on severity weights:
  - CRITICAL: +40
  - HIGH: +25
  - MEDIUM: +15
  - LOW: +5
  - Multi-category penalty: +15

### D. Redaction Engine (`gateway/redaction.py`)
- Reverse-offset text substitution prevents index drift.
- Categorized tokens: `[REDACTED_EMAIL_1]`, `[REDACTED_PHONE_1]`, `[REDACTED_SA_ID_1]`.
- Masked audit logging ensures secrets are not written to persistent storage.

### E. Persistent Audit Store (`gateway/audit.py`)
- Uses local SQLite (`data/audit_history.db`) with parameterized SQL queries.
- Indexed by timestamp and decision for rapid telemetry querying.
- Provides JSON and CSV export endpoints.
