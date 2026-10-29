# AI Policy Enforcement Gateway

An auditable security gateway that inspects user prompts prior to forwarding to upstream AI models. It detects prompt-injection attempts, identifies sensitive data (emails, telephone numbers, and South African ID numbers validated via Luhn checksum), redacts confidential information, evaluates configurable policies, and maintains persistent audit logs in SQLite.

---

## Key Features

- **Prompt Injection Defense**: Detects direct instruction overrides ("ignore previous instructions"), system prompt extraction, DAN/jailbreak persona hijackings, and delimiter injections.
- **Sensitive Data Redaction**: Automatically redacts emails, telephone numbers, and 13-digit South African ID numbers with valid Luhn checksums into safe tokens (e.g., `[REDACTED_EMAIL_1]`).
- **Credential Protection**: Blocks high-entropy API keys (OpenAI, AWS, GitHub) and plaintext password assignments.
- **Configurable Policy Engine**: JSON-backed policy system with strict precedence: `BLOCK > REDACT > WARN > ALLOW`.
- **Compound Risk Scoring**: Produces normalized risk scores (0–100) and risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Persistent SQLite Audit Logging**: Parameterized queries, sanitized log snippets, and export to CSV/JSON.
- **Security Test Lab**: Built-in test suite runner evaluating accuracy, false-positive traps, and detection latency.

---

## Architecture Overview

```
Untrusted User Input
        │
        ▼
[Normalization & NFKC]
        │
        ▼
[Security Detectors] ──── (Prompt Injection, PII, Credentials)
        │
        ▼
[Policy Engine] ───────── (Precedence: BLOCK > REDACT > WARN > ALLOW)
        │
   ┌────┴──────────────────────────┐
   ▼                               ▼
[BLOCK Decision]          [REDACT / ALLOW]
   │                               │
   ▼                               ▼
Drop & Reject             [Redaction Engine]
(Never sent to model)              │
                                   ▼
                         Forward to AI Model
                                   │
                                   ▼
                         [SQLite Audit Logger]
```

---

## Quickstart & Local Setup

### 1. Prerequisites
- Python 3.11+
- Git

### 2. Clone and Setup Virtual Environment

```bash
# Clone the repository
git clone https://github.com/example/ai-policy-enforcement-gateway.git
cd ai-policy-enforcement-gateway

# Create virtual environment
python3 -m venv .venv

# Activate the virtual environment
# On Linux / macOS:
source .venv/bin/activate
# On Windows (PowerShell):
# .venv\Scripts\Activate.ps1
# On Windows (Command Prompt):
# .venv\Scripts\activate.bat
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run Automated Test Suite

```bash
pytest -v
```

All unit and integration tests will execute against detectors, policy evaluation, redaction, and database persistence.

### 5. Launch the Streamlit Gateway Dashboard

```bash
streamlit run app.py
```

The interactive dashboard will open at `http://localhost:8501`.

---

## Configuration & Policies

Policies are defined in `config/policies.json`. Each policy specifies:
- `id`: Unique identifier (e.g., `PI-001`, `SD-003`).
- `name`: Human-readable label.
- `category`: `PROMPT_INJECTION`, `SENSITIVE_DATA`, `CREDENTIAL_EXPOSURE`, or `GUARDRAIL_BYPASS`.
- `severity`: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- `action`: `ALLOW`, `WARN`, `REDACT`, or `BLOCK`.
- `enabled`: Boolean toggle.
- `patterns`: List of regular expressions.

### Policy Precedence:
1. If any triggered rule specifies `BLOCK`, the final decision is `BLOCK`.
2. Otherwise, if any triggered rule specifies `REDACT`, the final decision is `REDACT`.
3. Otherwise, if any triggered rule specifies `WARN`, the final decision is `WARN`.
4. Otherwise, the decision is `ALLOW`.

---

## Limitations & Ethical Considerations

- **Heuristic Defense**: Regular expressions provide fast Layer-1 protection but cannot capture deep semantic nuances or novel obfuscated zero-day attacks.
- **South African ID Check**: Mathematical validity through the Luhn algorithm confirms numerical conformity, not verification against the Department of Home Affairs.
- **False Positives**: Security discussions and academic questions mentioning attack syntax may be flagged. Always calibrate policies for your specific domain.

---

## License

Apache-2.0
