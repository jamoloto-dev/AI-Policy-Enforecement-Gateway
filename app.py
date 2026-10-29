"""
AI Policy Enforcement Gateway - Streamlit Application.

Interactive cybersecurity console for inspecting prompts, running test labs,
managing security policies, exploring persistent audit logs, and reviewing security documentation.
"""

import streamlit as st
import json
import os
import pandas as pd
from gateway.enforcement import EnforcementGateway
from gateway.models import EnforcementAction, SeverityLevel, PolicyRule, ThreatCategory
from gateway.test_runner import SecurityTestRunner

# Configure Streamlit page
st.set_page_config(
    page_title="AI Policy Enforcement Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Cyber Dark CSS
st.markdown(
    """
    <style>
    /* Dark Cybersecurity Aesthetics */
    .stApp {
        background-color: #030712;
        color: #f3f4f6;
        font-family: 'JetBrains Mono', 'Segoe UI', monospace;
    }
    .metric-card {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 18px;
        text-align: center;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        margin-top: 4px;
    }
    .decision-block {
        background: rgba(225, 29, 72, 0.15);
        border: 1px solid #f43f5e;
        color: #fda4af;
        padding: 16px;
        border-radius: 8px;
        font-weight: 600;
    }
    .decision-allow {
        background: rgba(16, 185, 129, 0.15);
        border: 1px solid #10b981;
        color: #6ee7b7;
        padding: 16px;
        border-radius: 8px;
        font-weight: 600;
    }
    .decision-redact {
        background: rgba(6, 182, 212, 0.15);
        border: 1px solid #06b6d4;
        color: #67e8f9;
        padding: 16px;
        border-radius: 8px;
        font-weight: 600;
    }
    .decision-warn {
        background: rgba(245, 158, 11, 0.15);
        border: 1px solid #f59e0b;
        color: #fcd34d;
        padding: 16px;
        border-radius: 8px;
        font-weight: 600;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_gateway() -> EnforcementGateway:
    return EnforcementGateway()


gateway = get_gateway()

# Sidebar Navigation
st.sidebar.markdown("## 🛡️ Gateway Control")
st.sidebar.markdown(
    """
    <div style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 1rem;">
    Zero-Trust AI Security Pipeline • v1.0.0
    </div>
    """,
    unsafe_allow_html=True,
)

nav_selection = st.sidebar.radio(
    "Navigation",
    [
        "Security Overview",
        "Live Inspection",
        "Security Test Lab",
        "Policy Management",
        "Audit Explorer",
        "Security Information",
    ],
    index=0,
)

st.sidebar.markdown("---")
st.sidebar.info(
    "**Gateway Status**: ACTIVE\n\n"
    "Rule Engine: Deterministic\n\n"
    "Precedence: BLOCK > REDACT > WARN > ALLOW"
)

# -------------------------------------------------------------
# PAGE 1: Security Overview
# -------------------------------------------------------------
if nav_selection == "Security Overview":
    st.title("📊 Security Operations Overview")
    st.markdown("Real-time telemetry aggregated from persistent SQLite audit logs.")

    stats = gateway.audit_logger.get_statistics()
    total = stats["total_requests"]

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #94a3b8; font-size: 0.85rem;">TOTAL INSPECTIONS</div>
                <div class="metric-value" style="color: #38bdf8;">{stats['total_requests']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #94a3b8; font-size: 0.85rem;">ALLOWED</div>
                <div class="metric-value" style="color: #4ade80;">{stats['allowed']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #94a3b8; font-size: 0.85rem;">WARNED</div>
                <div class="metric-value" style="color: #fbbf24;">{stats['warned']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #94a3b8; font-size: 0.85rem;">REDACTED</div>
                <div class="metric-value" style="color: #22d3ee;">{stats['redacted']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col5:
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #94a3b8; font-size: 0.85rem;">BLOCKED</div>
                <div class="metric-value" style="color: #f43f5e;">{stats['blocked']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    if total == 0:
        st.warning("No live inspection requests have been processed yet. Visit **Live Inspection** or run the **Security Test Lab** to generate real telemetry.")
    else:
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Decision Breakdown")
            dec_df = pd.DataFrame(
                list(stats["decision_distribution"].items()),
                columns=["Decision", "Count"],
            )
            st.bar_chart(dec_df.set_index("Decision"))

        with c2:
            st.subheader("Threat Detection Rate")
            rate = stats["threat_detection_rate"]
            st.metric(
                label="Threat Interception Ratio",
                value=f"{rate}%",
                help="Formula: (Warned + Redacted + Blocked) / Total Requests * 100",
            )
            if stats["category_distribution"]:
                cat_df = pd.DataFrame(
                    list(stats["category_distribution"].items()),
                    columns=["Threat Category", "Incidents"],
                )
                st.dataframe(cat_df, use_container_width=True, hide_index=True)

        st.subheader("Recent Security Events")
        recent = gateway.audit_logger.query_events(limit=5)
        if recent:
            st.dataframe(pd.DataFrame(recent)[["timestamp", "request_id", "decision", "risk_level", "triggered_rules", "masked_snippet"]], use_container_width=True, hide_index=True)

# -------------------------------------------------------------
# PAGE 2: Live Inspection
# -------------------------------------------------------------
elif nav_selection == "Live Inspection":
    st.title("🔍 Live Prompt Inspection")
    st.markdown("Submit untrusted user text to inspect detection heuristics, evaluate policies, and simulate AI forwarding.")

    # Load sample cases for selector
    runner = SecurityTestRunner(gateway)
    sample_cases = runner.load_test_cases()
    case_titles = ["-- Select Preset Example or Enter Custom Text --"] + [f"[{c['id']}] {c['name']} ({c['expected_decision']})" for c in sample_cases]

    selected_example = st.selectbox("Preset Example Selector", case_titles)

    default_text = ""
    if selected_example != case_titles[0]:
        case_idx = case_titles.index(selected_example) - 1
        default_text = sample_cases[case_idx]["input"]

    col_input, col_clear = st.columns([6, 1])
    with col_input:
        user_input = st.text_area("Input Prompt to Inspect", value=default_text, height=140, placeholder="Type or paste prompt text here...")

    col_btn1, col_btn2 = st.columns([2, 8])
    with col_btn1:
        inspect_btn = st.button("🛡️ Inspect Input", type="primary", use_container_width=True)

    if inspect_btn and user_input:
        res = gateway.inspect_and_enforce(user_input, record_audit=True)

        st.markdown("---")
        st.subheader("Enforcement Decision Result")

        # Visual decision banner
        css_class = f"decision-{res.final_decision.value.lower()}"
        st.markdown(
            f"""
            <div class="{css_class}">
                <div style="font-size: 1.25rem; font-weight: 700;">DECISION: {res.final_decision.value}</div>
                <div style="margin-top: 4px;">{res.decision_reason}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Metrics row
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Risk Score (0-100)", f"{res.risk_score}/100")
        m2.metric("Risk Level", res.risk_level.value)
        m3.metric("Execution Latency", f"{res.execution_time_ms} ms")
        m4.metric("Forwarded to LLM", "YES" if res.forwarded_to_model else "BLOCKED AT GATEWAY")

        # Triggered Rules
        if res.findings:
            st.subheader(f"Triggered Detector Rules ({len(res.findings)})")
            findings_data = []
            for f in res.findings:
                findings_data.append({
                    "Rule ID": f.rule_id,
                    "Rule Name": f.rule_name,
                    "Category": f.category.value,
                    "Severity": f.severity.value,
                    "Action": f.action.value,
                    "Matched Text": f.matched_snippet,
                    "Explanation": f.explanation,
                })
            st.dataframe(pd.DataFrame(findings_data), use_container_width=True, hide_index=True)
        else:
            st.success("No security violations or sensitive data patterns were triggered.")

        # Redaction Output preview
        if res.final_decision == EnforcementAction.REDACT:
            st.subheader("Sanitized Output for Upstream AI Model")
            st.text_area("Redacted Prompt", value=res.redacted_output or "", height=100, disabled=True)
        elif res.final_decision == EnforcementAction.BLOCK:
            st.error("Input was BLOCKED. Downstream inference transmission was prohibited.")

# -------------------------------------------------------------
# PAGE 3: Security Test Lab
# -------------------------------------------------------------
elif nav_selection == "Security Test Lab":
    st.title("🧪 Security Test Lab")
    st.markdown("Execute the automated test suite of 24 benchmark test cases covering benign queries, injection variants, and sensitive data leakage.")

    runner = SecurityTestRunner(gateway)

    if st.button("🚀 Run Test Suite", type="primary"):
        with st.spinner("Executing benchmark test cases..."):
            suite_res = runner.run_suite()

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Test Cases", suite_res["total_cases"])
        c2.metric("Passed Cases", f"{suite_res['passed']} / {suite_res['total_cases']}")
        c3.metric("Test Accuracy", f"{suite_res['accuracy_percent']}%")
        c4.metric("False Positives / Negatives", f"{suite_res['false_positives']} FP / {suite_res['false_negatives']} FN")

        st.subheader("Test Case Detailed Results")
        df_results = pd.DataFrame(suite_res["results"])
        st.dataframe(
            df_results[["case_id", "name", "category", "expected_decision", "actual_decision", "passed", "risk_score", "execution_time_ms"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Click **Run Test Suite** above to execute the 24 positive and negative test cases against the current active policy configuration.")

# -------------------------------------------------------------
# PAGE 4: Policy Management
# -------------------------------------------------------------
elif nav_selection == "Policy Management":
    st.title("⚙️ Security Policy Management")
    st.markdown("Configure security rules, enforcement actions (ALLOW, WARN, REDACT, BLOCK), and enabled states.")

    policies = gateway.policy_engine.policies

    st.subheader("Active Policy Rules")
    for idx, p in enumerate(policies):
        with st.expander(f"{p.id} - {p.name} [{p.action.value}] ({'ENABLED' if p.enabled else 'DISABLED'})"):
            c1, c2, c3 = st.columns(3)
            with c1:
                new_enabled = st.checkbox("Enabled", value=p.enabled, key=f"en_{p.id}")
            with c2:
                new_action = st.selectbox(
                    "Enforcement Action",
                    ["ALLOW", "WARN", "REDACT", "BLOCK"],
                    index=["ALLOW", "WARN", "REDACT", "BLOCK"].index(p.action.value),
                    key=f"act_{p.id}",
                )
            with c3:
                new_sev = st.selectbox(
                    "Severity Level",
                    ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    index=["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(p.severity.value),
                    key=f"sev_{p.id}",
                )

            st.text(f"Description: {p.description}")
            st.text_area("Regex Patterns", value="\n".join(p.patterns), height=80, key=f"pat_{p.id}", disabled=True)

            # Update in memory
            p.enabled = new_enabled
            p.action = EnforcementAction(new_action)
            p.severity = SeverityLevel(new_sev)

    if st.button("💾 Save Policy Changes", type="primary"):
        try:
            gateway.policy_engine.save_policies(policies)
            gateway.reload_policies()
            st.success("Policies successfully validated, saved to config/policies.json, and reloaded!")
        except Exception as err:
            st.error(f"Failed to save policies: {err}")

# -------------------------------------------------------------
# PAGE 5: Audit Explorer
# -------------------------------------------------------------
elif nav_selection == "Audit Explorer":
    st.title("🗄️ Audit Explorer")
    st.markdown("Searchable, filterable audit history backed by persistent SQLite database storage.")

    f1, f2, f3 = st.columns(3)
    with f1:
        f_decision = st.selectbox("Filter by Decision", ["ALL", "ALLOW", "WARN", "REDACT", "BLOCK"])
    with f2:
        f_severity = st.selectbox("Filter by Severity", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    with f3:
        f_search = st.text_input("Search (Request ID, Snippet, Rule ID)")

    events = gateway.audit_logger.query_events(
        decision=f_decision,
        severity=f_severity,
        search_query=f_search,
        limit=200,
    )

    if events:
        st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)

        col_exp1, col_exp2 = st.columns(2)
        with col_exp1:
            json_data = gateway.audit_logger.export_json()
            st.download_button(
                label="📥 Export Audit History (JSON)",
                data=json_data,
                file_name="audit_history.json",
                mime="application/json",
            )
        with col_exp2:
            csv_data = gateway.audit_logger.export_csv()
            st.download_button(
                label="📥 Export Audit History (CSV)",
                data=csv_data,
                file_name="audit_history.csv",
                mime="text/csv",
            )
    else:
        st.info("No audit records matching your current filter criteria.")

# -------------------------------------------------------------
# PAGE 6: Security Information
# -------------------------------------------------------------
elif nav_selection == "Security Information":
    st.title("📖 Gateway Security Model & Documentation")
    st.markdown(
        """
        ### Architecture & Defense Philosophy
        The **AI Policy Enforcement Gateway** provides Layer-1 deterministic defense for AI systems.
        Before an untrusted prompt reaches an expensive or safety-sensitive LLM, the gateway executes
        regular expressions, normalized token matching, Luhn checksums, and policy evaluation.

        #### Rule Precedence Order:
        1. **BLOCK**: The prompt is rejected immediately. It is never forwarded to any downstream model.
        2. **REDACT**: Sensitive entities (emails, telephone numbers, South African ID numbers) are replaced with token placeholders before forwarding.
        3. **WARN**: Prompt contains suspicious markers but is forwarded with an audit flag.
        4. **ALLOW**: Clean input with zero triggered violations.

        #### Documented Limitations:
        - **Heuristics vs Semantics**: Regex cannot detect intent in complex paraphrases or encrypted inputs.
        - **South African ID Verification**: Luhn checksum confirms numerical validity, not verification against official Home Affairs records.
        - **False Positives**: Academic and defensive queries discussing prompt injection will trigger keyword patterns.
        """
    )
