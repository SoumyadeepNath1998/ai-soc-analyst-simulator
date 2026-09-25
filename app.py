# app.py
import streamlit as st
from mock_telemetry import MOCK_ALERTS
from soc_tools import (
    lookup_ip_threat_intel,
    lookup_dns_internal,
    parse_script_payload,
    calculate_risk_matrix
)

st.set_page_config(page_title="AI SOC Analyst & IR Simulator", layout="wide", page_icon="🛡️")

st.title("🛡️ Autonomous GenAI Tier-1 SOC Analyst Simulator")
st.markdown("---")

# Sidebar: Telemetry Ingestion Layer
st.sidebar.header("📥 Telemetry Ingestion")
selected_key = st.sidebar.selectbox("Select Inbound Alert", list(MOCK_ALERTS.keys()))
active_alert = MOCK_ALERTS[selected_key]

run_sim = st.sidebar.button("⚡ Ingest & Trigger Autonomous Triage", type="primary")

col1, col2, col3 = st.columns([1.2, 1.3, 1.5])

# Column 1: Raw Telemetry
with col1:
    st.subheader("1. Ingested Telemetry")
    st.caption(f"Source: {active_alert['source']} | Severity: {active_alert['severity']}")
    st.json(active_alert)

# Simulation Engine Trigger
if run_sim:
    telemetry = active_alert["telemetry_data"]
    endpoint = active_alert["endpoint"]

    with col2:
        st.subheader("2. Agent Reasoning & Tool Calls")
        st.write("🤖 *Executing Autonomous Triage Runbook...*")
        
        # Tool Call 1: Threat Intel / IP Check
        with st.expander("🔍 Tool 1: lookup_ip_threat_intel()", expanded=True):
            ip = telemetry.get("destination_ip", "N/A")
            ip_result = lookup_ip_threat_intel(ip)
            st.json(ip_result)

        # Tool Call 2: DNS Inspection
        with st.expander("🌐 Tool 2: lookup_dns_internal()", expanded=True):
            domain = telemetry.get("destination_domain") or telemetry.get("suspicious_query", "internal.corp")
            dns_result = lookup_dns_internal(domain)
            st.json(dns_result)

        # Tool Call 3: Script Analysis
        with st.expander("⚙️ Tool 3: parse_script_payload()", expanded=True):
            cmd = telemetry.get("command_line", "None")
            encoded_part = cmd.split("-Enc ")[-1] if "-Enc " in cmd else cmd
            script_result = parse_script_payload(encoded_part)
            st.json(script_result)

        # Compute Risk
        intel_score = ip_result.get("confidence_score", 10)
        if dns_result.get("dns_tunnel_detected"):
            intel_score = 95
        risk_score = calculate_risk_matrix(intel_score, endpoint.get("criticality", ""))

    with col3:
        st.subheader("3. ServiceNow SIR & Action Deck")
        
        is_escalation = risk_score >= 70
        verdict_badge = "🚨 ESCALATED TO TIER-2 SOC" if is_escalation else "✅ AUTO-RESOLVED (FALSE POSITIVE)"
        badge_type = "error" if is_escalation else "success"
        
        getattr(st, badge_type)(f"### Verdict: {verdict_badge}")
        
        st.metric(label="Calculated Composite Risk", value=f"{risk_score} / 100")
        
        sla_text = "Paused (Under Tier-2 Review)" if is_escalation else "Closed - Resolved"
        st.markdown(f"""
        **Mock ServiceNow Ticket Record:**
        - **Number:** `SIR0092147`
        - **Asset Affected:** `{endpoint['hostname']} ({endpoint['ip_address']})`
        - **SLA Status:** `{sla_text}`
        
        **Autonomous Analyst Working Notes:**
        > *Evaluated incoming payload against internal threat intelligence sources. Destination endpoint scored risk rating of {risk_score}. Autonomous triage playbook completed evidence collection without manual intervention.*
        """)