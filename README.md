# 🛡️ Autonomous GenAI Tier-1 SOC Analyst & IR Simulator

An end-to-end autonomous security triage platform simulating Tier-1 Security Operations Center (SOC) workflows using LangChain, Streamlit, and Python.

🔗 **Live Deployment:** [Interactive Web App](https://ai-soc-analyst-simulator-hsrrmss7fxt9fz3g9gvr3r.streamlit.app)

---

## ⚡ Core Architecture & Workflow
1. **Telemetry Ingestion:** Ingests simulated EDR (CrowdStrike Falcon), DNS firewall (BlueCat DDI), and SIEM logs.
2. **Autonomous Tool Calls:**
   - `lookup_ip_threat_intel()`: Correlates IPs against malicious C2 infrastructures.
   - `lookup_dns_internal()`: Detects high-entropy DNS tunneling patterns.
   - `parse_script_payload()`: Decodes obfuscated PowerShell execution cradles.
3. **Dynamic Risk Engine:** Calculates composite risk matrix adjusted for asset criticality (Tier-1 to Tier-3).
4. **Automated ITSM Action:** Emulates ServiceNow Security Incident Response (SIR) triage, SLA pausing, and escalation.

---

## 🛠️ Tech Stack
- **Frontend / Cloud:** Streamlit Community Cloud
- **Logic & Orchestration:** Python 3.12, LangChain Ecosystem
- **Telemetry Schema:** Pydantic models emulating MITRE ATT&CK vectors
