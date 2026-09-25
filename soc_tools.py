# soc_tools.py
import base64

def lookup_ip_threat_intel(ip: str) -> dict:
    """Simulates Threat Intel lookup (VirusTotal/OTX)"""
    malicious_ips = ["198.51.100.24"]
    if ip in malicious_ips:
        return {"ip": ip, "reputation": "Malicious", "confidence_score": 92, "tags": ["C2-Server", "CobaltStrike"]}
    return {"ip": ip, "reputation": "Clean / Internal", "confidence_score": 5, "tags": ["Enterprise Internal"]}

def lookup_dns_internal(domain: str) -> dict:
    """Simulates BlueCat DDI / Internal DNS lookup"""
    if "exfil-domain-test" in domain or "malicious-beacon" in domain:
        return {"domain": domain, "category": "Suspicious", "dns_tunnel_detected": True, "action": "Sinkhole Recommended"}
    return {"domain": domain, "category": "Legitimate Enterprise", "dns_tunnel_detected": False, "action": "Allowed"}

def parse_script_payload(payload: str) -> dict:
    """Decodes Base64 encoded PowerShell payloads"""
    try:
        decoded_bytes = base64.b64decode(payload)
        decoded_str = decoded_bytes.decode('utf-16le', errors='ignore')
        return {"decoded_script": decoded_str, "risk_detected": "WebClient Download Cradle (T1059.001)"}
    except Exception:
        return {"decoded_script": payload, "risk_detected": "None / Plaintext"}

def calculate_risk_matrix(intel_score: int, asset_criticality: str) -> int:
    """Computes composite security risk score (0-100)"""
    multiplier = 1.0
    if "Tier-1" in asset_criticality:
        multiplier = 1.3
    composite = min(int(intel_score * multiplier), 100)
    return composite