#!/usr/bin/env python3
"""
GhostNet — anomaly_detector.py v2.0
Wazuh alert ingestion + MITRE ATT&CK auto-mapping

Author: Elie Fuentes (enak223)
"""

import json, re, sys, time, logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("ghostnet.anomaly_detector")

WAZUH_API_BASE  = "https://192.168.248.20:55000"
WAZUH_USER      = "wazuh"
WAZUH_PASS      = "wazuh"
VERIFY_SSL      = False
POLL_INTERVAL   = 30
HIGH_SEV_LEVEL  = 7

MITRE_MAPPINGS = [
    {"groups":["network_scan","scan"],"keywords":["nmap","scan","port scan","sweep","discovery"],"suricata_category":["Network Scan"],"techniques":[("T1046","Network Service Discovery","Reconnaissance")]},
    {"groups":["web_scan"],"keywords":["nikto","dirb","gobuster","web scan","directory"],"techniques":[("T1595.003","Wordlist Scanning","Reconnaissance")]},
    {"groups":["exploit","web_attack"],"keywords":["exploit","sql injection","sqli","rce","shellshock","log4j","path traversal"],"suricata_category":["Exploit Kit","Web Application Attack"],"techniques":[("T1190","Exploit Public-Facing Application","Initial Access")]},
    {"groups":["brute_force","authentication_failed"],"keywords":["brute force","brute_force","multiple failed","authentication failure","invalid user","failed password","login failed"],"techniques":[("T1110","Brute Force","Credential Access")]},
    {"groups":["powershell","command_exec"],"keywords":["powershell","cmd.exe","wscript","cscript","mshta","rundll32"],"techniques":[("T1059.001","PowerShell","Execution")]},
    {"groups":["shell","command_exec"],"keywords":["bash","/bin/sh","shell","command execution","command injection"],"techniques":[("T1059.004","Unix Shell","Execution")]},
    {"groups":["scheduled_task"],"keywords":["cron","scheduled task","at command","schtasks"],"techniques":[("T1053","Scheduled Task/Job","Execution")]},
    {"groups":["rootkit","persistence"],"keywords":["rootkit","bootkit","startup","autorun","persistence","rc.local"],"techniques":[("T1543","Create or Modify System Process","Persistence")]},
    {"groups":["ssh_authorized_keys"],"keywords":["authorized_keys","ssh key",".ssh/"],"techniques":[("T1098.004","SSH Authorized Keys","Persistence")]},
    {"groups":["privesc","privilege_escalation"],"keywords":["sudo","privilege escalat","setuid","suid","capability","sudoers"],"suricata_category":["Attempted Administrator Privilege Gain"],"techniques":[("T1068","Exploitation for Privilege Escalation","Privilege Escalation")]},
    {"groups":["log_clear","log_deletion"],"keywords":["log clear","event log","audit log cleared","truncated","wtmp","utmp"],"techniques":[("T1070.001","Clear Windows Event Logs","Defense Evasion")]},
    {"groups":["obfuscation"],"keywords":["base64","obfuscat","encode","xor","packed"],"techniques":[("T1027","Obfuscated Files or Information","Defense Evasion")]},
    {"groups":["credential_access","passwd"],"keywords":["credential","/etc/shadow","/etc/passwd","mimikatz","lsass","ntlm","hash dump","hashdump","kerberoast"],"techniques":[("T1003","OS Credential Dumping","Credential Access")]},
    {"groups":["system_info"],"keywords":["whoami","uname","hostname","systeminfo","net user","getpid"],"techniques":[("T1082","System Information Discovery","Discovery")]},
    {"groups":["lateral_movement","rdp"],"keywords":["lateral movement","rdp","remote desktop","psexec","wmi","pass-the-hash"],"techniques":[("T1021","Remote Services","Lateral Movement")]},
    {"groups":["ssh_lateral"],"keywords":["ssh login","accepted publickey","accepted password"],"techniques":[("T1021.004","Remote Services: SSH","Lateral Movement")]},
    {"groups":["c2","c&c","beacon"],"keywords":["c2","command and control","beacon","cobalt strike","metasploit","reverse shell","bind shell","rat ","remote access"],"suricata_category":["Malware Command and Control Activity"],"techniques":[("T1071.001","Web Protocols (C2)","Command and Control"),("T1105","Ingress Tool Transfer","Command and Control")]},
    {"groups":["dns_tunnel"],"keywords":["dns tunnel","dnscat","iodine"],"techniques":[("T1071.004","DNS (C2)","Command and Control")]},
    {"groups":["exfil","data_exfiltration"],"keywords":["exfil","data leak","upload","ftp outbound","large transfer"],"suricata_category":["Attempted Information Leak"],"techniques":[("T1041","Exfiltration Over C2 Channel","Exfiltration")]},
    {"groups":["dos","ddos"],"keywords":["denial of service","flood","ddos","syn flood","udp flood"],"suricata_category":["Attempted Denial of Service"],"techniques":[("T1498","Network Denial of Service","Impact")]},
    {"groups":["ransomware"],"keywords":["ransomware","encrypt",".locked",".enc ","ransom"],"techniques":[("T1486","Data Encrypted for Impact","Impact")]},
]

@dataclass
class MitreMatch:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str
    match_reason: str
    navigator_url: str = field(init=False)
    def __post_init__(self):
        self.navigator_url = f"https://attack.mitre.org/techniques/{self.technique_id.replace('.','/')}/"

@dataclass
class AnomalyAlert:
    alert_id: str
    timestamp: str
    source_ip: Optional[str]
    dest_ip: Optional[str]
    rule_id: str
    rule_level: int
    rule_description: str
    rule_groups: list
    agent_name: str
    raw_mitre: list
    mapped_mitre: list
    suricata_category: Optional[str] = None
    suricata_signature: Optional[str] = None
    severity_label: str = "INFO"
    def to_dict(self):
        d = asdict(self)
        d["mapped_mitre"] = [asdict(m) for m in self.mapped_mitre]
        return d

def auto_map_mitre(description, groups, suricata_category=None, existing_mitre=None):
    matches, seen = [], set()
    desc_lower = description.lower()
    groups_lower = [g.lower() for g in groups]

    def _add(techniques, confidence, reason):
        for tid, tname, tactic in techniques:
            if tid not in seen:
                seen.add(tid)
                matches.append(MitreMatch(tid, tname, tactic, confidence, reason))

    for eid in (existing_mitre or []):
        for entry in MITRE_MAPPINGS:
            for tid, tname, tactic in entry["techniques"]:
                if tid == eid and tid not in seen:
                    seen.add(tid)
                    matches.append(MitreMatch(tid, tname, tactic, "high", "wazuh_rule_tag"))

    if suricata_category:
        for entry in MITRE_MAPPINGS:
            if suricata_category in entry.get("suricata_category", []):
                _add(entry["techniques"], "high", f"suricata_category:{suricata_category}")

    for entry in MITRE_MAPPINGS:
        if any(g in groups_lower for g in entry.get("groups", [])):
            _add(entry["techniques"], "medium", f"rule_group")

    for entry in MITRE_MAPPINGS:
        for kw in entry.get("keywords", []):
            if kw in desc_lower:
                _add(entry["techniques"], "low", f"keyword:{kw}")
                break

    return matches

def severity_label(level):
    if level >= 12: return "CRITICAL"
    if level >= 9:  return "HIGH"
    if level >= 7:  return "MEDIUM"
    if level >= 4:  return "LOW"
    return "INFO"

class WazuhClient:
    def __init__(self):
        self.token = None
        self.token_expires = 0.0

    def _get_token(self):
        if self.token and time.time() < self.token_expires:
            return self.token
        log.info("Authenticating with Wazuh API...")
        r = requests.get(f"{WAZUH_API_BASE}/security/user/authenticate",
                         auth=(WAZUH_USER, WAZUH_PASS), verify=VERIFY_SSL, timeout=10)
        r.raise_for_status()
        self.token = r.json()["data"]["token"]
        self.token_expires = time.time() + 840
        return self.token

    def get_alerts(self, min_level=7, limit=50):
        headers = {"Authorization": f"Bearer {self._get_token()}"}
        r = requests.get(f"{WAZUH_API_BASE}/alerts",
                         headers=headers,
                         params={"limit": limit, "sort": "-timestamp", "q": f"rule.level>={min_level}"},
                         verify=VERIFY_SSL, timeout=15)
        r.raise_for_status()
        return r.json().get("data", {}).get("affected_items", [])

def parse_alert(raw):
    rule  = raw.get("rule", {})
    agent = raw.get("agent", {})
    data  = raw.get("data", {})
    net   = raw.get("network", {})

    mitre_block    = rule.get("mitre", {})
    existing_mitre = mitre_block.get("id", []) if isinstance(mitre_block, dict) else []
    suricata_cat   = data.get("alert", {}).get("category") if "alert" in data else None
    suricata_sig   = data.get("alert", {}).get("signature") if "alert" in data else None
    src_ip = data.get("src_ip") or net.get("srcip") or raw.get("srcip")
    dst_ip = data.get("dest_ip") or net.get("dstip") or raw.get("dstip")

    mapped = auto_map_mitre(
        description=rule.get("description", ""),
        groups=rule.get("groups", []),
        suricata_category=suricata_cat,
        existing_mitre=existing_mitre,
    )
    lv = int(rule.get("level", 0))
    return AnomalyAlert(
        alert_id=raw.get("id", "unknown"),
        timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        source_ip=src_ip, dest_ip=dst_ip,
        rule_id=str(rule.get("id","0")), rule_level=lv,
        rule_description=rule.get("description",""),
        rule_groups=rule.get("groups",[]),
        agent_name=agent.get("name","unknown"),
        raw_mitre=existing_mitre, mapped_mitre=mapped,
        suricata_category=suricata_cat, suricata_signature=suricata_sig,
        severity_label=severity_label(lv),
    )

def write_report(alerts, path="ghostnet_anomaly_report.json"):
    tactic_counts, tech_counts = {}, {}
    for a in alerts:
        for m in a.mapped_mitre:
            tactic_counts[m.tactic] = tactic_counts.get(m.tactic, 0) + 1
            if m.technique_id not in tech_counts:
                tech_counts[m.technique_id] = {"name":m.technique_name,"tactic":m.tactic,"count":0,"url":m.navigator_url}
            tech_counts[m.technique_id]["count"] += 1

    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "mitre_summary": {
            "tactic_hit_counts": tactic_counts,
            "top_techniques": [{"id":k,**v} for k,v in sorted(tech_counts.items(), key=lambda x:-x[1]["count"])[:10]],
        },
        "alerts": [a.to_dict() for a in alerts],
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    log.info(f"Report written → {path}")
    return report

def print_alert(a):
    sep = "─" * 68
    print(f"\n{sep}")
    print(f"  [{a.severity_label}] {a.rule_description}")
    print(f"  ID: {a.alert_id} | Level: {a.rule_level} | Agent: {a.agent_name}")
    print(f"  Time: {a.timestamp}")
    if a.source_ip:
        print(f"  Src: {a.source_ip}  →  Dst: {a.dest_ip or 'N/A'}")
    if a.suricata_signature:
        print(f"  Suricata: [{a.suricata_category}] {a.suricata_signature}")
    if a.mapped_mitre:
        print("  MITRE ATT&CK:")
        for m in a.mapped_mitre:
            print(f"    • {m.technique_id} — {m.technique_name} [{m.tactic}] ({m.confidence} / {m.match_reason})")
            print(f"      {m.navigator_url}")
    else:
        print("  MITRE ATT&CK: No mapping found")
    print(sep)

def run():
    log.info("GhostNet Anomaly Detector v2.0 starting...")
    client = WazuhClient()
    seen_ids, cycle = set(), 0

    while True:
        cycle += 1
        log.info(f"Poll cycle {cycle} — fetching alerts (level >= {HIGH_SEV_LEVEL})...")
        try:
            new_alerts = []
            for raw in client.get_alerts(min_level=HIGH_SEV_LEVEL):
                aid = raw.get("id","")
                if aid in seen_ids: continue
                seen_ids.add(aid)
                alert = parse_alert(raw)
                new_alerts.append(alert)
                print_alert(alert)

            if new_alerts:
                write_report(new_alerts, f"ghostnet_anomaly_cycle_{cycle}.json")
                log.info(f"  → {len(new_alerts)} new alerts processed")
            else:
                log.info("  → No new alerts")

        except requests.exceptions.ConnectionError as e:
            log.error(f"Wazuh API unreachable: {e}")
        except Exception as e:
            log.exception(f"Unexpected error: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run()
