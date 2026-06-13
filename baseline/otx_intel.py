#!/usr/bin/env python3
"""
GhostNet — OTX Threat Intel → Suricata Rule Generator
Pulls IOCs from AlienVault OTX and generates custom Suricata rules

Author: Eliezer Fuentes (enak223)
Usage: python3 otx_intel.py
"""

import json, re, sys, time, logging, requests
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [OTX] %(message)s")
log = logging.getLogger("ghostnet.otx")

OTX_API_KEY    = "5ceac14e712a5a912804ce5256962970b967d4ee3c30536586884edc7dc0b3dd"
OTX_BASE       = "https://otx.alienvault.com/api/v1"
RULES_OUT      = Path("/etc/suricata/rules/ghostnet_otx.rules")
RULES_BACKUP   = Path("/tmp/ghostnet_otx_backup.rules")
SURICATA_RULES = Path("/var/lib/suricata/rules/suricata.rules")
LOOKBACK_DAYS  = 7
MAX_IOCS       = 500
SID_BASE       = 9900000

PULSE_CATEGORIES = [
    "Malware", "Ransomware", "Exploit Kit", "APT",
    "Command and Control", "Phishing", "Backdoor"
]

def otx_get(endpoint, params=None):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = f"{OTX_BASE}{endpoint}"
    try:
        r = requests.get(url, headers=headers, params=params, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.error(f"OTX API error {endpoint}: {e}")
        return {}

def fetch_subscribed_pulses():
    log.info("Fetching subscribed OTX pulses...")
    since = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).strftime(
        "%Y-%m-%dT%H:%M:%S")
    pulses = []
    page = 1
    while True:
        data = otx_get("/pulses/subscribed", {"modified_since": since, "page": page, "limit": 20})
        results = data.get("results", [])
        if not results:
            break
        pulses.extend(results)
        log.info(f"  Page {page}: {len(results)} pulses")
        if not data.get("next"):
            break
        page += 1
        time.sleep(0.5)
    log.info(f"Total pulses fetched: {len(pulses)}")
    return pulses

def extract_iocs(pulses):
    iocs = {"ip": set(), "domain": set(), "url": set(), "hostname": set()}
    for pulse in pulses:
        cat = pulse.get("tags", [])
        name = pulse.get("name", "")
        for ind in pulse.get("indicators", []):
            t = ind.get("type", "")
            v = ind.get("indicator", "").strip()
            if not v or len(v) > 253:
                continue
            if t in ("IPv4", "IPv6") and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v):
                # Skip RFC1918
                if not any(v.startswith(p) for p in ("10.","172.16.","172.17.",
                           "172.18.","192.168.","127.","0.")):
                    iocs["ip"].add(v)
            elif t == "domain" and re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,251}[a-zA-Z0-9]$", v):
                iocs["domain"].add(v)
            elif t == "hostname" and "." in v:
                iocs["hostname"].add(v)
            elif t == "URL" and v.startswith("http"):
                # Extract host from URL
                try:
                    host = v.split("/")[2].split(":")[0]
                    if host and "." in host:
                        iocs["hostname"].add(host)
                except: pass

    # Cap to MAX_IOCS
    for k in iocs:
        iocs[k] = set(list(iocs[k])[:MAX_IOCS])

    log.info(f"IOCs extracted — IPs: {len(iocs['ip'])} | "
             f"Domains: {len(iocs['domain'])} | Hostnames: {len(iocs['hostname'])}")
    return iocs

def generate_rules(iocs):
    rules = []
    sid = SID_BASE
    ts = datetime.now().strftime("%Y-%m-%d")

    rules.append(f"# GhostNet OTX Threat Intel Rules — Generated {ts}")
    rules.append(f"# Source: AlienVault OTX | IOCs from last {LOOKBACK_DAYS} days")
    rules.append(f"# IPs: {len(iocs['ip'])} | Domains: {len(iocs['domain'])} | Hostnames: {len(iocs['hostname'])}")
    rules.append("")

    # IP rules
    if iocs["ip"]:
        rules.append("# ── Malicious IP Rules ─────────────────────────────────────")
        for ip in sorted(iocs["ip"]):
            rules.append(
                f'alert ip $HOME_NET any -> {ip} any '
                f'(msg:"GhostNet OTX Malicious IP Outbound {ip}"; '
                f'threshold:type limit,track by_src,count 1,seconds 60; '
                f'classtype:trojan-activity; sid:{sid}; rev:1; '
                f'metadata:created_at {ts},confidence high,source otx;)'
            )
            sid += 1
            rules.append(
                f'alert ip {ip} any -> $HOME_NET any '
                f'(msg:"GhostNet OTX Malicious IP Inbound {ip}"; '
                f'threshold:type limit,track by_src,count 1,seconds 60; '
                f'classtype:trojan-activity; sid:{sid}; rev:1; '
                f'metadata:created_at {ts},confidence high,source otx;)'
            )
            sid += 1

    # DNS rules for domains
    all_domains = iocs["domain"] | iocs["hostname"]
    if all_domains:
        rules.append("")
        rules.append("# ── Malicious Domain DNS Rules ──────────────────────────────")
        for domain in sorted(all_domains):
            safe = domain.replace(".", "\\.")
            rules.append(
                f'alert dns $HOME_NET any -> any 53 '
                f'(msg:"GhostNet OTX Malicious Domain DNS Query {domain}"; '
                f'dns.query; content:"{domain}"; nocase; '
                f'threshold:type limit,track by_src,count 1,seconds 300; '
                f'classtype:trojan-activity; sid:{sid}; rev:1; '
                f'metadata:created_at {ts},confidence medium,source otx;)'
            )
            sid += 1

    log.info(f"Generated {sid - SID_BASE} Suricata rules (SID {SID_BASE}-{sid-1})")
    return rules

def write_rules(rules):
    content = "\n".join(rules) + "\n"

    # Try writing to Suricata rules dir (needs sudo)
    try:
        RULES_OUT.parent.mkdir(parents=True, exist_ok=True)
        RULES_OUT.write_text(content)
        log.info(f"Rules written → {RULES_OUT}")
        return str(RULES_OUT)
    except PermissionError:
        # Fall back to /tmp
        RULES_BACKUP.write_text(content)
        log.warning(f"Permission denied on {RULES_OUT}")
        log.info(f"Rules written to backup → {RULES_BACKUP}")
        log.info(f"Run: sudo cp {RULES_BACKUP} {RULES_OUT} && sudo systemctl reload suricata")
        return str(RULES_BACKUP)

def save_ioc_report(iocs, pulses):
    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "lookback_days": LOOKBACK_DAYS,
        "pulse_count": len(pulses),
        "ioc_counts": {k: len(v) for k, v in iocs.items()},
        "sample_ips": list(sorted(iocs["ip"]))[:20],
        "sample_domains": list(sorted(iocs["domain"]))[:20],
    }
    outfile = f"ghostnet_otx_report_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    Path(outfile).write_text(json.dumps(report, indent=2))
    log.info(f"IOC report saved → {outfile}")
    return outfile

def main():
    log.info("GhostNet OTX Threat Intel starting...")
    pulses = fetch_subscribed_pulses()
    if not pulses:
        log.warning("No pulses returned — check API key or subscriptions")
        log.info("Tip: Subscribe to pulses at https://otx.alienvault.com/browse")
        sys.exit(0)

    iocs = extract_iocs(pulses)
    total = sum(len(v) for v in iocs.values())
    if total == 0:
        log.warning("No IOCs extracted from pulses")
        sys.exit(0)

    rules = generate_rules(iocs)
    rules_path = write_rules(rules)
    report = save_ioc_report(iocs, pulses)

    log.info("\n" + "="*55)
    log.info("OTX INTEL SUMMARY")
    log.info(f"  Pulses processed : {len(pulses)}")
    log.info(f"  Malicious IPs    : {len(iocs['ip'])}")
    log.info(f"  Malicious Domains: {len(iocs['domain'])}")
    log.info(f"  Hostnames        : {len(iocs['hostname'])}")
    log.info(f"  Rules generated  : {len(rules)-4}")
    log.info(f"  Rules file       : {rules_path}")
    log.info(f"  IOC report       : {report}")
    log.info("="*55)

    log.info("\nNext steps:")
    log.info(f"  1. sudo cp {rules_path} /etc/suricata/rules/ghostnet_otx.rules")
    log.info(f"  2. Add to /etc/suricata/suricata.yaml rule-files section:")
    log.info(f"       - /etc/suricata/rules/ghostnet_otx.rules")
    log.info(f"  3. sudo systemctl reload suricata")
    log.info(f"  4. sudo suricata --list-rules | grep GhostNet")

if __name__ == "__main__":
    main()
