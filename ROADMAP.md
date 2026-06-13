# GhostNet — Project Roadmap

## Phase 1 — Core Detection Engine ✅ COMPLETE
- [x] baseline_builder.py — Wazuh agent baseline profiling
- [x] anomaly_detector.py v1.0 — Alert ingestion and severity triage

## Phase 2 — Suricata IDS + MITRE Auto-Mapper ✅ COMPLETE
- [x] Suricata 8.0.5 installed on ubuntuai (ens37, 192.168.248.0/24)
- [x] ET Open ruleset — 50,750 rules loaded
- [x] EVE JSON → Wazuh Docker volume mount wired
- [x] Wazuh logcollector tailing /var/log/suricata/eve.json
- [x] Custom Wazuh rules 100200–100215 with MITRE tags
- [x] anomaly_detector.py v2.1 — 4-tier MITRE ATT&CK auto-mapper
  - High: Wazuh rule tag pass-through
  - High: Suricata EVE category match
  - Medium: Wazuh rule group match
  - Low: Keyword match in description
- [x] OpenSearch indexer endpoint (wazuh-alerts-*) replacing broken /alerts API

## Phase 3 — NullByte Adversary Simulation ✅ COMPLETE
- [x] nullbyte.py — 5-module adversary simulation runner
- [x] Recon (nmap -sV) → ET SCAN Nmap User-Agent detected ✅
- [x] Web attack (nikto) → ET WEB_SERVER ColdFusion, CVE-2024-44000 detected ✅
- [x] Exfil sim (curl 5MB POST) → STREAM anomaly detected ✅
- [x] Brute force (hydra SSH) → SSH not exposed on ubuntu-web (gap documented)
- [x] Detection rate: 3/4 modules (75%) — pipeline validated end-to-end

## Phase 4 — Dashboard + Reporting 🔄 NEXT
- [ ] ATT&CK Navigator heatmap generation from anomaly_detector mitre_summary
- [ ] n8n workflow: Wazuh alert → Claude triage → Slack/email notification
- [ ] Executive PDF report generator from cycle JSON output
- [ ] NullByte SSH brute force fix (enable SSH on ubuntu-web or switch target)

## Phase 5 — Threat Intel Integration 📋 PLANNED
- [ ] AbuseIPDB / OTX enrichment on source IPs
- [ ] IOC feed ingest into Suricata custom rules
- [ ] Automated false positive suppression tuning
