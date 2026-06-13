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
- [x] anomaly_detector.py v2.2 — 4-tier MITRE ATT&CK auto-mapper
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
- [x] Brute force (hydra SSH) → SSH enabled on ubuntu-web, hydra triggers ET SSH invalid banner alerts ✅
- [x] Detection rate: 4/4 modules (100%) — pipeline validated end-to-end

## Phase 4 — Dashboard + Reporting ✅ COMPLETE
- [x] ATT&CK Navigator heatmap — 10 techniques across 6 tactics, upload-ready JSON layer
- [x] n8n workflow: Wazuh alert → Claude triage → output notification
- [x] Executive PDF report generator from cycle JSON output
- [x] NullByte SSH brute force fix (SSH enabled on ubuntu-web, hydra triggers ET SSH invalid banner alerts)

## Phase 5 — Threat Intel Integration ✅ COMPLETE
- [x] OTX threat intel feed — 36 pulses, 496 Suricata rules auto-generated
- [x] IOC feed deployed to Suricata (SID 9900000-9900495, 51251 total signatures)
- [x] Automated false positive suppression tuning via stratified alert sampling
