# 👻 Project GhostNet
### Passive Network Behavior Baselining & Anomaly Detection

> *"You can't hunt what you can't see. GhostNet sees everything — silently."*

[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)](https://github.com/enak223)
[![Stack](https://img.shields.io/badge/Stack-Zeek%20%7C%20Suricata%20%7C%20Wazuh%20%7C%20n8n%20%7C%20AI-blue?style=flat-square)](https://github.com/enak223)
[![Mode](https://img.shields.io/badge/Mode-Passive%20%7C%20Always--On-purple?style=flat-square)](https://github.com/enak223)
[![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)](LICENSE)

---

## 📌 Overview

**GhostNet** is a passive network behavior baselining and anomaly detection system built for homelabs and small environments. Unlike active scanners that probe your network, GhostNet watches silently — learning what normal looks like, then alerting when something deviates.

It answers three questions continuously:
- **What is normal?** — Zeek captures and logs all network flows to build a behavioral baseline: who talks to who, on what ports, at what times, with what data volumes.
- **What changed?** — An AI anomaly analyst compares live traffic patterns against the baseline and flags deviations: new connections, unusual protocols, off-hours activity, unexpected data transfers.
- **Is it a threat?** — Wazuh correlates GhostNet anomalies with host-level telemetry and MITRE ATT&CK mappings to separate noise from signal.

No active scanning. No network disruption. No footprint. Just eyes.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        GHOSTNET PIPELINE                            │
│                                                                     │
│  ┌──────────────┐      ┌──────────────┐     ┌──────────────────┐    │
│  │   CAPTURE    │────▶│   BASELINE   │────▶│    DETECT        │    │
│  │              │      │              │     │                  │    │
│  │ Zeek         │      │ Flow Logger  │     │ Anomaly Engine   │    │
│  │ Suricata IDS │      │ Conn Summary │     │ Deviation Scorer │    │
│  │ pcap mirror  │      │ JSON Storage │     │ Threshold Rules  │    │
│  └──────────────┘      └──────────────┘     └──────────────────┘    │
│                                                     │               │
│  ┌──────────────┐      ┌──────────────┐     ┌───────▼──────────┐    │
│  │  RESPOND     │◀────│  CORRELATE   │◀────│    ANALYZE       │    │
│  │              │      │              │     │                  │    │
│  │ Wazuh Alert  │      │ Wazuh SIEM   │     │ AI Analyst Agent │    │
│  │ n8n Action   │      │ MITRE Mapping│     │ Claude API       │    │
│  │ Slack/Email  │      │ Host Context │     │ Risk Narrative   │    │
│  └──────────────┘      └──────────────┘     └──────────────────┘    │
│                                                                     │
│         ┌────────────────────────────────────────┐                  │
│         │        ALWAYS-ON PASSIVE SENSOR        │                  │
│         │   Network tap on VMnet interface       │                  │
│         │   Zero active probes — silent ops      │                  │
│         └────────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Data Flow:**
```
Network Interface (promiscuous mode)
    └──▶ Zeek: parse traffic → conn.log / dns.log / http.log / ssl.log
             └──▶ Suricata: IDS signature matching → eve.json alerts
                      └──▶ Wazuh: ingest Zeek + Suricata logs
                               └──▶ n8n: hourly anomaly check workflow
                                        └──▶ AI Agent: baseline comparison + risk score
                                                 └──▶ Wazuh alert + Slack/email delivery
```

---

## 🧰 Tech Stack

| Component | Tool | Role |
|-----------|------|------|
| **Traffic Capture** | Zeek 6.x | Deep packet inspection, protocol parsing, flow logging |
| **IDS** | Suricata 7.x | Signature-based threat detection, rule matching |
| **SIEM** | Wazuh 4.x | Log ingestion, alert correlation, MITRE ATT&CK mapping |
| **Orchestration** | n8n (self-hosted) | Anomaly check scheduling, alert routing, workflow logic |
| **AI Agent** | Claude API | Behavioral analysis, anomaly narration, risk scoring |
| **Baseline Storage** | SQLite / JSON flat files | Lightweight flow baseline persistence |
| **Visualization** | Wazuh Dashboard | Real-time alert and flow visualization |
| **API Testing** | Postman | Manual workflow and API validation |
| **Host OS** | Ubuntu 22.04 | Primary GhostNet sensor host |
| **Virtualization** | VMware Workstation | Homelab multi-VM environment |

---

## ✨ Features

### 👁️ Passive Traffic Capture
- Zeek runs in promiscuous mode — captures all traffic on the VMnet interface without injecting packets
- Generates structured logs: `conn.log` (all flows), `dns.log`, `http.log`, `ssl.log`, `files.log`, `weird.log`
- Suricata runs alongside Zeek for signature-based detection using ET Open ruleset
- Zero active probing — completely invisible to monitored hosts

### 📊 Behavioral Baselining
- Builds per-host connection profiles: typical destination IPs, ports, protocols, bytes transferred, connection times
- Tracks daily and hourly traffic patterns to identify time-of-day baselines
- Baseline stored in lightweight SQLite DB — updated on a rolling 7-day window
- New hosts appearing on the network are flagged immediately (zero-baseline anomaly)

### 🤖 AI Anomaly Analyst Agent
- Claude agent receives hourly Zeek conn.log summaries and compares against stored baseline
- Scores each deviation using: magnitude of change + protocol sensitivity + time-of-day context + host criticality
- Generates plain-language narrative for each anomaly: *"Host 192.168.248.128 initiated 47 outbound connections to 10.0.0.x on port 4444 — no prior baseline for this destination. Pattern consistent with C2 beaconing (MITRE T1071)."*
- Maps detected behaviors to MITRE ATT&CK tactics automatically

### 🚨 Wazuh Integration
- Zeek and Suricata logs ship to Wazuh manager via Wazuh agent
- Custom decoder parses Zeek `conn.log` JSON format
- Custom rules fire on: new internal hosts, new external destinations, protocol anomalies, off-hours connections, high-volume transfers
- GhostNet AI findings injected back into Wazuh as synthetic alerts for unified dashboard view

### 🔔 Alerting
- Critical anomalies delivered via Slack webhook and SMTP email
- Alert includes: affected host, anomaly description, MITRE tactic, AI risk narrative, raw Zeek log excerpt
- n8n workflow throttles duplicate alerts (30-minute suppression window)

---

## 📁 Project Structure

```
ghostnet/
├── README.md
├── .env.example
│
├── zeek/
│   ├── site/
│   │   ├── local.zeek              # Local Zeek config — loaded scripts
│   │   └── ghostnet.zeek           # Custom GhostNet Zeek script
│   ├── scripts/
│   │   ├── new_host_detector.zeek  # Alert on first-seen internal hosts
│   │   ├── dns_tunneling.zeek      # Detect high-volume/entropy DNS queries
│   │   └── long_connection.zeek    # Flag unusually long-lived connections
│   └── deploy_zeek.sh              # Zeek installation and config script
│
├── suricata/
│   ├── suricata.yaml               # Suricata config (tuned for homelab)
│   ├── rules/
│   │   ├── ghostnet_custom.rules   # Custom Suricata rules
│   │   └── et_open_subset.rules    # Trimmed ET Open ruleset
│   └── deploy_suricata.sh
│
├── baseline/
│   ├── baseline_builder.py         # Reads Zeek conn.log → builds SQLite baseline
│   ├── anomaly_detector.py         # Compares current traffic to baseline
│   ├── schema.sql                  # SQLite schema for baseline storage
│   └── ghostnet.db                 # Baseline database (gitignored)
│
├── n8n/
│   ├── workflows/
│   │   ├── ghostnet_hourly.json    # Hourly anomaly check workflow
│   │   ├── ai_analyst_agent.json   # AI anomaly analyst sub-workflow
│   │   └── alert_delivery.json     # Alert routing workflow
│   └── credentials/
│       └── credentials.example.json
│
├── ai_agent/
│   ├── prompts/
│   │   ├── anomaly_analyst_system.txt  # System prompt: anomaly analysis
│   │   ├── mitre_mapper_prompt.txt     # Prompt: MITRE ATT&CK mapping
│   │   └── alert_narrative_prompt.txt  # Prompt: human-readable alert narrative
│   └── agent_runner.py
│
├── wazuh/
│   ├── custom_rules/
│   │   ├── ghostnet_rules.xml      # Custom Wazuh rules for GhostNet events
│   │   └── zeek_rules.xml          # Rules for Zeek log anomalies
│   ├── decoders/
│   │   ├── zeek_decoder.xml        # Decoder for Zeek conn.log JSON
│   │   └── suricata_decoder.xml    # Decoder for Suricata eve.json
│   └── ossec.conf.snippet          # Wazuh localfile config for Zeek/Suricata logs
│
├── postman/
│   ├── GhostNet_API_Tests.postman_collection.json
│   └── GhostNet_Environments.postman_environment.json
│
└── docs/
    ├── architecture.md
    ├── zeek_log_reference.md
    └── baseline_methodology.md
```

---

## ⚙️ Setup & Installation

### Prerequisites

```bash
# Core requirements
- Ubuntu 22.04 LTS (sensor host — dedicated VM recommended)
- Zeek 6.x
- Suricata 7.x
- Wazuh Agent 4.x (reporting to existing manager at 192.168.248.20)
- n8n self-hosted (v1.x+)
- Python 3.10+
- API key: Anthropic Claude
- Network interface in promiscuous mode
```

### 1. Clone the Repository

```bash
git clone https://github.com/enak223/ghostnet.git
cd ghostnet
```

### 2. Configure Environment Variables

```bash
cp .env.example .env
nano .env
```

```dotenv
# .env
ANTHROPIC_API_KEY=your_anthropic_key_here

# Network interface to monitor (check with: ip link show)
MONITOR_INTERFACE=ens33

# Zeek log directory
ZEEK_LOG_DIR=/opt/zeek/logs/current

# Wazuh
WAZUH_HOST=192.168.248.20
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=your_wazuh_api_password

# Alerting
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=your_app_password
ALERT_RECIPIENT=your@email.com

# Baseline settings
BASELINE_WINDOW_DAYS=7
ANOMALY_SCORE_THRESHOLD=6.5
```

### 3. Install and Configure Zeek

```bash
# Install Zeek
sudo bash zeek/deploy_zeek.sh

# Or manually:
sudo apt install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev
# Follow: https://docs.zeek.org/en/master/install.html

# Copy GhostNet Zeek scripts
sudo cp zeek/site/ghostnet.zeek /opt/zeek/share/zeek/site/
sudo cp zeek/scripts/*.zeek /opt/zeek/share/zeek/site/

# Add to local.zeek
echo '@load ghostnet' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek

# Deploy and start
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl status
```

### 4. Install and Configure Suricata

```bash
sudo bash suricata/deploy_suricata.sh

# Or manually:
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt install -y suricata

# Copy GhostNet config and rules
sudo cp suricata/suricata.yaml /etc/suricata/suricata.yaml
sudo cp suricata/rules/ghostnet_custom.rules /etc/suricata/rules/

# Start Suricata on monitor interface
sudo systemctl enable suricata
sudo systemctl start suricata

# Verify running
sudo suricata --list-runmodes
sudo tail -f /var/log/suricata/eve.json
```

### 5. Set Interface to Promiscuous Mode

```bash
# Temporary (until reboot)
sudo ip link set ens33 promisc on

# Permanent (via systemd)
sudo tee /etc/systemd/network/10-promisc.link << EOF
[Match]
Name=ens33

[Link]
Promiscuous=yes
EOF

sudo systemctl restart systemd-networkd

# Verify
ip link show ens33 | grep PROMISC
```

### 6. Build Initial Baseline

```bash
pip install -r requirements.txt

# Run baseline builder against existing Zeek logs (needs 24–48h of data first)
python baseline/baseline_builder.py \
  --log-dir /opt/zeek/logs/current \
  --db baseline/ghostnet.db \
  --window-days 7

# Verify baseline populated
python baseline/anomaly_detector.py --test
```

### 7. Deploy Wazuh Rules and Decoders

```bash
# Copy to Wazuh manager (run on 192.168.248.20)
sudo cp wazuh/custom_rules/ghostnet_rules.xml \
    /var/ossec/etc/rules/ghostnet_rules.xml

sudo cp wazuh/custom_rules/zeek_rules.xml \
    /var/ossec/etc/rules/zeek_rules.xml

sudo cp wazuh/decoders/zeek_decoder.xml \
    /var/ossec/etc/decoders/zeek_decoder.xml

sudo cp wazuh/decoders/suricata_decoder.xml \
    /var/ossec/etc/decoders/suricata_decoder.xml

# Add Zeek/Suricata log paths to ossec.conf
# (Append the snippet from wazuh/ossec.conf.snippet)

sudo systemctl restart wazuh-manager
```

### 8. Import n8n Workflows

```bash
# Import via n8n UI or CLI
n8n import:workflow --input=n8n/workflows/ghostnet_hourly.json
n8n import:workflow --input=n8n/workflows/ai_analyst_agent.json
n8n import:workflow --input=n8n/workflows/alert_delivery.json
```

Configure the **Cron** node in `ghostnet_hourly.json`:
```
Schedule: 0 * * * *     (Every hour)
Timezone: America/New_York
```

---

## 🔧 Custom Wazuh Rules

```xml
<!-- wazuh/custom_rules/ghostnet_rules.xml -->
<group name="ghostnet,network_anomaly">

  <!-- New host detected on network — never seen before -->
  <rule id="100600" level="8">
    <decoded_as>ghostnet</decoded_as>
    <field name="event_type">new_host</field>
    <description>GhostNet: New host detected on network - $(src_ip) [no baseline]</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>ghostnet_discovery,new_asset</group>
  </rule>

  <!-- New external destination — host contacting IP with no prior baseline -->
  <rule id="100601" level="7">
    <decoded_as>ghostnet</decoded_as>
    <field name="event_type">new_destination</field>
    <description>GhostNet: $(src_ip) contacted new external destination $(dst_ip):$(dst_port) — no baseline</description>
    <group>ghostnet_anomaly</group>
  </rule>

  <!-- Off-hours connection — outside normal activity window -->
  <rule id="100602" level="7">
    <decoded_as>ghostnet</decoded_as>
    <field name="event_type">off_hours_connection</field>
    <description>GhostNet: Off-hours network activity from $(src_ip) to $(dst_ip) at $(event_time)</description>
    <group>ghostnet_anomaly,behavioral_anomaly</group>
  </rule>

  <!-- High-volume data transfer — exceeds baseline by 3x+ -->
  <rule id="100603" level="9">
    <decoded_as>ghostnet</decoded_as>
    <field name="event_type">high_volume_transfer</field>
    <description>GhostNet: High-volume transfer detected from $(src_ip) — $(bytes_sent) bytes ($(deviation_factor)x baseline)</description>
    <mitre>
      <id>T1048</id>
    </mitre>
    <group>ghostnet_anomaly,data_exfiltration</group>
  </rule>

  <!-- Potential C2 beaconing — periodic connections at regular intervals -->
  <rule id="100604" level="12">
    <decoded_as>ghostnet</decoded_as>
    <field name="event_type">beaconing_detected</field>
    <description>GhostNet: Possible C2 beaconing from $(src_ip) to $(dst_ip) — $(connection_count) connections at $(interval_seconds)s intervals</description>
    <mitre>
      <id>T1071</id>
      <id>T1571</id>
    </mitre>
    <group>ghostnet_critical,c2_beaconing</group>
    <options>alert_by_email</options>
  </rule>

  <!-- DNS anomaly — high query volume or entropy (possible tunneling) -->
  <rule id="100605" level="11">
    <decoded_as>ghostnet</decoded_as>
    <field name="event_type">dns_anomaly</field>
    <description>GhostNet: DNS anomaly from $(src_ip) — $(query_count) queries, avg entropy $(entropy_score) [possible tunneling]</description>
    <mitre>
      <id>T1071.004</id>
    </mitre>
    <group>ghostnet_critical,dns_tunneling</group>
    <options>alert_by_email</options>
  </rule>

  <!-- Port scan detected via Zeek — rapid multi-port connections -->
  <rule id="100606" level="10">
    <decoded_as>ghostnet</decoded_as>
    <field name="event_type">port_scan</field>
    <description>GhostNet: Port scan detected from $(src_ip) — $(port_count) unique ports in $(scan_window)s</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>ghostnet_critical,reconnaissance</group>
  </rule>

  <!-- Lateral movement — internal host contacting multiple internal hosts -->
  <rule id="100607" level="13">
    <decoded_as>ghostnet</decoded_as>
    <field name="event_type">lateral_movement</field>
    <description>GhostNet: Possible lateral movement — $(src_ip) contacted $(internal_host_count) internal hosts in $(time_window)s</description>
    <mitre>
      <id>T1021</id>
      <id>T1570</id>
    </mitre>
    <group>ghostnet_critical,lateral_movement</group>
    <options>alert_by_email</options>
  </rule>

  <!-- AI analyst flagged anomaly — catch-all for AI-detected deviations -->
  <rule id="100610" level="8">
    <decoded_as>ghostnet</decoded_as>
    <field name="event_type">ai_anomaly</field>
    <description>GhostNet AI: $(ai_finding) on $(src_ip) [risk score: $(risk_score)]</description>
    <group>ghostnet_ai_alert</group>
  </rule>

  <!-- GhostNet pipeline error -->
  <rule id="100699" level="6">
    <decoded_as>ghostnet</decoded_as>
    <field name="event_type">pipeline_error</field>
    <description>GhostNet: Pipeline error — $(error_message)</description>
    <group>ghostnet_error</group>
  </rule>

</group>
```

---

## 🤖 AI Anomaly Analyst Agent

The AI Anomaly Analyst receives hourly Zeek flow summaries and returns structured anomaly findings with MITRE ATT&CK mappings.

### System Prompt

```
You are a senior network security analyst specializing in behavioral anomaly detection and threat hunting.

You will receive a JSON object containing:
- "baseline": per-host traffic profiles (avg connections/hour, typical destinations, common ports, active hours)
- "current_window": Zeek conn.log summary for the last hour (source IP, destination IP, port, protocol, bytes, duration, connection count)
- "environment": homelab context (known hosts, their roles, expected behavior)

Your tasks:
1. Compare current_window traffic against baseline. Identify ALL meaningful deviations.
2. Score each anomaly 1–10 using: magnitude of deviation (40%), protocol sensitivity (30%), time-of-day context (20%), known attack pattern match (10%).
3. For each anomaly scoring 5+, map to the most likely MITRE ATT&CK tactic and technique.
4. Write a one-sentence plain-English narrative for each finding.
5. Return ONLY a JSON object matching the provided schema. No preamble, no markdown.
```

### Agent Input Schema

```json
{
  "analysis_window": "2025-01-12T03:00:00Z",
  "environment": {
    "known_hosts": {
      "192.168.248.20": "Wazuh Manager / AI Server",
      "192.168.248.139": "Ubuntu Web Server",
      "192.168.248.130": "Kali Linux",
      "192.168.248.128": "Windows 11 Workstation"
    }
  },
  "baseline": { ... },
  "current_window": { ... }
}
```

---

## 🏠 Homelab Environment

```
┌─────────────────────────────────────────────────────────┐
│             GHOSTNET HOMELAB — VMware Workstation       │
│                                                         │
│  VMnet: NAT / Host-Only (192.168.248.0/24)              │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │  VM 1: Ubuntu AI — GhostNet Sensor + n8n        │    │
│  │  IP: 192.168.248.20                             │    │
│  │  Role: Zeek sensor, Suricata IDS, n8n, Wazuh    │    │
│  │  Interface: ens33 (promiscuous mode)            │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │  VM 2: Ubuntu Web Server (Monitored)            │    │
│  │  IP: 192.168.248.139                            │    │
│  │  Role: Passively observed target                │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │  VM 3: Kali Linux (Attacker simulation)         │    │
│  │  IP: 192.168.248.130                            │    │
│  │  Role: Generate anomalous traffic for testing   │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │  VM 4: Windows 11 (Monitored)                   │    │
│  │  IP: 192.168.248.128                            │    │
│  │  Role: Passively observed target                │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

**Traffic visibility:** The GhostNet sensor on VM1 captures all VMnet traffic by running Zeek and Suricata on the shared VMnet interface in promiscuous mode — seeing all inter-VM communication without any configuration change on monitored VMs.

---

## 🔐 Security Notes

- GhostNet is **read-only** at the network level. It captures copies of packets and never injects traffic.
- API keys stored in `.env`, never committed to version control. `.env` in `.gitignore`.
- Zeek log files may contain sensitive network data — stored locally, never uploaded.
- The Suricata ruleset is trimmed to reduce noise in a homelab context. Full ET Open ruleset will generate excessive false positives on lab traffic.
- Baseline DB (`ghostnet.db`) is gitignored — it contains network topology information.
- **Authorized use only.** GhostNet must only be deployed on networks you own or have explicit written authorization to monitor.

---

## 🗺️ Roadmap

| Phase | Feature | Status |
|-------|---------|--------|
| v0.1 | Zeek install + conn.log generation | ✅ Complete |
| v0.1 | Suricata install + ET Open rules | 🔲 Planned |
| v0.2 | Baseline builder (SQLite) | ✅ Complete |
| v0.2 | Anomaly detector — threshold scoring | ✅ Complete |
| v0.3 | Wazuh Zeek + Suricata log ingestion | ✅ Complete |
| v0.3 | Custom Wazuh rules deployment | ✅ Complete |
| v0.4 | n8n hourly anomaly check workflow | ✅ Complete |
| v0.4 | AI Anomaly Analyst Agent (Claude) | ✅ Complete |
| v0.5 | MITRE ATT&CK auto-mapping | 🔲 Planned |
| v0.5 | Slack + email alert delivery | ✅ Complete |
| v1.0 | Wazuh dashboard custom views | 🔲 Future |
| v1.0 | Week-over-week baseline drift reporting | 🔲 Future |
| v1.1 | Kali-generated attack simulation test suite | ✅ Complete |
| v1.2 | GhostNet + NullByte unified risk dashboard | 🔲 Future |
| v1.3 | Encrypted baseline snapshots for forensics | 🔲 Future |

---

## 👤 Author

**Eliezer Fuentes** — Cybersecurity Professional

Threat Hunting | Vulnerability Management | SOC Automation | Offensive Security

[![GitHub](https://img.shields.io/badge/GitHub-enak223-181717?style=flat&logo=github)](https://github.com/enak223)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-eliezerfuentes-0A66C2?style=flat&logo=linkedin)](https://www.linkedin.com/in/eliezerfuentes/)

---

> *Silent. Passive. Always watching.*
