#!/usr/bin/env python3
"""
GhostNet — anomaly_detector.py
Compares current Zeek conn.log against the saved baseline.
Flags deviations: new destinations, new ports, off-hours activity,
high-volume transfers, and sensitive port connections.

Author: Eliezer Fuentes
Project: GhostNet — Passive Network Behavior Baselining & Anomaly Detection
"""

import sqlite3
import os
import sys
import json
import argparse
from datetime import datetime, timezone


# ── CONFIG ────────────────────────────────────────────────────────────────────
DEFAULT_LOG_PATH = "/opt/zeek/logs/current/conn.log"
DEFAULT_DB_PATH  = "/root/ghostnet/baseline/ghostnet.db"
DEFAULT_OUT_PATH = os.path.expanduser("~/ghostnet/anomalies")

# Known homelab hosts
KNOWN_HOSTS = {
    "192.168.248.20":  "Wazuh Manager / AI Server (VM1)",
    "192.168.248.139": "Ubuntu Web Server (VM2)",
    "192.168.248.130": "Kali Linux (VM3)",
    "192.168.248.128": "Windows 11 (VM4)",
}

# Sensitive ports — always flag regardless of baseline
SENSITIVE_PORTS = {
    22:   "SSH",
    23:   "Telnet",
    445:  "SMB",
    3389: "RDP",
    4444: "Metasploit default",
    5555: "Android ADB / C2",
    6666: "C2 common",
    8080: "HTTP Alt",
    9001: "Tor",
    9050: "Tor SOCKS",
}
# Whitelisted destinations — never flag these
WHITELIST_IPS = {
    # NTP servers
    "91.189.91.112", "91.189.91.113",
    "185.125.190.121", "185.125.190.122", "185.125.190.123",
    "69.10.208.170",
    # DNS
    "1.1.1.1", "8.8.8.8", "8.8.4.4",
    # Ubuntu CDN / Canonical
    "91.189.91.47", "91.189.91.48",
    "192.168.248.1",    # VMware host gateway
    "192.168.248.254",  # VMware DHCP
}

WHITELIST_PORTS = {
    123,   # NTP — always normal
    67,    # DHCP — always normal
    68,    # DHCP client — always normal
    137,   # NetBIOS
    138,   # NetBIOS
    1900,  # SSDP/UPnP
    5353,  # mDNS
    5355,  # LLMNR
}

WHITELIST_DST_RANGES = (
    "185.125.",   # Ubuntu/Canonical
    "91.189.",    # Canonical
    "192.178.",   # Google internal CDN
    "224.0.0.",    # multicast
    "239.255.",    # multicast
    "142.250.", "142.251.",   # Google
    "173.194.", "172.217.",   # Google
    "151.101.",               # Fastly CDN
    "104.21.",                # Cloudflare
    "172.67.",                # Cloudflare
    "34.107.", "34.120.",     # Google Cloud
    "34.160.",                # Google Cloud
    "74.125.",                # Google
    "162.159.",               # Cloudflare
    "20.60.",      # Microsoft Azure
    "13.107.",     # Microsoft
    "140.82.",     # GitHub
    "140.83.",     # GitHub
    "50.218.",     # n8n/Automattic
    "108.156.",    # AWS CloudFront
    "172.64.",     # Cloudflare
    "104.26.",     # Cloudflare
    "160.79.",     # Zoom/misc
    "195.181.",    # misc CDN
    "34.49.",      # Google Cloud
    "34.111.",     # Google Cloud
) 
# Anomaly scoring weights (must add to 100)
SCORE_NEW_DESTINATION   = 30   # Never seen this dst IP before
SCORE_NEW_PORT          = 20   # Never seen this port from this host
SCORE_SENSITIVE_PORT    = 35   # Connection to a sensitive port
SCORE_OFF_HOURS         = 0    # Activity outside normal hours for this host
SCORE_HIGH_VOLUME       = 25   # Bytes transferred >> baseline average
SCORE_NEW_INTERNAL_HOST = 40   # Brand new host on the internal network

# Risk tiers
RISK_CRITICAL   = 70
RISK_HIGH       = 45
RISK_MEDIUM     = 25
RISK_LOW        = 10


# ── HELPERS ───────────────────────────────────────────────────────────────────
def get_risk_label(score: int) -> str:
    if score >= RISK_CRITICAL:
        return "🔴 CRITICAL"
    elif score >= RISK_HIGH:
        return "🟠 HIGH"
    elif score >= RISK_MEDIUM:
        return "🟡 MEDIUM"
    elif score >= RISK_LOW:
        return "🔵 LOW"
    return "⚪ INFO"


def host_label(ip: str) -> str:
    return KNOWN_HOSTS.get(ip, f"Unknown Host ({ip})")


# ── LOAD BASELINE ─────────────────────────────────────────────────────────────
def load_baseline(db_path: str) -> dict:
    """
    Load the saved baseline from SQLite into memory.
    Returns a dict with per-host behavioral profiles.
    """
    if not os.path.exists(db_path):
        print(f"[!] Baseline DB not found: {db_path}")
        print("[!] Run baseline_builder.py first.")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    baseline = {}

    # Load all known src→dst:port combinations
    cursor.execute("""
        SELECT src_ip, dst_ip, dst_port, protocol, connection_count,
               total_bytes, avg_duration
        FROM host_baseline
    """)
    for row in cursor.fetchall():
        src_ip, dst_ip, dst_port, proto, count, total_bytes, avg_dur = row
        if src_ip not in baseline:
            baseline[src_ip] = {
                "destinations": {},
                "active_hours": set(),
                "total_connections": 0,
                "avg_bytes_per_conn": 0,
            }
        key = f"{dst_ip}:{dst_port}:{proto}"
        baseline[src_ip]["destinations"][key] = {
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": proto,
            "count": count,
            "total_bytes": total_bytes,
            "avg_duration": avg_dur,
        }

    # Load known active hours per host
    cursor.execute("""
        SELECT src_ip, hour_of_day FROM host_hourly_profile
    """)
    for src_ip, hour in cursor.fetchall():
        if src_ip in baseline:
            baseline[src_ip]["active_hours"].add(hour)

    # Compute avg bytes per connection per host
    cursor.execute("""
        SELECT src_ip, SUM(total_bytes), SUM(connection_count)
        FROM host_baseline GROUP BY src_ip
    """)
    for src_ip, total_bytes, total_conns in cursor.fetchall():
        if src_ip in baseline and total_conns > 0:
            baseline[src_ip]["avg_bytes_per_conn"] = total_bytes / total_conns
            baseline[src_ip]["total_connections"] = total_conns

    conn.close()
    print(f"[+] Baseline loaded — {len(baseline)} known hosts")
    return baseline


# ── PARSE CONN LOG ────────────────────────────────────────────────────────────
def parse_conn_log(log_path: str) -> list:
    """Parse Zeek conn.log into a list of connection dicts."""
    if not os.path.exists(log_path):
        print(f"[!] Log file not found: {log_path}")
        sys.exit(1)

    connections = []
    fields = []

    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            values = line.split("\t")
            if len(values) != len(fields):
                continue
            connections.append(dict(zip(fields, values)))

    print(f"[+] Parsed {len(connections)} current connections")
    return connections


# ── ANOMALY DETECTION ─────────────────────────────────────────────────────────
def detect_anomalies(baseline: dict, connections: list) -> list:
    """
    Compare current connections against baseline.
    Returns a list of anomaly dicts, sorted by risk score descending.
    """
    anomalies = []
    # Track new internal hosts (IPs not in baseline at all)
    known_internal = set(baseline.keys())

    for record in connections:
        try:
            src_ip    = record.get("id.orig_h", "-")
            dst_ip    = record.get("id.resp_h", "-")
            dst_port  = int(record.get("id.resp_p", "0") or 0)
            proto     = record.get("proto", "-")
            ts_raw    = record.get("ts", "0")
            ts        = float(ts_raw) if ts_raw != "-" else 0.0
            orig_bytes_raw = record.get("orig_bytes", "0")
            orig_bytes = int(orig_bytes_raw) if orig_bytes_raw not in ("-", "", None) else 0
            resp_bytes_raw = record.get("resp_bytes", "0")
            resp_bytes = int(resp_bytes_raw) if resp_bytes_raw not in ("-", "", None) else 0
            total_bytes = orig_bytes + resp_bytes

            if src_ip == "-" or dst_ip == "-":
                continue

            # ── Whitelist check — skip known-good traffic ──
            if dst_ip in WHITELIST_IPS:
                continue
            if dst_port in WHITELIST_PORTS:
                continue
            if any(dst_ip.startswith(r) for r in WHITELIST_DST_RANGES):
                continue

            # Only analyze internal source IPs (homelab hosts)
            if not src_ip.startswith("192.168.248."):
                continue

            score = 0
            reasons = []

            try:
                hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
                ts_human = datetime.fromtimestamp(
                    ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                hour = 0
                ts_human = "unknown"

            # ── Check 1: New internal host (never seen before) ──
            if src_ip not in baseline:
                score += SCORE_NEW_INTERNAL_HOST
                reasons.append(
                    f"NEW INTERNAL HOST — {src_ip} has no baseline history"
                )
                # Add minimal baseline entry so we don't re-flag every connection
                baseline[src_ip] = {
                    "destinations": {},
                    "active_hours": set(),
                    "total_connections": 0,
                    "avg_bytes_per_conn": 0,
                }

            host_baseline = baseline[src_ip]
            conn_key = f"{dst_ip}:{dst_port}:{proto}"

            # ── Check 2: New destination never seen from this host ──
            if conn_key not in host_baseline["destinations"]:
                score += SCORE_NEW_DESTINATION
                reasons.append(
                    f"NEW DESTINATION — {src_ip} → {dst_ip}:{dst_port} "
                    f"[{proto}] never seen in baseline"
                )

            # ── Check 3: Sensitive port connection ──
            if dst_port in SENSITIVE_PORTS:
                score += SCORE_SENSITIVE_PORT
                reasons.append(
                    f"SENSITIVE PORT — {dst_port} "
                    f"({SENSITIVE_PORTS[dst_port]}) contacted by {src_ip}"
                )

            # ── Check 4: Off-hours activity ──
            known_hours = host_baseline.get("active_hours", set())
            if known_hours and hour not in known_hours:
                score += SCORE_OFF_HOURS
                known_str = ", ".join(
                    f"{h:02d}:00" for h in sorted(known_hours)
                )
                reasons.append(
                    f"OFF-HOURS — activity at {hour:02d}:00 UTC, "
                    f"baseline active hours: {known_str}"
                )

            # ── Check 5: High-volume transfer (3x baseline average) ──
            avg_bytes = host_baseline.get("avg_bytes_per_conn", 0)
            if avg_bytes > 0 and total_bytes > (avg_bytes * 3):
                score += SCORE_HIGH_VOLUME
                reasons.append(
                    f"HIGH VOLUME — {total_bytes} bytes transferred "
                    f"({total_bytes/avg_bytes:.1f}x baseline avg of "
                    f"{avg_bytes:.0f} bytes)"
                )

            # Only record if anomaly score is meaningful
            if score >= RISK_LOW and reasons:
                anomalies.append({
                    "timestamp":    ts_human,
                    "src_ip":       src_ip,
                    "src_label":    host_label(src_ip),
                    "dst_ip":       dst_ip,
                    "dst_port":     dst_port,
                    "protocol":     proto,
                    "total_bytes":  total_bytes,
                    "hour_utc":     hour,
                    "score":        score,
                    "risk":         get_risk_label(score),
                    "reasons":      reasons,
                })

        except Exception as e:
            print(f"[DEBUG] Exception on record: {e} | {record.get('id.orig_h')} → {record.get('id.resp_h')}:{record.get('id.resp_p')}")
            continue

    # Sort by score descending
    anomalies.sort(key=lambda x: x["score"], reverse=True)
    return anomalies


# ── REPORT ────────────────────────────────────────────────────────────────────
def print_report(anomalies: list):
    """Print anomaly report to terminal."""
    print("\n" + "="*65)
    print("  👻 GHOSTNET — ANOMALY DETECTION REPORT")
    print(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("="*65)

    if not anomalies:
        print("\n  ✅ No anomalies detected — traffic matches baseline.\n")
        print("="*65)
        return

    print(f"\n  ⚠️  {len(anomalies)} anomalies detected\n")

    for i, a in enumerate(anomalies, 1):
        print(f"  [{i}] {a['risk']}  (score: {a['score']})")
        print(f"      Time     : {a['timestamp']}")
        print(f"      Source   : {a['src_ip']} — {a['src_label']}")
        print(f"      Dest     : {a['dst_ip']}:{a['dst_port']} [{a['protocol']}]")
        print(f"      Bytes    : {a['total_bytes']}")
        print(f"      Findings :")
        for reason in a["reasons"]:
            print(f"               → {reason}")
        print()

    # Summary counts by risk tier
    critical = sum(1 for a in anomalies if a["score"] >= RISK_CRITICAL)
    high     = sum(1 for a in anomalies if RISK_HIGH <= a["score"] < RISK_CRITICAL)
    medium   = sum(1 for a in anomalies if RISK_MEDIUM <= a["score"] < RISK_HIGH)
    low      = sum(1 for a in anomalies if RISK_LOW <= a["score"] < RISK_MEDIUM)

    print("  " + "-"*40)
    print(f"  🔴 Critical : {critical}")
    print(f"  🟠 High     : {high}")
    print(f"  🟡 Medium   : {medium}")
    print(f"  🔵 Low      : {low}")
    print("="*65)


def save_json_report(anomalies: list, out_path: str):
    """Save anomalies as JSON for n8n/AI agent consumption."""
    os.makedirs(out_path, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(out_path, f"anomalies_{timestamp}.json")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_anomalies": len(anomalies),
        "anomalies": anomalies,
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[+] JSON report saved: {filename}")

    # ── POST to n8n webhook ──
    import urllib.request
    webhook_url = "http://localhost:5678/webhook/1d2b908d-5afa-4b9e-87c1-fe66bb335baa"
    payload = json.dumps(report).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[+] Webhook delivered — HTTP {resp.status}")
    except Exception as e:
        print(f"[!] Webhook delivery failed: {e}")

    # ── POST to Wazuh API ──
    try:
        token_resp = urllib.request.urlopen(
            urllib.request.Request(
                "https://localhost:55000/security/user/authenticate",
                headers={"Authorization": "Basic d2F6dWgtd3VpOk15UzNjcjM3UDQ1MHIuKi0="},
                method="POST"
            ), context=__import__('ssl').create_default_context(),
            timeout=10
        )
    except Exception:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        token_resp = urllib.request.urlopen(
            urllib.request.Request(
                "https://localhost:55000/security/user/authenticate",
                headers={"Authorization": "Basic d2F6dWgtd3VpOk15UzNjcjM3UDQ1MHIuKi0="},
                method="POST"
            ), context=ctx, timeout=10
        )
    token_data = json.loads(token_resp.read())
    wazuh_token = token_data["data"]["token"]

    summary = f"GhostNet: {len(anomalies)} anomalies — Critical:{sum(1 for a in anomalies if a['score']>=70)} High:{sum(1 for a in anomalies if 45<=a['score']<70)}"
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    wazuh_payload = json.dumps({"events": [summary]}).encode("utf-8")
    wazuh_req = urllib.request.Request(
        "https://localhost:55000/events",
        data=wazuh_payload,
        headers={"Authorization": f"Bearer {wazuh_token}", "Content-Type": "application/json"},
        method="POST"
    )
    urllib.request.urlopen(wazuh_req, context=ctx, timeout=10)
    print(f"[+] Wazuh alert sent: {summary}")

    return filename

# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="GhostNet Anomaly Detector — compare traffic to baseline"
    )
    parser.add_argument(
        "--log",
        default=DEFAULT_LOG_PATH,
        help=f"Path to Zeek conn.log (default: {DEFAULT_LOG_PATH})"
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
        help=f"Path to baseline SQLite DB (default: {DEFAULT_DB_PATH})"
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT_PATH,
        help=f"Directory for JSON anomaly reports (default: {DEFAULT_OUT_PATH})"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Save anomalies as JSON report for AI agent"
    )
    args = parser.parse_args()

    print("\n👻 GhostNet — Anomaly Detector")
    print(f"   Log      : {args.log}")
    print(f"   Baseline : {args.db}\n")

    # Load baseline
    baseline = load_baseline(args.db)

    # Parse current log
    connections = parse_conn_log(args.log)

    # Detect anomalies
    print("[+] Running anomaly detection...")
    anomalies = detect_anomalies(baseline, connections)
    print(f"[+] Detection complete — {len(anomalies)} anomalies found")

    # Print report
    print_report(anomalies)

    # Save JSON if requested
    if args.json and anomalies:
        save_json_report(anomalies, args.out)


if __name__ == "__main__":
    main()
