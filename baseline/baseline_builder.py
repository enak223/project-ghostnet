#!/usr/bin/env python3
"""
GhostNet — baseline_builder.py
Reads Zeek conn.log and builds a per-host behavioral baseline in SQLite.

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
DEFAULT_DB_PATH  = os.path.expanduser("~/ghostnet/baseline/ghostnet.db")

# Known homelab hosts — used for asset labeling in reports
KNOWN_HOSTS = {
    "192.168.248.20":  "Wazuh Manager / AI Server (VM1)",
    "192.168.248.139": "Ubuntu Web Server (VM2)",
    "192.168.248.130": "Kali Linux (VM3)",
    "192.168.248.128": "Windows 11 (VM4)",
}

# Sensitive ports — connections to these get flagged in anomaly detection
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


# ── DATABASE SETUP ─────────────────────────────────────────────────────────────
def init_db(db_path: str) -> sqlite3.Connection:
    """Create the SQLite database and tables if they don't exist."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Per-host connection baseline
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS host_baseline (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip          TEXT NOT NULL,
            dst_ip          TEXT NOT NULL,
            dst_port        INTEGER,
            protocol        TEXT,
            service         TEXT,
            connection_count INTEGER DEFAULT 1,
            total_bytes     INTEGER DEFAULT 0,
            avg_duration    REAL DEFAULT 0,
            first_seen      TEXT,
            last_seen       TEXT,
            is_internal     INTEGER DEFAULT 0,
            is_sensitive_port INTEGER DEFAULT 0,
            UNIQUE(src_ip, dst_ip, dst_port, protocol)
        )
    """)

    # Per-host hourly activity profile
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS host_hourly_profile (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip      TEXT NOT NULL,
            hour_of_day INTEGER NOT NULL,
            conn_count  INTEGER DEFAULT 0,
            UNIQUE(src_ip, hour_of_day)
        )
    """)

    # Raw connection log (last 7 days rolling window)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS conn_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL,
            src_ip      TEXT,
            src_port    INTEGER,
            dst_ip      TEXT,
            dst_port    INTEGER,
            protocol    TEXT,
            service     TEXT,
            duration    REAL,
            orig_bytes  INTEGER,
            resp_bytes  INTEGER,
            conn_state  TEXT,
            ingested_at TEXT
        )
    """)

    # Build metadata
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS build_meta (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            built_at    TEXT,
            log_path    TEXT,
            lines_parsed INTEGER,
            hosts_found  INTEGER
        )
    """)

    conn.commit()
    print(f"[+] Database initialized: {db_path}")
    return conn


# ── ZEEK LOG PARSER ────────────────────────────────────────────────────────────
def parse_conn_log(log_path: str) -> list[dict]:
    """
    Parse Zeek conn.log (TSV format with # header lines).
    Returns a list of connection dicts.
    """
    if not os.path.exists(log_path):
        print(f"[!] Log file not found: {log_path}")
        sys.exit(1)

    connections = []
    fields = []

    print(f"[+] Parsing: {log_path}")

    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()

            # Skip empty lines and non-field comment lines
            if not line:
                continue

            # Extract field names from header
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue

            # Skip other comment lines
            if line.startswith("#"):
                continue

            # Parse data line
            values = line.split("\t")
            if len(values) != len(fields):
                continue

            record = dict(zip(fields, values))
            connections.append(record)

    print(f"[+] Parsed {len(connections)} connections")
    return connections


# ── BASELINE BUILDER ───────────────────────────────────────────────────────────
def build_baseline(conn: sqlite3.Connection, connections: list[dict]):
    """
    Process parsed connections and upsert into the baseline tables.
    """
    cursor = conn.cursor()
    ingested_at = datetime.now(timezone.utc).isoformat()
    hosts_seen = set()

    for record in connections:
        try:
            src_ip   = record.get("id.orig_h", "-")
            dst_ip   = record.get("id.resp_h", "-")
            src_port = int(record.get("id.orig_p", 0))
            dst_port_raw = record.get("id.resp_p", "0")
            dst_port = int(dst_port_raw) if dst_port_raw != "-" else 0
            proto    = record.get("proto", "-")
            service  = record.get("service", "-")
            ts_raw   = record.get("ts", "0")
            ts       = float(ts_raw) if ts_raw != "-" else 0.0
            duration_raw = record.get("duration", "-")
            duration = float(duration_raw) if duration_raw != "-" else 0.0
            orig_bytes_raw = record.get("orig_bytes", "0")
            orig_bytes = int(orig_bytes_raw) if orig_bytes_raw not in ("-", "") else 0
            resp_bytes_raw = record.get("resp_bytes", "0")
            resp_bytes = int(resp_bytes_raw) if resp_bytes_raw not in ("-", "") else 0
            conn_state = record.get("conn_state", "-")

            # Skip invalid records
            if src_ip == "-" or dst_ip == "-":
                continue

            hosts_seen.add(src_ip)
            total_bytes = orig_bytes + resp_bytes
            is_internal = 1 if dst_ip.startswith("192.168.") else 0
            is_sensitive = 1 if dst_port in SENSITIVE_PORTS else 0

            # Convert timestamp to ISO datetime string
            try:
                ts_dt = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            except Exception:
                ts_dt = ingested_at

            # ── Insert raw conn log ──
            cursor.execute("""
                INSERT INTO conn_log
                    (ts, src_ip, src_port, dst_ip, dst_port, protocol,
                     service, duration, orig_bytes, resp_bytes, conn_state, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts, src_ip, src_port, dst_ip, dst_port, proto,
                  service, duration, orig_bytes, resp_bytes, conn_state, ingested_at))

            # ── Upsert host baseline ──
            cursor.execute("""
                INSERT INTO host_baseline
                    (src_ip, dst_ip, dst_port, protocol, service,
                     connection_count, total_bytes, avg_duration,
                     first_seen, last_seen, is_internal, is_sensitive_port)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(src_ip, dst_ip, dst_port, protocol)
                DO UPDATE SET
                    connection_count  = connection_count + 1,
                    total_bytes       = total_bytes + excluded.total_bytes,
                    avg_duration      = (avg_duration + excluded.avg_duration) / 2,
                    last_seen         = excluded.last_seen,
                    is_sensitive_port = excluded.is_sensitive_port
            """, (src_ip, dst_ip, dst_port, proto, service,
                  total_bytes, duration, ts_dt, ts_dt,
                  is_internal, is_sensitive))

            # ── Upsert hourly profile ──
            try:
                hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
            except Exception:
                hour = 0

            cursor.execute("""
                INSERT INTO host_hourly_profile (src_ip, hour_of_day, conn_count)
                VALUES (?, ?, 1)
                ON CONFLICT(src_ip, hour_of_day)
                DO UPDATE SET conn_count = conn_count + 1
            """, (src_ip, hour))

        except Exception as e:
            print(f"[!] Skipping record: {e} | {record}")
            continue

    conn.commit()
    return hosts_seen


# ── REPORT ─────────────────────────────────────────────────────────────────────
def print_summary(conn: sqlite3.Connection, hosts_seen: set):
    """Print a human-readable baseline summary."""
    cursor = conn.cursor()

    print("\n" + "="*60)
    print("  GHOSTNET — BASELINE SUMMARY")
    print("="*60)
    print(f"  Hosts observed: {len(hosts_seen)}")

    for host in sorted(hosts_seen):
        label = KNOWN_HOSTS.get(host, "Unknown Host")
        print(f"\n  [{host}] — {label}")

        # Top destinations
        cursor.execute("""
            SELECT dst_ip, dst_port, protocol, connection_count, total_bytes
            FROM host_baseline
            WHERE src_ip = ?
            ORDER BY connection_count DESC
            LIMIT 5
        """, (host,))
        rows = cursor.fetchall()

        print(f"    Top destinations (by connection count):")
        for row in rows:
            dst_ip, dst_port, proto, count, total_bytes = row
            sensitive = " ⚠️  SENSITIVE PORT" if dst_port in SENSITIVE_PORTS else ""
            print(f"      → {dst_ip}:{dst_port} [{proto}] "
                  f"— {count} conns, {total_bytes} bytes{sensitive}")

        # Hourly activity
        cursor.execute("""
            SELECT hour_of_day, conn_count
            FROM host_hourly_profile
            WHERE src_ip = ?
            ORDER BY hour_of_day
        """, (host,))
        hours = cursor.fetchall()
        if hours:
            active_hours = [f"{h:02d}:00({c})" for h, c in hours]
            print(f"    Active hours (UTC): {', '.join(active_hours)}")

    # Sensitive port connections
    cursor.execute("""
        SELECT src_ip, dst_ip, dst_port, protocol, connection_count
        FROM host_baseline
        WHERE is_sensitive_port = 1
        ORDER BY connection_count DESC
    """)
    sensitive_rows = cursor.fetchall()

    if sensitive_rows:
        print(f"\n  ⚠️  SENSITIVE PORT CONNECTIONS DETECTED:")
        for row in sensitive_rows:
            src, dst, port, proto, count = row
            port_name = SENSITIVE_PORTS.get(port, "unknown")
            print(f"    {src} → {dst}:{port} ({port_name}) [{proto}] — {count} conns")
    else:
        print(f"\n  ✅ No sensitive port connections detected")

    print("\n" + "="*60)


# ── MAIN ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="GhostNet Baseline Builder — parse Zeek conn.log into SQLite baseline"
    )
    parser.add_argument(
        "--log",
        default=DEFAULT_LOG_PATH,
        help=f"Path to Zeek conn.log (default: {DEFAULT_LOG_PATH})"
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
        help=f"Path to SQLite database (default: {DEFAULT_DB_PATH})"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print baseline summary after building"
    )
    args = parser.parse_args()

    print("\n👻 GhostNet — Baseline Builder")
    print(f"   Log : {args.log}")
    print(f"   DB  : {args.db}\n")

    # Init DB
    db_conn = init_db(args.db)

    # Parse Zeek log
    connections = parse_conn_log(args.log)

    # Build baseline
    print("[+] Building baseline...")
    hosts_seen = build_baseline(db_conn, connections)
    print(f"[+] Baseline updated — {len(hosts_seen)} hosts processed")

    # Write build metadata
    cursor = db_conn.cursor()
    cursor.execute("""
        INSERT INTO build_meta (built_at, log_path, lines_parsed, hosts_found)
        VALUES (?, ?, ?, ?)
    """, (datetime.now(timezone.utc).isoformat(), args.log,
          len(connections), len(hosts_seen)))
    db_conn.commit()

    # Print summary
    if args.summary:
        print_summary(db_conn, hosts_seen)

    db_conn.close()
    print("\n[+] Done. Baseline saved to:", args.db)


if __name__ == "__main__":
    main()
