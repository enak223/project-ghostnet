#!/usr/bin/env python3
"""
GhostNet — ATT&CK Navigator Heatmap Generator
Reads anomaly_detector cycle JSON → outputs ATT&CK Navigator layer file

Author: Elie Fuentes (enak223)
Usage: python3 navigator_heatmap.py ghostnet_anomaly_cycle_1.json
"""

import json, sys, glob
from datetime import datetime
from pathlib import Path
from collections import defaultdict

LAYER_TEMPLATE = {
    "name": "GhostNet Detection Coverage",
    "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Auto-generated from GhostNet anomaly_detector MITRE mappings",
    "filters": {"platforms": ["Windows","Linux","Network"]},
    "sorting": 3,
    "layout": {"layout": "side", "aggregateFunction": "max",
                "showID": True, "showName": True},
    "hideDisabled": False,
    "techniques": [],
    "gradient": {
        "colors": ["#ffffff", "#ff6666", "#cc0000"],
        "minValue": 0,
        "maxValue": 10
    },
    "legendItems": [
        {"label": "1-2 hits", "color": "#ffcccc"},
        {"label": "3-5 hits", "color": "#ff6666"},
        {"label": "6+ hits", "color": "#cc0000"}
    ],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": True,
    "tacticRowBackground": "#1a1a2e",
    "selectTechniquesAcrossTactics": False,
    "selectSubtechniquesWithParent": False
}

def load_reports(paths):
    alerts = []
    for p in paths:
        try:
            data = json.loads(Path(p).read_text())
            alerts.extend(data.get("alerts", []))
            print(f"[+] Loaded {len(data.get('alerts',[]))} alerts from {p}")
        except Exception as e:
            print(f"[!] Failed to load {p}: {e}")
    return alerts

def build_technique_map(alerts):
    counts = defaultdict(lambda: {"count": 0, "name": "", "tactic": "", 
                                   "url": "", "sources": set()})
    for alert in alerts:
        for m in alert.get("mapped_mitre", []):
            tid = m.get("technique_id", "")
            if not tid:
                continue
            counts[tid]["count"] += 1
            counts[tid]["name"] = m.get("technique_name", "")
            counts[tid]["tactic"] = m.get("tactic", "").lower().replace(" ", "-")
            counts[tid]["url"] = m.get("navigator_url", "")
            counts[tid]["sources"].add(alert.get("agent_name", "unknown"))
    return counts

def tactic_to_shortname(tactic):
    mapping = {
        "reconnaissance": "reconnaissance",
        "resource-development": "resource-development",
        "initial-access": "initial-access",
        "execution": "execution",
        "persistence": "persistence",
        "privilege-escalation": "privilege-escalation",
        "defense-evasion": "defense-evasion",
        "credential-access": "credential-access",
        "discovery": "discovery",
        "lateral-movement": "lateral-movement",
        "collection": "collection",
        "command-and-control": "command-and-control",
        "exfiltration": "exfiltration",
        "impact": "impact",
    }
    key = tactic.lower().replace(" ", "-")
    return mapping.get(key, key)

def score_to_color(count):
    if count >= 6: return "#cc0000"
    if count >= 3: return "#ff6666"
    if count >= 1: return "#ffcccc"
    return "#ffffff"

def generate_layer(technique_map):
    layer = dict(LAYER_TEMPLATE)
    layer["techniques"] = []
    layer["metadata"] = [
        {"name": "generated", "value": datetime.now().isoformat()},
        {"name": "tool", "value": "GhostNet anomaly_detector v2.1"},
        {"name": "total_techniques", "value": str(len(technique_map))}
    ]

    for tid, data in technique_map.items():
        count = data["count"]
        # Handle subtechniques (T1071.001 → techniqueID + subTechniqueOf)
        is_sub = "." in tid
        entry = {
            "techniqueID": tid,
            "tactic": tactic_to_shortname(data["tactic"]),
            "score": min(count, 10),
            "color": score_to_color(count),
            "comment": f"Hits: {count} | Agents: {', '.join(sorted(data['sources']))}",
            "enabled": True,
            "metadata": [
                {"name": "technique", "value": data["name"]},
                {"name": "hit_count", "value": str(count)},
                {"name": "url", "value": data["url"]}
            ],
            "links": [{"label": "ATT&CK", "url": data["url"]}] if data["url"] else [],
            "showSubtechniques": is_sub
        }
        layer["techniques"].append(entry)

    return layer

def print_summary(technique_map):
    print(f"\n{'='*60}")
    print("GHOSTNET ATT&CK COVERAGE SUMMARY")
    print(f"{'='*60}")
    print(f"{'Technique ID':<15} {'Count':>5}  {'Name':<45} Tactic")
    print("-"*100)
    for tid, d in sorted(technique_map.items(), key=lambda x: -x[1]["count"]):
        print(f"{tid:<15} {d['count']:>5}  {d['name']:<45} {d['tactic']}")
    print(f"{'='*60}")
    print(f"Total unique techniques: {len(technique_map)}")

def main():
    if len(sys.argv) < 2:
        # Auto-find all cycle reports
        paths = sorted(glob.glob("ghostnet_anomaly_cycle_*.json"))
        if not paths:
            paths = sorted(glob.glob("../ghostnet_anomaly_cycle_*.json"))
        if not paths:
            print("Usage: python3 navigator_heatmap.py <cycle_report.json> [...]")
            print("No ghostnet_anomaly_cycle_*.json found in current directory")
            sys.exit(1)
        print(f"[*] Auto-detected reports: {paths}")
    else:
        paths = sys.argv[1:]

    alerts = load_reports(paths)
    print(f"[*] Total alerts loaded: {len(alerts)}")

    technique_map = build_technique_map(alerts)
    print(f"[*] Unique MITRE techniques mapped: {len(technique_map)}")

    layer = generate_layer(technique_map)
    print_summary(technique_map)

    outfile = f"ghostnet_navigator_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    Path(outfile).write_text(json.dumps(layer, indent=2))
    print(f"\n[+] Navigator layer saved → {outfile}")
    print(f"    Upload to: https://mitre-attack.github.io/attack-navigator/")

if __name__ == "__main__":
    main()
