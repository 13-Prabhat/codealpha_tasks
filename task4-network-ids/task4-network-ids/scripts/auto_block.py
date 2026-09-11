#!/usr/bin/env python3
"""
auto_block.py — minimal, auditable auto-responder for Suricata alerts.

Tails an eve.json log, counts alerts per source IP in a sliding window,
and fires `iptables -I INPUT -s <ip> -j DROP` when a source crosses a
threshold. Every action is logged to blocked_ips.log with a reason and
timestamp so it's reviewable, not a black box.

This is IDS-driven active response (a fail2ban-style pattern), not
inline IPS — Suricata itself is still only observing traffic; this
script is what actually changes the firewall state in reaction to what
it sees.

Usage:
    sudo python3 auto_block.py --eve /var/log/suricata/eve.json
    sudo python3 auto_block.py --eve sample_data/eve_sample.json --dry-run
"""

import argparse
import json
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

SEVERITY_WEIGHT = {1: 3, 2: 2, 3: 1}  # Suricata severity 1=high .. 3=low


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--eve", required=True, help="path to eve.json")
    p.add_argument("--threshold", type=int, default=5,
                    help="weighted alert score to trigger a block (default 5)")
    p.add_argument("--window", type=int, default=60,
                    help="sliding window in seconds (default 60)")
    p.add_argument("--block-ttl", type=int, default=900,
                    help="seconds before an auto-block is lifted (default 900 = 15 min)")
    p.add_argument("--dry-run", action="store_true",
                    help="log what WOULD be blocked, without touching iptables")
    p.add_argument("--follow", action="store_true",
                    help="keep tailing the file for new lines (live mode)")
    return p.parse_args()


def block_ip(ip: str, reason: str, dry_run: bool, log_fh):
    ts = datetime.now(timezone.utc).isoformat()
    if dry_run:
        action = "DRY-RUN would block"
    else:
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            action = "BLOCKED"
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            action = f"BLOCK-FAILED ({e})"
    line = f"{ts}\t{action}\t{ip}\t{reason}\n"
    log_fh.write(line)
    log_fh.flush()
    print(line, end="")


def unblock_ip(ip: str, dry_run: bool, log_fh):
    ts = datetime.now(timezone.utc).isoformat()
    if not dry_run:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
        )
    log_fh.write(f"{ts}\tUNBLOCKED (ttl expired)\t{ip}\t-\n")
    log_fh.flush()


def main():
    args = parse_args()
    alert_events = defaultdict(deque)   # ip -> deque[(timestamp, weight, sig)]
    blocked_until = {}                  # ip -> unblock timestamp

    with open("blocked_ips.log", "a") as log_fh, open(args.eve) as eve_fh:
        while True:
            line = eve_fh.readline()
            if not line:
                if not args.follow:
                    break
                time.sleep(1)
                continue

            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event_type") != "alert":
                continue

            src_ip = rec.get("src_ip")
            sig = rec.get("alert", {}).get("signature", "unknown")
            severity = rec.get("alert", {}).get("severity", 3)
            now = time.time()

            dq = alert_events[src_ip]
            dq.append((now, SEVERITY_WEIGHT.get(severity, 1), sig))
            while dq and now - dq[0][0] > args.window:
                dq.popleft()

            score = sum(w for _, w, _ in dq)
            if score >= args.threshold and src_ip not in blocked_until:
                sigs = ", ".join(sorted({s for _, _, s in dq}))
                block_ip(src_ip, f"score={score} sigs=[{sigs}]", args.dry_run, log_fh)
                blocked_until[src_ip] = now + args.block_ttl

            # expire old blocks
            for ip, until in list(blocked_until.items()):
                if now >= until:
                    unblock_ip(ip, args.dry_run, log_fh)
                    del blocked_until[ip]
                    alert_events[ip].clear()


if __name__ == "__main__":
    main()
