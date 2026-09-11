#!/usr/bin/env bash
# =============================================================================
# simulate_traffic.sh — generates traffic patterns that should trip the
# custom rules in rules/local.rules. Run FROM a second lab machine/VM
# against a TARGET you own/control, on an isolated lab network only.
#
# Usage: ./simulate_traffic.sh <target_ip> [flask_port]
# =============================================================================
set -euo pipefail

TARGET="${1:?Usage: $0 <target_ip> [flask_port]}"
PORT="${2:-5000}"

echo "[*] Target: $TARGET  (web app port: $PORT)"
echo "[*] Ensure Suricata is running and tailing eve.json/fast.log elsewhere."
read -rp "Press Enter to begin (Ctrl+C to abort) ..."

echo "[1/7] SYN scan (sid:9000001) ..."
command -v nmap >/dev/null && sudo nmap -sS -T4 -p 1-1000 "$TARGET" || echo "  nmap not installed, skipping"

echo "[2/7] ICMP ping sweep (sid:9000002) ..."
for i in $(seq 1 11); do ping -c1 -W1 "$TARGET" >/dev/null 2>&1 || true; done
echo "  sent 11 pings"

echo "[3/7] NULL scan (sid:9000003) ..."
command -v nmap >/dev/null && sudo nmap -sN -p 1-100 "$TARGET" || echo "  nmap not installed, skipping"

echo "[4/7] SSH brute-force pattern (sid:9000010) — 6 quick connection attempts ..."
for i in $(seq 1 6); do
  timeout 2 bash -c "echo > /dev/tcp/$TARGET/22" 2>/dev/null || true
done

echo "[5/7] SQL Injection pattern against /login (sid:9000020/9000021) ..."
curl -s -o /dev/null "http://$TARGET:$PORT/login" \
  --data "username=admin' OR '1'='1' -- &password=x" || true

echo "[6/7] XSS pattern against /search (sid:9000022) ..."
curl -s -o /dev/null "http://$TARGET:$PORT/search?q=<script>alert(1)</script>" || true

echo "[7/7] Path traversal pattern against /download (sid:9000024) ..."
curl -s -o /dev/null "http://$TARGET:$PORT/download?file=../../../../etc/passwd" || true

echo "[*] Done. On the monitoring box, check:"
echo "    grep LOCAL /var/log/suricata/fast.log | tail -20"
echo "    jq 'select(.event_type==\"alert\")' /var/log/suricata/eve.json | tail -50"
