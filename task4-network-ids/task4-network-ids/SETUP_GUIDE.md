# Network Intrusion Detection System — Setup & Operation Guide
### Tool: Suricata (open-source, multi-threaded IDS/IPS/NSM engine)

> **Why Suricata over Snort for this lab:** Suricata is a drop-in
> conceptual replacement for Snort — it reads the same rule syntax — but
> adds native multi-threading, built-in JSON (`eve.json`) logging, and
> first-class protocol parsers (HTTP, TLS, DNS, etc.) that make the
> dashboard/analytics step in §5 far simpler. Everything here also maps
> directly onto Snort 3 if your instructor requires Snort specifically —
> the rule syntax and workflow are ~95% identical; differences are noted
> inline.

Run all of this inside a lab VM (e.g. Ubuntu 22.04/24.04, VirtualBox/VMware),
**never on a production network** without authorization — actively
monitoring traffic you don't own may be illegal in your jurisdiction.

---

## 1. Install Suricata

```bash
# Ubuntu/Debian
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install -y suricata suricata-update

# Confirm install
suricata --build-info | head -20
suricata -V
```

Snort 3 equivalent:
```bash
sudo apt install -y snort3
```

## 2. Identify your monitoring interface

```bash
ip a                     # note your active interface, e.g. eth0 / ens33
```

For a home/campus lab, monitor your VM's bridged/NAT interface. For a
real span/mirror port setup you'd point this at a switch mirror instead.

## 3. Configure

1. Back up the default config:
   ```bash
   sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
   ```
2. Merge in the settings from `config/suricata.yaml.snippet` (this repo) —
   at minimum set `HOME_NET`, the `af-packet.interface`, and the
   `eve-log` output block.
3. Copy the custom rules into place:
   ```bash
   sudo cp rules/local.rules /etc/suricata/rules/local.rules
   ```
4. Pull the community ruleset (Emerging Threats Open — thousands of
   maintained signatures for known malware, exploits, CVEs):
   ```bash
   sudo suricata-update
   sudo suricata-update list-sources        # see what feeds are available
   ```
5. **Validate the config before going live** — this is the single most
   useful command when something doesn't start:
   ```bash
   sudo suricata -T -c /etc/suricata/suricata.yaml -v
   ```

## 4. Run it

**Foreground (testing/lab demo):**
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

**As a background service (persistent monitoring):**
```bash
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

Watch alerts live:
```bash
sudo tail -f /var/log/suricata/fast.log        # human-readable one-liners
sudo tail -f /var/log/suricata/eve.json | jq .  # structured JSON, needs `jq`
```

## 5. Generate test traffic to prove the rules fire

From another machine/VM on the same network (or `127.0.0.1` if testing
locally against a loopback-bound service):

```bash
# Recon: trip the SYN-scan rule (sid:9000001)
nmap -sS -T4 <target_ip>

# Recon: ICMP sweep (sid:9000002)
for i in 1 2 3 4 5 6 7 8 9 10 11; do ping -c1 <target_ip>; done

# Web attack: SQLi pattern in URI (sid:9000020/9000021) — against
# the Task 3 vulnerable app if you're running it in the same lab:
curl "http://<target_ip>:5000/login?username=admin' OR '1'='1&password=x"

# Web attack: XSS pattern (sid:9000022)
curl "http://<target_ip>:5000/search?q=<script>alert(1)</script>"

# Web attack: path traversal (sid:9000024)
curl "http://<target_ip>:5000/download?file=../../../../etc/passwd"

# Insecure protocol (sid:9000040/9000041)
telnet <target_ip> 23
```
`scripts/simulate_traffic.sh` in this package automates the above.

Confirm each fires:
```bash
grep "LOCAL" /var/log/suricata/fast.log | tail -20
```

## 6. Continuous monitoring

- `systemctl status suricata` / journal logs for engine health.
- `eve.json` is the source of truth — ship it to a SIEM (ELK/Splunk) or
  parse it locally (see `scripts/dashboard_generator.py`, §7 below).
- Suricata's own `stats` output (every 30s per config) reports packet
  drop %, which matters most: a high drop rate means the engine can't
  keep up and is silently missing traffic — check this before trusting
  "no alerts" as "no attacks."

## 7. Response mechanisms

See `RESPONSE_PLAYBOOK.md` for the full manual + automated response
procedure. In short:
- **Automated:** `scripts/auto_block.py` tails `eve.json` and drops the
  source IP into an `iptables`/`nftables` deny rule when a high-severity
  alert fires repeatedly (a lightweight fail2ban-style responder).
- **Manual:** documented triage checklist for anything the automated
  responder doesn't cover (e.g. anything below the block threshold).

## 8. Visualization

`scripts/dashboard_generator.py` reads an `eve.json` alert log and
produces a static HTML dashboard (`dashboard.html`) with:
- Alerts-over-time chart
- Top source IPs
- Alert breakdown by category/signature
- Top targeted ports

Run it against your live log, or against the bundled
`sample_data/eve_sample.json` to see it work without a live capture:

```bash
python3 scripts/dashboard_generator.py --input sample_data/eve_sample.json --out dashboard.html
```

A pre-generated example (`dashboard_example.html` + `dashboard_charts.png`)
is included in this package so you can see the expected output immediately.

## 9. Package Contents

```
task4-network-ids/
├── SETUP_GUIDE.md              <- this file
├── RESPONSE_PLAYBOOK.md        <- manual + automated response procedures
├── rules/local.rules           <- custom detection rules (14 signatures)
├── config/suricata.yaml.snippet<- key config blocks to merge in
├── scripts/
│   ├── simulate_traffic.sh     <- generates test traffic to trip each rule
│   ├── auto_block.py           <- tails eve.json, auto-blocks repeat offenders
│   └── dashboard_generator.py  <- eve.json -> HTML/PNG dashboard
├── sample_data/eve_sample.json <- sample alert log (for offline dashboard demo)
├── dashboard_example.html      <- pre-rendered example dashboard
└── dashboard_charts.png        <- pre-rendered example chart image
```
