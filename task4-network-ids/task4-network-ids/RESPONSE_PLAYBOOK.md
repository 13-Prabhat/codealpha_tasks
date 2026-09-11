# Intrusion Response Playbook

Suricata run as above is **IDS mode** (detect + alert only, `af-packet`
passive). This playbook covers what happens *after* an alert fires —
both an automated first response and the manual process behind it.

## 1. Automated response (script-driven)

`scripts/auto_block.py` implements a minimal, transparent auto-responder:

1. Tails `eve.json` for new `event_type: alert` entries.
2. Counts alerts per source IP within a sliding window.
3. If a single source IP crosses a threshold (default: 5 High/Medium
   alerts in 60 seconds), it:
   - Inserts a `DROP` rule for that IP via `iptables` (or `nft` if using
     nftables), blocking further traffic at the host firewall.
   - Logs the action, timestamp, triggering signature IDs, and alert
     count to `blocked_ips.log`.
4. Blocks are **temporary by default** (configurable TTL) and auto-expire,
   to avoid permanently locking out a spoofed or shared IP — a human
   should review and make it permanent if warranted.

This mirrors how fail2ban works for SSH brute-force, generalized to any
Suricata signature category. It is intentionally simple (a Python script
+ iptables) rather than a black box, so it's auditable for a course
submission.

**To convert Suricata itself from IDS to inline IPS** (actually drop
malicious packets in-path, not just alert), it would run in `af-packet`
IPS mode or via `nfqueue`, using `drop` instead of `alert` in the rule
action — noted here for completeness but out of scope for a single-VM
passive lab, since it requires the box to sit inline on the traffic path.

## 2. Manual triage checklist

For anything the automated responder doesn't act on (low-severity,
below threshold, or a rule you want a human judgment call on):

1. **Confirm it's real.** Pull the full `eve.json` record for the alert
   (`jq 'select(.event_type=="alert")' eve.json`) — check payload,
   src/dest IP+port, and whether the traffic pattern matches a known
   benign source (e.g. your own vulnerability scanner).
2. **Scope it.** Search `eve.json` for all activity from that source IP
   in the surrounding time window — was this one probe or a longer
   campaign (recon → exploit attempt → follow-up connection)?
3. **Contain.** If not already auto-blocked: block the IP
   (`sudo iptables -I INPUT -s <ip> -j DROP`), and if the alert indicates
   a possible compromised *internal* host (e.g. large outbound transfer,
   sid:9000032), isolate that host from the network instead of just
   blocking the remote IP.
4. **Preserve evidence.** Copy the relevant `eve.json` lines and, if
   available, the full pcap, to a separate evidence directory before any
   remediation touches the affected host.
5. **Remediate.** Patch/rotate credentials/rebuild the affected service
   depending on what the alert indicated (e.g. an SQLi alert against the
   app from Task 3 → confirm the fixed app is deployed, not the
   vulnerable one).
6. **Document.** Record: what fired, when, source, what was done, and
   whether it was a true or false positive — feed false positives back
   into rule tuning (§3).

## 3. Tuning to reduce noise

- Alerts that are consistently false positives should be scoped tighter
  (add a `content` match, a `threshold`, or a `$HOME_NET`/port
  restriction) rather than disabled outright, where possible.
- Track false-positive rate per signature; a rule that's wrong more than
  it's right is worse than no rule (alert fatigue causes real alerts to
  get missed).

## 4. Escalation

For anything indicating actual compromise (not just an attempt) —
successful auth bypass, RCE evidence, unexpected outbound C2-like
traffic — escalate immediately per your organization's incident
response plan rather than continuing routine triage.
