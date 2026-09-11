#!/usr/bin/env python3
"""
dashboard_generator.py — turns a Suricata eve.json alert log into a
static HTML dashboard (+ PNG chart) for visualizing detected attacks.

Usage:
    python3 dashboard_generator.py --input /var/log/suricata/eve.json --out dashboard.html
    python3 dashboard_generator.py --input sample_data/eve_sample.json --out dashboard.html
"""

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def load_alerts(path):
    alerts = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event_type") == "alert":
                alerts.append(rec)
    return alerts


def build_charts(alerts, png_path):
    fig, axes = plt.subplots(2, 2, figsize=(12, 9))
    fig.suptitle("Suricata NIDS — Detected Attack Overview", fontsize=15, fontweight="bold")

    # 1. Alerts over time (by hour bucket)
    hour_counts = Counter()
    for a in alerts:
        ts = a.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour_counts[dt.strftime("%H:%M")] += 1
        except ValueError:
            continue
    times = sorted(hour_counts)
    axes[0, 0].plot(times, [hour_counts[t] for t in times], marker="o", markersize=3, color="#c0392b")
    axes[0, 0].set_title("Alerts Over Time")
    axes[0, 0].set_ylabel("Alert count")
    # Thin the x tick labels so they stay readable regardless of how many buckets there are
    max_ticks = 12
    step = max(1, len(times) // max_ticks)
    axes[0, 0].set_xticks(range(0, len(times), step))
    axes[0, 0].set_xticklabels([times[i] for i in range(0, len(times), step)], rotation=45, ha="right")

    # 2. Top source IPs
    src_counts = Counter(a.get("src_ip", "unknown") for a in alerts)
    top_src = src_counts.most_common(8)
    axes[0, 1].barh([s[0] for s in top_src][::-1], [s[1] for s in top_src][::-1], color="#2980b9")
    axes[0, 1].set_title("Top Source IPs")
    axes[0, 1].set_xlabel("Alert count")

    # 3. Alert breakdown by signature
    sig_counts = Counter(a.get("alert", {}).get("signature", "unknown") for a in alerts)
    top_sig = sig_counts.most_common(8)
    labels = [s[0][:35] + ("…" if len(s[0]) > 35 else "") for s in top_sig]
    axes[1, 0].barh(labels[::-1], [s[1] for s in top_sig][::-1], color="#8e44ad")
    axes[1, 0].set_title("Alerts by Signature")
    axes[1, 0].set_xlabel("Alert count")

    # 4. Targeted ports
    port_counts = Counter(a.get("dest_port", 0) for a in alerts)
    top_ports = port_counts.most_common(8)
    axes[1, 1].bar([str(p[0]) for p in top_ports], [p[1] for p in top_ports], color="#27ae60")
    axes[1, 1].set_title("Top Targeted Ports")
    axes[1, 1].set_xlabel("Port")
    axes[1, 1].set_ylabel("Alert count")

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig(png_path, dpi=130)
    plt.close(fig)

    return {
        "hour_counts": hour_counts,
        "src_counts": src_counts,
        "sig_counts": sig_counts,
        "port_counts": port_counts,
    }


def severity_label(sev):
    return {1: "High", 2: "Medium", 3: "Low"}.get(sev, "Unknown")


def build_html(alerts, stats, png_path, out_path):
    sev_counts = Counter(severity_label(a.get("alert", {}).get("severity", 3)) for a in alerts)

    rows = []
    for a in sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)[:50]:
        alert = a.get("alert", {})
        rows.append(
            f"<tr><td>{a.get('timestamp','')}</td><td>{a.get('src_ip','')}</td>"
            f"<td>{a.get('dest_ip','')}:{a.get('dest_port','')}</td>"
            f"<td>{severity_label(alert.get('severity',3))}</td>"
            f"<td>{alert.get('signature','')}</td>"
            f"<td>{alert.get('category','')}</td></tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Suricata NIDS Dashboard</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 24px;
          background: #0f1117; color: #e8e8ec; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .sub {{ color: #9aa0aa; margin-bottom: 24px; font-size: 13px; }}
  .cards {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .card {{ background: #181b24; border: 1px solid #2a2e3a; border-radius: 10px;
           padding: 16px 20px; min-width: 140px; }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card .lbl {{ font-size: 12px; color: #9aa0aa; text-transform: uppercase; letter-spacing: .04em; }}
  .high {{ color: #e74c3c; }} .medium {{ color: #f39c12; }} .low {{ color: #2ecc71; }}
  img {{ width: 100%; border-radius: 10px; border: 1px solid #2a2e3a; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #2a2e3a; }}
  th {{ color: #9aa0aa; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
  tr:hover {{ background: #181b24; }}
</style>
</head>
<body>
  <h1>Suricata NIDS Dashboard</h1>
  <div class="sub">Generated from eve.json &middot; {len(alerts)} total alerts</div>

  <div class="cards">
    <div class="card"><div class="num">{len(alerts)}</div><div class="lbl">Total Alerts</div></div>
    <div class="card"><div class="num high">{sev_counts.get('High',0)}</div><div class="lbl">High Severity</div></div>
    <div class="card"><div class="num medium">{sev_counts.get('Medium',0)}</div><div class="lbl">Medium Severity</div></div>
    <div class="card"><div class="num low">{sev_counts.get('Low',0)}</div><div class="lbl">Low Severity</div></div>
    <div class="card"><div class="num">{len(stats['src_counts'])}</div><div class="lbl">Unique Source IPs</div></div>
  </div>

  <img src="{png_path}" alt="alert charts">

  <h2 style="font-size:16px;">Recent Alerts</h2>
  <table>
    <tr><th>Time</th><th>Source</th><th>Destination</th><th>Severity</th><th>Signature</th><th>Category</th></tr>
    {''.join(rows)}
  </table>
</body>
</html>"""
    with open(out_path, "w") as f:
        f.write(html)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--out", default="dashboard.html")
    p.add_argument("--png", default="dashboard_charts.png")
    args = p.parse_args()

    alerts = load_alerts(args.input)
    if not alerts:
        print("No alert events found in input file.")
        return
    stats = build_charts(alerts, args.png)
    build_html(alerts, stats, args.png, args.out)
    print(f"Wrote {args.out} and {args.png} from {len(alerts)} alerts.")


if __name__ == "__main__":
    main()
