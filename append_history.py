#!/usr/bin/env python3
"""
append_history.py - Append one summary row per scan run to data/history.csv.

Each nightly run adds a single line: date, totals, KEV count, tier counts.
Over weeks this file becomes a time series - and the dashboard's
"findings over time" trend line reads straight from it. A dashboard
showing a LIVE trend from scheduled runs is the difference between
"a chart" and "a monitored system."

Usage: python append_history.py enriched_findings.json data/history.csv
"""
import csv
import json
import sys
from datetime import date
from pathlib import Path

src = Path(sys.argv[1] if len(sys.argv) > 1 else "enriched_findings.json")
dst = Path(sys.argv[2] if len(sys.argv) > 2 else "data/history.csv")

findings = json.loads(src.read_text(encoding="utf-8"))
tiers = {}
for f in findings:
    t = f.get("risk_tier", "UNSCORED")
    tiers[t] = tiers.get(t, 0) + 1

row = {
    "scan_date": date.today().isoformat(),
    "total_findings": len(findings),
    "kev_count": sum(1 for f in findings if str(f.get("kev", "")).lower() == "true"),
    "act_now": tiers.get("ACT NOW", 0),
    "high": tiers.get("HIGH", 0),
    "elevated": tiers.get("ELEVATED", 0),
    "low": tiers.get("LOW", 0),
    "unscored": tiers.get("UNSCORED", 0),
}

dst.parent.mkdir(parents=True, exist_ok=True)
is_new = not dst.exists()
with open(dst, "a", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(row.keys()))
    if is_new:
        w.writeheader()
    w.writerow(row)
print(f"history += {row}")
