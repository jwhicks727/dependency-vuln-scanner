#!/usr/bin/env python3
"""
make_badge.py - Write a shields.io endpoint JSON from enriched findings.

The README embeds:
  https://img.shields.io/endpoint?url=<raw-github-url-to-data/badge.json>
and shields.io renders whatever this file says - so the badge updates
itself every time the nightly scan commits fresh data. A living security
status indicator, zero services, zero keys.

Usage: python make_badge.py enriched_findings.json data/badge.json
"""
import json
import sys
from pathlib import Path

src = Path(sys.argv[1] if len(sys.argv) > 1 else "enriched_findings.json")
dst = Path(sys.argv[2] if len(sys.argv) > 2 else "data/badge.json")

findings = json.loads(src.read_text(encoding="utf-8"))
kev = sum(1 for f in findings if str(f.get("kev", "")).lower() == "true")
total = len(findings)

if kev:
    color, msg = "red", f"{total} findings, {kev} KEV"
elif total:
    color, msg = "yellow", f"{total} findings, 0 KEV"
else:
    color, msg = "brightgreen", "clean"

dst.parent.mkdir(parents=True, exist_ok=True)
dst.write_text(json.dumps({
    "schemaVersion": 1, "label": "security scan",
    "message": msg, "color": color,
}, indent=2), encoding="utf-8")
print(f"badge -> {dst}: {msg} ({color})")
