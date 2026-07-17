#!/usr/bin/env python3
"""
env_to_deps.py - Inventory the CURRENT Python environment as scanner input.

Why scan the environment instead of requirements.txt: the manifest lists
ranges and intentions; the environment is what's actually installed - the
same manifest-vs-lockfile lesson from npm, applied to Python. In CI this
runs right after `pip install`, so it captures exactly what the build used.

dependency_type is "unknown" here on purpose: a live environment can't
tell you which install line brought a package in. Honest over guessed.

Usage:  python env_to_deps.py [output.csv]
"""
import csv
import sys
from importlib.metadata import distributions

out = sys.argv[1] if len(sys.argv) > 1 else "self_deps.csv"
rows = []
for dist in distributions():
    name = dist.metadata.get("Name", "")
    version = dist.version or ""
    if name and version:
        rows.append((name, "PyPI", version, "unknown"))

rows.sort(key=lambda r: r[0].lower())
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["name", "ecosystem", "version", "dependency_type"])
    w.writerows(rows)
print(f"Wrote {len(rows)} installed packages to {out}")
