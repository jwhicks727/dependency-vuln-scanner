#!/usr/bin/env python3
"""
sca_scan.py - Software Composition Analysis scanner.

Reads a list of dependencies (name, ecosystem, version) and asks the
OSV.dev API which ones have known vulnerabilities, then writes a clean,
flat findings table to CSV.

This script does ONE job: turn a dependency list into a vulnerability table.
Enrichment (EPSS exploit-probability scores, CISA KEV flags, risk tiering)
happens downstream in Power BI. Keeping that boundary sharp is what makes
the whole pipeline easy to reason about and easy to demo.

Usage:
    python sca_scan.py
    python sca_scan.py --input dependencies.csv --output sca_findings.csv
"""

import argparse
import csv
import sys
import time
from pathlib import Path

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 30   # seconds; fail loudly instead of hanging forever
POLITE_DELAY = 0.1     # seconds between calls; be a good API citizen

# The columns our findings table will have. Power BI reads this header,
# so the order and names here define the shape of everything downstream.
FIELDNAMES = [
    "package",
    "ecosystem",
    "installed_version",
    "cve_id",
    "osv_id",
    "summary",
    "severity",
    "cvss_vector",
    "published",
    "modified",
    "aliases",
    "reference_url",
]


def query_osv(name, ecosystem, version):
    """Ask OSV: 'are there known vulns for this exact package version?'

    Returns a list of vulnerability records (empty list if the package
    version is clean). Note: OSV paginates only when a single package has
    more than 1,000 vulns - none of ours do, so we keep this simple.
    """
    payload = {
        "version": version,
        "package": {"name": name, "ecosystem": ecosystem},
    }
    resp = requests.post(OSV_QUERY_URL, json=payload, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return resp.json().get("vulns", [])


def pick_cve(vuln):
    """Prefer a CVE id - EPSS and KEV are both keyed on CVE numbers.

    If there is no CVE alias, fall back to OSV's own id (e.g. a GHSA or
    PYSEC id) so every finding still has a unique identifier.
    """
    for alias in vuln.get("aliases", []):
        if alias.upper().startswith("CVE-"):
            return alias
    return vuln.get("id", "")


def pick_severity(vuln):
    """Grab a human-readable severity label (HIGH / CRITICAL / ...) if present.

    GitHub advisories expose this under database_specific.severity. Not every
    source provides it, so this is best-effort - Power BI will compute its own
    risk tier from EPSS anyway.
    """
    db = vuln.get("database_specific", {})
    if isinstance(db, dict) and db.get("severity"):
        return str(db["severity"]).upper()
    return ""


def pick_cvss_vector(vuln):
    """Return the first CVSS vector string, if any (e.g. CVSS:3.1/AV:N/...)."""
    for sev in vuln.get("severity", []):
        if sev.get("score"):
            return sev["score"]
    return ""


def first_reference(vuln):
    """Return the first advisory/reference URL so a row links back to detail."""
    refs = vuln.get("references", [])
    if refs:
        return refs[0].get("url", "")
    return ""


def flatten(name, ecosystem, version, vuln):
    """Turn one nested OSV vuln record into one flat CSV row (a dict)."""
    return {
        "package": name,
        "ecosystem": ecosystem,
        "installed_version": version,
        "cve_id": pick_cve(vuln),
        "osv_id": vuln.get("id", ""),
        "summary": (vuln.get("summary") or "").strip().replace("\n", " "),
        "severity": pick_severity(vuln),
        "cvss_vector": pick_cvss_vector(vuln),
        "published": vuln.get("published", ""),
        "modified": vuln.get("modified", ""),
        "aliases": "; ".join(vuln.get("aliases", [])),
        "reference_url": first_reference(vuln),
    }


def read_dependencies(path):
    """Read the input CSV into a list of (name, ecosystem, version) tuples."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            name = (row.get("name") or "").strip()
            if not name:
                continue  # skip blank lines
            rows.append((
                name,
                (row.get("ecosystem") or "").strip(),
                (row.get("version") or "").strip(),
            ))
        return rows


def main():
    parser = argparse.ArgumentParser(
        description="Scan a dependency list against the OSV.dev vulnerability database."
    )
    parser.add_argument("--input", default="dependencies.csv",
                        help="CSV of dependencies to scan (default: dependencies.csv)")
    parser.add_argument("--output", default="sca_findings.csv",
                        help="Where to write findings (default: sca_findings.csv)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        sys.exit(f"Input file not found: {input_path.resolve()}")

    deps = read_dependencies(input_path)
    print(f"Scanning {len(deps)} dependencies against OSV.dev...\n")

    findings = []
    for name, ecosystem, version in deps:
        label = f"{name} {version} ({ecosystem})"
        try:
            vulns = query_osv(name, ecosystem, version)
        except requests.RequestException as exc:
            print(f"  ERROR  {label} - request failed: {exc}")
            continue

        if vulns:
            print(f"  VULN   {label} - {len(vulns)} finding(s)")
            for vuln in vulns:
                findings.append(flatten(name, ecosystem, version, vuln))
        else:
            print(f"  clean  {label}")

        time.sleep(POLITE_DELAY)

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(findings)

    out = Path(args.output).resolve()
    print(f"\nDone. {len(findings)} findings from {len(deps)} packages written to:\n  {out}")


if __name__ == "__main__":
    main()
