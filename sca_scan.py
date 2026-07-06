#!/usr/bin/env python3
"""
sca_scan.py - Software Composition Analysis scanner.

Reads a list of dependencies (name, ecosystem, version) and asks the
OSV.dev API which ones have known vulnerabilities, then writes a clean,
flat findings table to CSV.

Network hardening (issue #1): OSV request failures are split into two
kinds. Transient failures (429 rate limiting, 5xx server errors) are
retried with exponential backoff, since the vulnerability status is
genuinely unknown and a retry will often succeed. Terminal failures
(other 4xx errors) are not retried - they indicate a request problem
that won't fix itself - and are logged and skipped immediately.
"""

import argparse
import csv
import sys
import time
from pathlib import Path

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 30
POLITE_DELAY = 0.1
MAX_RETRIES = 4          # attempts for a transient failure before giving up
BACKOFF_BASE_SECONDS = 1  # 1s, 2s, 4s, 8s...

FIELDNAMES = [
    "package", "ecosystem", "installed_version", "cve_id", "osv_id",
    "summary", "severity", "cvss_vector", "published", "modified",
    "aliases", "reference_url",
]


class TerminalRequestError(Exception):
    """A request failure that retrying will not fix (e.g. 400, 404)."""


def _is_transient(status_code):
    """429 (rate limited) and 5xx (server-side) are worth retrying."""
    return status_code == 429 or 500 <= status_code < 600


def query_osv(name, ecosystem, version):
    """Ask OSV: 'are there known vulns for this exact package version?'

    Retries transient failures (429, 5xx) with exponential backoff,
    honoring a Retry-After header when the server sends one. Terminal
    failures (other 4xx) raise immediately with no retry.

    Returns (vulns, status) where status is one of:
        "ok"               - succeeded, first try
        "ok-after-retry"    - succeeded after 1+ retries
        "retries-exhausted" - never succeeded, ran out of attempts
    Raises TerminalRequestError for non-retryable failures.
    """
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    attempt = 0

    while True:
        try:
            resp = requests.post(OSV_QUERY_URL, json=payload, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            status = "ok" if attempt == 0 else "ok-after-retry"
            return resp.json().get("vulns", []), status

        except requests.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else None

            if code is None or not _is_transient(code):
                # Terminal: a 404/400/etc won't be fixed by waiting.
                raise TerminalRequestError(f"HTTP {code}: {exc}") from exc

            attempt += 1
            if attempt >= MAX_RETRIES:
                return [], "retries-exhausted"

            # Respect Retry-After if the server sent one; else exponential backoff.
            retry_after = exc.response.headers.get("Retry-After") if exc.response is not None else None
            if retry_after is not None:
                try:
                    wait = float(retry_after)
                except ValueError:
                    wait = BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
            else:
                wait = BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))

            time.sleep(wait)

        except requests.RequestException as exc:
            # Network-level failure (DNS, connection, timeout) - also transient.
            attempt += 1
            if attempt >= MAX_RETRIES:
                return [], "retries-exhausted"
            time.sleep(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))


def pick_cve(vuln):
    for alias in vuln.get("aliases", []):
        if alias.upper().startswith("CVE-"):
            return alias
    return vuln.get("id", "")


def pick_severity(vuln):
    db = vuln.get("database_specific", {})
    if isinstance(db, dict) and db.get("severity"):
        return str(db["severity"]).upper()
    return ""


def pick_cvss_vector(vuln):
    for sev in vuln.get("severity", []):
        if sev.get("score"):
            return sev["score"]
    return ""


def first_reference(vuln):
    refs = vuln.get("references", [])
    return refs[0].get("url", "") if refs else ""


def flatten(name, ecosystem, version, vuln):
    return {
        "package": name, "ecosystem": ecosystem, "installed_version": version,
        "cve_id": pick_cve(vuln), "osv_id": vuln.get("id", ""),
        "summary": (vuln.get("summary") or "").strip().replace("\n", " "),
        "severity": pick_severity(vuln), "cvss_vector": pick_cvss_vector(vuln),
        "published": vuln.get("published", ""), "modified": vuln.get("modified", ""),
        "aliases": "; ".join(vuln.get("aliases", [])), "reference_url": first_reference(vuln),
    }


def read_dependencies(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = []
        for row in csv.DictReader(f):
            name = (row.get("name") or "").strip()
            if name:
                rows.append((name, (row.get("ecosystem") or "").strip(), (row.get("version") or "").strip()))
        return rows


def main():
    parser = argparse.ArgumentParser(description="Scan dependencies against OSV.dev.")
    parser.add_argument("--input", default="dependencies.csv")
    parser.add_argument("--output", default="sca_findings.csv")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        sys.exit(f"Input file not found: {input_path.resolve()}")

    deps = read_dependencies(input_path)
    print(f"Scanning {len(deps)} dependencies against OSV.dev...\n")

    findings = []
    retried_ok = terminal_skips = exhausted_skips = 0

    for name, ecosystem, version in deps:
        label = f"{name} {version} ({ecosystem})"
        try:
            vulns, status = query_osv(name, ecosystem, version)
        except TerminalRequestError as exc:
            print(f"  SKIP   {label} - terminal error, not retried: {exc}")
            terminal_skips += 1
            continue

        if status == "retries-exhausted":
            print(f"  SKIP   {label} - retried {MAX_RETRIES}x, still failing")
            exhausted_skips += 1
            continue

        tag = "VULN " if vulns else "clean"
        if status == "ok-after-retry":
            tag += " (recovered after retry)"
            retried_ok += 1

        if vulns:
            print(f"  {tag}  {label} - {len(vulns)} finding(s)")
            for vuln in vulns:
                findings.append(flatten(name, ecosystem, version, vuln))
        else:
            print(f"  {tag}  {label}")

        time.sleep(POLITE_DELAY)

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(findings)

    out = Path(args.output).resolve()
    print(f"\nDone. {len(findings)} findings from {len(deps)} packages written to:\n  {out}")
    print(f"  Recovered via retry: {retried_ok}  |  Terminal skips: {terminal_skips}  |  Retries exhausted: {exhausted_skips}")


if __name__ == "__main__":
    main()
