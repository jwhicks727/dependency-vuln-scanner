#!/usr/bin/env python3
"""
enrich_findings.py - Enrich SCA findings with real-world exploitability data.

Takes the scanner's findings (sca_scan.py output) and adds three columns
from two authoritative sources:

  epss_score      - probability (0-1) this CVE is exploited in the next
                    30 days. From FIRST.org's EPSS API, recomputed daily
                    from live observation data (honeypots, IDS telemetry).
  epss_percentile - where that score ranks among ALL scored CVEs (0-1).
                    A score of 0.02 sounds small until you learn it's the
                    88th percentile.
  kev             - "true" if CISA has CONFIRMED exploitation in the wild
                    (Known Exploited Vulnerabilities catalog). Not a
                    prediction - an observation.
  kev_date_added  - when CISA added it (empty if not in KEV).
  risk_tier       - computed triage tier (see tier logic below).

Why these beat raw CVSS severity for prioritization: CVSS scores how bad
exploitation WOULD be (theoretical). EPSS scores how likely exploitation
IS (empirical). KEV records that it already HAPPENED. You can't opt out
of having dependencies, so patch order should follow the threat, not
the theory.

Findings whose cve_id is a non-CVE fallback (GHSA-/PYSEC- ids from OSV,
where no CVE alias existed) cannot be enriched - both sources key on CVE
numbers. Those rows get empty EPSS fields and kev="false". That's honest:
missing data should look missing, not fabricated.

Usage:
    python enrich_findings.py                                # defaults
    python enrich_findings.py --input sca_findings.csv \
        --output-csv enriched_findings.csv \
        --output-json enriched_findings.json

Network hardening matches sca_scan.py: transient failures (429/5xx)
retry with exponential backoff; terminal failures abort loudly rather
than writing partially-enriched data that looks complete.
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

import requests

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT = 30
EPSS_BATCH_SIZE = 100   # EPSS accepts comma-separated CVE lists; stay polite
MAX_RETRIES = 4
BACKOFF_BASE_SECONDS = 1

# Risk tier thresholds. EPSS_HIGH is deliberately conservative: 0.10 means
# "a 1-in-10 chance of exploitation within 30 days," which for a school or
# small org is well past the point of urgency. These become the gate's
# policy knobs in the CI stage.
EPSS_HIGH = 0.10
EPSS_ELEVATED = 0.01


class TerminalRequestError(Exception):
    """A request failure that retrying will not fix."""


def _is_transient(status_code):
    return status_code == 429 or 500 <= status_code < 600


def _get_with_retries(url, params=None):
    """GET with the same transient/terminal split as sca_scan.py."""
    attempt = 0
    while True:
        try:
            resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return resp
        except requests.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else None
            if code is None or not _is_transient(code):
                raise TerminalRequestError(f"HTTP {code}: {exc}") from exc
            attempt += 1
            if attempt >= MAX_RETRIES:
                raise TerminalRequestError(f"retries exhausted at HTTP {code}") from exc
            time.sleep(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))
        except requests.RequestException as exc:
            attempt += 1
            if attempt >= MAX_RETRIES:
                raise TerminalRequestError(f"network failure, retries exhausted: {exc}") from exc
            time.sleep(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))


def fetch_epss(cve_ids):
    """Fetch EPSS scores for a list of CVE ids.

    Returns {cve_id: (score, percentile)} as floats. CVEs unknown to EPSS
    (very new, or malformed) simply won't appear in the result dict.
    """
    scores = {}
    ids = sorted(set(cve_ids))
    for i in range(0, len(ids), EPSS_BATCH_SIZE):
        batch = ids[i:i + EPSS_BATCH_SIZE]
        resp = _get_with_retries(EPSS_URL, params={"cve": ",".join(batch)})
        for row in resp.json().get("data", []):
            try:
                scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue  # skip malformed rows rather than corrupt the join
        time.sleep(0.2)  # polite pause between batches
    return scores


def fetch_kev():
    """Download CISA's KEV catalog.

    Returns {cve_id: date_added}. ~1,300 entries, one request.
    """
    resp = _get_with_retries(KEV_URL)
    catalog = resp.json()
    kev = {}
    for vuln in catalog.get("vulnerabilities", []):
        cve = vuln.get("cveID", "")
        if cve:
            kev[cve] = vuln.get("dateAdded", "")
    return kev


def risk_tier(kev_hit, epss_score):
    """Compute the triage tier for one finding.

    ACT NOW   - confirmed exploited (KEV), no debate left to have
    HIGH      - >= 10% chance of exploitation in the next 30 days
    ELEVATED  - >= 1%: above the noise floor, worth scheduling
    LOW       - scored, but down in the noise
    UNSCORED  - no CVE id, or EPSS has no data for it
    """
    if kev_hit:
        return "ACT NOW"
    if epss_score is None:
        return "UNSCORED"
    if epss_score >= EPSS_HIGH:
        return "HIGH"
    if epss_score >= EPSS_ELEVATED:
        return "ELEVATED"
    return "LOW"


def enrich(findings, epss_scores, kev_catalog):
    """Join EPSS + KEV data onto findings, in place. Returns the list."""
    for row in findings:
        cve = row.get("cve_id", "")
        is_real_cve = cve.upper().startswith("CVE-")

        epss = epss_scores.get(cve) if is_real_cve else None
        kev_hit = is_real_cve and cve in kev_catalog

        row["epss_score"] = f"{epss[0]:.5f}" if epss else ""
        row["epss_percentile"] = f"{epss[1]:.5f}" if epss else ""
        row["kev"] = "true" if kev_hit else "false"
        row["kev_date_added"] = kev_catalog.get(cve, "") if kev_hit else ""
        row["risk_tier"] = risk_tier(kev_hit, epss[0] if epss else None)
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Enrich SCA findings with EPSS scores and CISA KEV status."
    )
    parser.add_argument("--input", default="sca_findings.csv")
    parser.add_argument("--output-csv", default="enriched_findings.csv")
    parser.add_argument("--output-json", default="enriched_findings.json")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        sys.exit(f"Input file not found: {input_path.resolve()}")

    with open(input_path, newline="", encoding="utf-8") as f:
        findings = list(csv.DictReader(f))

    if not findings:
        print("No findings in input - writing empty outputs.")

    real_cves = sorted({
        r["cve_id"] for r in findings
        if r.get("cve_id", "").upper().startswith("CVE-")
    })
    print(f"Loaded {len(findings)} findings ({len(real_cves)} unique CVE ids).")

    print("Fetching EPSS scores...")
    try:
        epss_scores = fetch_epss(real_cves) if real_cves else {}
    except TerminalRequestError as exc:
        sys.exit(f"EPSS fetch failed - aborting rather than writing "
                 f"partially-enriched data: {exc}")
    print(f"  EPSS returned scores for {len(epss_scores)} of {len(real_cves)} CVEs.")

    print("Fetching CISA KEV catalog...")
    try:
        kev_catalog = fetch_kev()
    except TerminalRequestError as exc:
        sys.exit(f"KEV fetch failed - aborting rather than writing "
                 f"partially-enriched data: {exc}")
    print(f"  KEV catalog contains {len(kev_catalog)} confirmed-exploited CVEs.")

    enrich(findings, epss_scores, kev_catalog)

    kev_count = sum(1 for r in findings if r["kev"] == "true")
    tiers = {}
    for r in findings:
        tiers[r["risk_tier"]] = tiers.get(r["risk_tier"], 0) + 1

    fieldnames = list(findings[0].keys()) if findings else []
    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"\nDone. {len(findings)} enriched findings written to:")
    print(f"  {Path(args.output_csv).resolve()}")
    print(f"  {Path(args.output_json).resolve()}")
    print(f"  KEV hits: {kev_count}")
    print("  Tiers: " + ", ".join(f"{k}: {v}" for k, v in sorted(tiers.items())))


if __name__ == "__main__":
    main()
