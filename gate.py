#!/usr/bin/env python3
"""
gate.py - CI security gate over enriched findings.

Reads enriched_findings.json and decides: does this build pass?

The policy (and the reasoning an interviewer will ask about):
  - KEV-listed  -> FAIL. CISA has observed real-world exploitation.
    There is no risk-acceptance argument left to have.
  - EPSS >= threshold (default 0.10, inclusive) -> FAIL. A 1-in-10
    chance of exploitation within 30 days is past the point of "later."
  - Everything else -> WARN. Reported in the summary, does not block.
    You cannot opt out of having dependencies; a gate that fails on
    every LOW would just get disabled. Gate on the threat, not the theory.
  - --prod-only downgrades dev-dependency breaches to warnings. Build
    tooling risk is real (supply chain) but it is not production attack
    surface; some teams gate the two differently. Off by default.

Exit codes:
  0 = pass (warnings allowed)   1 = gate breach   2 = usage/data error
CI needs to distinguish "policy failed the build" from "the tool broke."
"""

import argparse
import json
import os
import sys
from pathlib import Path

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2

DEFAULT_EPSS_THRESHOLD = 0.10


def parse_epss(raw):
    """EPSS arrives as a string; '' means 'no score exists'. Never invent 0.0."""
    if raw is None or str(raw).strip() == "":
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def evaluate(findings, epss_threshold=DEFAULT_EPSS_THRESHOLD, prod_only=False):
    """The pure policy function. Returns (breaches, warnings).

    breaches: list of (finding, [reason strings])
    warnings: list of findings that are reported but do not fail the build.
    Pure = no I/O, no exit codes - so it is trivially testable, and the CLI
    below stays a thin shell around it.
    """
    breaches = []
    warnings = []

    for finding in findings:
        reasons = []
        kev = str(finding.get("kev", "")).lower() == "true"
        epss = parse_epss(finding.get("epss_score"))

        if kev:
            reasons.append("KEV: confirmed exploited in the wild (CISA)")
        if epss is not None and epss >= epss_threshold:
            reasons.append(f"EPSS {epss:.5f} >= threshold {epss_threshold}")

        if reasons and prod_only and finding.get("dependency_type") != "prod":
            reasons = []  # downgrade: dev-only breach becomes a warning

        if reasons:
            breaches.append((finding, reasons))
        else:
            warnings.append(finding)

    return breaches, warnings


def format_summary(breaches, warnings, epss_threshold, markdown=False):
    """One summary renderer, two dialects (console / markdown)."""
    lines = []
    h = "## " if markdown else ""
    verdict = "GATE: FAIL" if breaches else "GATE: PASS"
    lines.append(f"{h}{verdict}")
    lines.append("")
    lines.append(f"Policy: fail on KEV or EPSS >= {epss_threshold}; warn otherwise.")
    lines.append(f"Breaches: {len(breaches)}  |  Warnings: {len(warnings)}")
    lines.append("")

    if breaches:
        lines.append("**Blocking findings:**" if markdown else "Blocking findings:")
        for finding, reasons in breaches:
            pkg = f"{finding.get('package')} {finding.get('installed_version')}"
            cve = finding.get("cve_id", "?")
            for r in reasons:
                bullet = "- " if markdown else "  - "
                lines.append(f"{bullet}{pkg} ({cve}): {r}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Security gate over enriched findings.")
    parser.add_argument("--input", default="enriched_findings.json")
    parser.add_argument("--epss-threshold", type=float, default=DEFAULT_EPSS_THRESHOLD)
    parser.add_argument("--prod-only", action="store_true",
                        help="Only prod dependencies can fail the build.")
    parser.add_argument("--markdown-summary", default=None,
                        help="Also write a markdown summary to this path.")
    args = parser.parse_args()

    path = Path(args.input)
    if not path.exists():
        print(f"gate: input not found: {path.resolve()}", file=sys.stderr)
        sys.exit(EXIT_ERROR)

    try:
        findings = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(findings, list):
            raise ValueError("expected a JSON list of findings")
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"gate: could not parse {path}: {exc}", file=sys.stderr)
        sys.exit(EXIT_ERROR)

    breaches, warnings = evaluate(
        findings, epss_threshold=args.epss_threshold, prod_only=args.prod_only)

    print(format_summary(breaches, warnings, args.epss_threshold, markdown=False))

    md = format_summary(breaches, warnings, args.epss_threshold, markdown=True)
    if args.markdown_summary:
        Path(args.markdown_summary).write_text(md, encoding="utf-8")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")

    sys.exit(EXIT_FAIL if breaches else EXIT_PASS)


if __name__ == "__main__":
    main()
