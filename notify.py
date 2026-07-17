#!/usr/bin/env python3
"""
notify.py - Detect NEW findings since the last scan and build an alert email.

The delta logic is the whole point: a nightly email saying "you still have
52 findings" trains you to delete it. An email that arrives ONLY when
something NEW appeared - a fresh CVE disclosed against a dependency you
already had - is a signal worth reading. This is the "world changed even
though my code didn't" half of the two-trigger design.

Each finding in the email carries three actions:
  1. the advisory link (reference_url from the scan)
  2. its OSV database page
  3. a prefilled "create GitHub issue" link - one click files the
     remediation issue in the repo, title and body already written.

Usage:
  python notify.py --old data/enriched_findings.json \
                   --new enriched_findings.json \
                   --repo jwhicks727/dependency-vuln-scanner \
                   --out-html email.html --out-json new_findings.json
Exit code is always 0; the count of new findings goes to stdout and
$GITHUB_OUTPUT (new_count=N) so the workflow can skip the send step.
"""
import argparse
import html
import json
import os
import sys
import urllib.parse
from pathlib import Path

TIER_COLORS = {
    "ACT NOW": "#c0392b", "HIGH": "#e67e22",
    "ELEVATED": "#f1c40f", "LOW": "#7f8c8d", "UNSCORED": "#95a5a6",
}


def finding_key(f):
    """Identity of a finding: same vuln on same package = same finding."""
    return (f.get("package", ""), f.get("installed_version", ""), f.get("osv_id", ""))


def diff_findings(old, new):
    """Findings present in new but not in old."""
    old_keys = {finding_key(f) for f in old}
    return [f for f in new if finding_key(f) not in old_keys]


def issue_url(repo, f):
    """Prefilled GitHub new-issue link for one finding."""
    title = f"Vulnerability: {f.get('package')} {f.get('installed_version')} ({f.get('cve_id')})"
    body = (
        f"## Problem\n"
        f"`{f.get('package')} {f.get('installed_version')}` carries "
        f"{f.get('cve_id')} ({f.get('osv_id')}).\n\n"
        f"Severity: {f.get('severity') or 'n/a'} | "
        f"EPSS: {f.get('epss_score') or 'unscored'} | "
        f"KEV: {f.get('kev')} | Tier: {f.get('risk_tier')}\n\n"
        f"Advisory: {f.get('reference_url') or 'n/a'}\n\n"
        f"## Desired behavior\n"
        f"Upgrade to a fixed version (check the advisory) and re-scan clean.\n\n"
        f"## Acceptance criteria\n"
        f"- [ ] Package upgraded\n- [ ] Re-scan shows this finding resolved\n"
        f"- [ ] App still builds and passes tests\n"
    )
    q = urllib.parse.urlencode({"title": title, "body": body, "labels": "security"})
    return f"https://github.com/{repo}/issues/new?{q}"


def build_html(new_findings, repo, dashboard_url=""):
    rows = []
    for f in sorted(new_findings,
                    key=lambda x: (x.get("kev") != "true",
                                   -(float(x.get("epss_score") or 0)))):
        tier = f.get("risk_tier", "UNSCORED")
        color = TIER_COLORS.get(tier, "#95a5a6")
        osv = f.get("osv_id", "")
        links = []
        if f.get("reference_url"):
            links.append(f'<a href="{html.escape(f["reference_url"])}">advisory</a>')
        if osv:
            links.append(f'<a href="https://osv.dev/vulnerability/{html.escape(osv)}">OSV</a>')
        links.append(f'<a href="{html.escape(issue_url(repo, f))}">file issue</a>')
        rows.append(
            "<tr>"
            f'<td style="padding:6px 10px;"><b>{html.escape(f.get("package",""))}</b> '
            f'{html.escape(f.get("installed_version",""))}</td>'
            f'<td style="padding:6px 10px;">{html.escape(f.get("cve_id",""))}</td>'
            f'<td style="padding:6px 10px;color:#fff;background:{color};'
            f'text-align:center;">{html.escape(tier)}</td>'
            f'<td style="padding:6px 10px;">{html.escape(f.get("epss_score") or "-")}</td>'
            f'<td style="padding:6px 10px;">{" · ".join(links)}</td>'
            "</tr>"
        )
    dash = (f'<p><a href="{html.escape(dashboard_url)}">Open the triage dashboard</a></p>'
            if dashboard_url else "")
    return (
        '<div style="font-family:Segoe UI,Arial,sans-serif;max-width:760px;">'
        f"<h2>{len(new_findings)} new security finding"
        f"{'s' if len(new_findings) != 1 else ''}</h2>"
        "<p>New since the previous scheduled scan. Sorted KEV-first, then EPSS.</p>"
        '<table style="border-collapse:collapse;width:100%;font-size:14px;">'
        "<tr style='background:#2c3e50;color:#fff;'>"
        "<th style='padding:6px 10px;text-align:left;'>Package</th>"
        "<th style='padding:6px 10px;text-align:left;'>CVE</th>"
        "<th style='padding:6px 10px;'>Tier</th>"
        "<th style='padding:6px 10px;'>EPSS</th>"
        "<th style='padding:6px 10px;text-align:left;'>Act</th></tr>"
        + "".join(rows) + "</table>" + dash + "</div>"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", required=True, help="previous enriched_findings.json")
    ap.add_argument("--new", required=True, help="current enriched_findings.json")
    ap.add_argument("--repo", required=True, help="owner/name for issue links")
    ap.add_argument("--dashboard-url", default="")
    ap.add_argument("--out-html", default="email.html")
    ap.add_argument("--out-json", default="new_findings.json")
    args = ap.parse_args()

    old = []
    old_path = Path(args.old)
    if old_path.exists():  # first run ever: everything is "new"
        old = json.loads(old_path.read_text(encoding="utf-8"))
    new = json.loads(Path(args.new).read_text(encoding="utf-8"))

    delta = diff_findings(old, new)
    Path(args.out_json).write_text(json.dumps(delta, indent=2), encoding="utf-8")
    if delta:
        Path(args.out_html).write_text(
            build_html(delta, args.repo, args.dashboard_url), encoding="utf-8")

    print(f"new_count={len(delta)}")
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"new_count={len(delta)}\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
