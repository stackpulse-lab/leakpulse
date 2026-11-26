"""Machine-readable and shareable reports: SARIF 2.1.0 and standalone HTML.

Both renderers are pure functions over scanner results, so they can be tested
without running a scan. Secrets are never written in full: results only carry
the masked ``Finding.masked`` value, exactly like the text and JSON reports.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import quote

from .rules import RULES, SEVERITY_RANK

PROJECT_URL = "https://github.com/stackpulse-lab/leakpulse"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}
ENTROPY_RULE = {
    "id": "high-entropy-string",
    "name": "High-entropy string",
    "description": "High-entropy string (possible secret)",
    "severity": "medium",
}


def _rule_catalog() -> List[Dict[str, str]]:
    """All rules in a stable order: regex rules first, then the heuristic."""
    catalog = [
        {
            "id": rule.id,
            "name": rule.id,
            "description": rule.description,
            "severity": rule.severity,
        }
        for rule in RULES
    ]
    catalog.append(ENTROPY_RULE)
    return catalog


def _counts(findings) -> Dict[str, int]:
    counts = {level: 0 for level in SEVERITY_RANK}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def _uri(path: str) -> str:
    """Percent-encode a repository-relative path for a SARIF artifact URI."""
    return quote(path.replace("\\", "/"), safe="/")


def render_sarif(
    findings,
    files_scanned: int,
    commits_scanned: int,
    elapsed: float,
    exit_code: int,
    version: str,
) -> str:
    catalog = _rule_catalog()
    index_by_id = {rule["id"]: index for index, rule in enumerate(catalog)}
    rules = [
        {
            "id": rule["id"],
            "name": rule["name"],
            "shortDescription": {"text": rule["description"]},
            "defaultConfiguration": {"level": SARIF_LEVEL[rule["severity"]]},
            "helpUri": f"{PROJECT_URL}#rules",
            "properties": {"severity": rule["severity"], "tags": ["security", "secrets"]},
        }
        for rule in catalog
    ]

    results = []
    for finding in findings:
        message = f"{finding.description} detected ({finding.masked})"
        properties = {"severity": finding.severity}
        if finding.commit:
            properties["commit"] = finding.commit
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": index_by_id.get(finding.rule_id, len(catalog) - 1),
                "level": SARIF_LEVEL[finding.severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _uri(finding.path)},
                            "region": {"startLine": max(1, finding.line)},
                        }
                    }
                ],
                "partialFingerprints": {"leakpulse/v1": finding.fingerprint},
                "properties": properties,
            }
        )

    payload = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LeakPulse",
                        "informationUri": PROJECT_URL,
                        "version": version,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "filesScanned": files_scanned,
                            "commitsScanned": commits_scanned,
                            "elapsedSeconds": round(elapsed, 3),
                            "exitCode": exit_code,
                        },
                    }
                ],
                "results": results,
                "properties": {"summary": _counts(findings)},
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


HTML_STYLE = """
:root { color-scheme: light dark; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
  "Helvetica Neue", Arial, "PingFang SC", "Microsoft YaHei", sans-serif;
  margin: 2rem auto; max-width: 1100px; padding: 0 1rem; line-height: 1.5; }
h1 { font-size: 1.5rem; margin-bottom: .25rem; }
.meta { color: #6b7280; font-size: .875rem; margin-bottom: 1.5rem; }
.cards { display: flex; flex-wrap: wrap; gap: .75rem; margin-bottom: 1.5rem; }
.card { border: 1px solid #d1d5db; border-radius: 8px; padding: .75rem 1rem; min-width: 7rem; }
.card .num { font-size: 1.5rem; font-weight: 600; display: block; }
.high .num { color: #b91c1c; }
.medium .num { color: #b45309; }
.low .num { color: #0e7490; }
table { border-collapse: collapse; width: 100%; font-size: .875rem; }
th, td { border-bottom: 1px solid #e5e7eb; padding: .5rem; text-align: left; vertical-align: top; }
th { background: #f9fafb; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
tr.sev-high td:first-child { border-left: 3px solid #b91c1c; }
tr.sev-medium td:first-child { border-left: 3px solid #b45309; }
tr.sev-low td:first-child { border-left: 3px solid #0e7490; }
footer { color: #6b7280; font-size: .8rem; margin-top: 2rem; }
"""


def render_html(
    findings,
    files_scanned: int,
    commits_scanned: int,
    elapsed: float,
    exit_code: int,
    version: str,
    generated_at: Optional[datetime] = None,
) -> str:
    moment = generated_at or datetime.now(timezone.utc)
    counts = _counts(findings)
    rows = []
    for finding in findings:
        location = html.escape(finding.location)
        rows.append(
            "<tr class=\"sev-{sev}\">"
            "<td><strong>{sev}</strong></td>"
            "<td><code>{rule}</code></td>"
            "<td><code>{location}</code></td>"
            "<td><code>{masked}</code></td>"
            "<td>{description}</td>"
            "</tr>".format(
                sev=html.escape(finding.severity),
                rule=html.escape(finding.rule_id),
                location=location,
                masked=html.escape(finding.masked),
                description=html.escape(finding.description),
            )
        )
    if rows:
        table = (
            "<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th>"
            "<th>Match (masked)</th><th>Description</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    else:
        table = "<p>No potential secrets found.</p>"

    scope = f"{files_scanned} file(s)"
    if commits_scanned:
        scope += f", {commits_scanned} commit(s)"
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LeakPulse audit report</title>
<style>{style}</style>
</head>
<body>
<h1>LeakPulse audit report</h1>
<p class="meta">LeakPulse {version} &middot; generated {generated} &middot; scanned {scope}
 &middot; {elapsed:.2f}s &middot; exit code {exit_code}</p>
<div class="cards">
<div class="card high"><span class="num">{high}</span>high</div>
<div class="card medium"><span class="num">{medium}</span>medium</div>
<div class="card low"><span class="num">{low}</span>low</div>
<div class="card"><span class="num">{total}</span>total</div>
</div>
{table}
<footer>Matches are masked; rotate any credential that this report identifies.
Generated locally by LeakPulse &mdash; no data was uploaded.</footer>
</body>
</html>
""".format(
        style=HTML_STYLE,
        version=html.escape(version),
        generated=html.escape(moment.strftime("%Y-%m-%d %H:%M:%S UTC")),
        scope=html.escape(scope),
        elapsed=elapsed,
        exit_code=exit_code,
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        total=len(findings),
        table=table,
    )
