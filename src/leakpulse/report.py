"""Human-readable reporting (JSON output lives in the CLI)."""
from __future__ import annotations

from typing import List

from .rules import SEVERITY_RANK
from .scanner import Finding

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
SEVERITY_COLOR = {
    "high": "\033[31m",  # red
    "medium": "\033[33m",  # yellow
    "low": "\033[36m",  # cyan
}


def render_text(
    findings: List[Finding],
    files_scanned: int,
    commits_scanned: int,
    elapsed: float,
    color: bool = True,
) -> str:
    lines: List[str] = []
    for finding in findings:
        severity = finding.severity.upper()
        padded = f"{severity:<6}"
        if color:
            padded = f"{SEVERITY_COLOR[finding.severity]}{padded}{RESET}"
        lines.append(
            f"{padded} {finding.rule_id:<26} {finding.location:<44} "
            f"{finding.masked:<26} {DIM if color else ''}{finding.description}{RESET if color else ''}"
        )

    counts = {level: 0 for level in SEVERITY_RANK}
    for finding in findings:
        counts[finding.severity] += 1
    total = len(findings)

    if findings:
        lines.append("")
    if total:
        summary = (
            f"{total} potential secret{'s' if total != 1 else ''} found "
            f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low)"
        )
    else:
        summary = "No potential secrets found."
    scope = f"Scanned {files_scanned} file{'s' if files_scanned != 1 else ''}"
    if commits_scanned:
        scope += f" and {commits_scanned} commit{'s' if commits_scanned != 1 else ''}"
    scope += f" in {elapsed:.2f}s."

    if color and total:
        summary = f"{BOLD}{summary}{RESET}"
    lines.append(f"{summary} {scope}")
    return "\n".join(lines)
