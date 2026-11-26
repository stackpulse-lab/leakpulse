"""Baseline support: fail CI only on secrets introduced after a snapshot.

A baseline stores the stable :attr:`~leakpulse.scanner.Finding.fingerprint`
values (SHA-256 over rule id, path and matched value) of findings that are
already known and accepted.  Only hashes are written, so committing a baseline
never commits a credential or even a partial one.

Fingerprints deliberately ignore the line number: moving an accepted finding
up or down a file keeps it suppressed, while changing the secret itself
(rotation) produces a new fingerprint and therefore a new finding.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set, Tuple

BASELINE_SCHEMA = "leakpulse-baseline/1"


class BaselineError(ValueError):
    """Raised when a baseline file is unreadable, malformed or unsafe."""


def fingerprints(findings: Iterable) -> List[str]:
    """Return sorted, de-duplicated fingerprints for a finding sequence."""
    return sorted({finding.fingerprint for finding in findings})


def build_baseline(findings: Iterable, tool_version: str, created_at: Optional[datetime] = None) -> dict:
    """Build the JSON-serialisable baseline document."""
    moment = created_at or datetime.now(timezone.utc)
    values = fingerprints(findings)
    return {
        "schema": BASELINE_SCHEMA,
        "tool": f"leakpulse {tool_version}",
        "created_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(values),
        "fingerprints": values,
    }


def write_baseline(path: Path, findings: Iterable, tool_version: str) -> int:
    """Write a baseline file and return the number of recorded fingerprints."""
    document = build_baseline(findings, tool_version)
    path = Path(path)
    try:
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot write {path}: {exc}") from exc
    return document["count"]


def load_baseline(path: Path) -> Set[str]:
    """Load and validate a baseline file, returning the accepted fingerprints."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot read {path}: {exc}") from exc
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise BaselineError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise BaselineError(f"{path} must contain a JSON object")
    if document.get("schema") != BASELINE_SCHEMA:
        raise BaselineError(f"{path} has unsupported schema {document.get('schema')!r} (expected {BASELINE_SCHEMA})")
    values = document.get("fingerprints")
    if not isinstance(values, list) or any(not isinstance(item, str) or not item for item in values):
        raise BaselineError(f"{path} has no valid 'fingerprints' list")
    return set(values)


def split_by_baseline(findings: Sequence, accepted: Set[str]) -> Tuple[List, List]:
    """Return (new findings, findings suppressed by the baseline)."""
    new: List = []
    suppressed: List = []
    for finding in findings:
        (suppressed if finding.fingerprint in accepted else new).append(finding)
    return new, suppressed
