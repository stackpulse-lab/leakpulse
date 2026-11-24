"""File, staged-change and git-history scanning."""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from .entropy import candidates, looks_random, shannon_entropy
from .rules import RULES, SEVERITY_RANK, is_placeholder, is_reference

INLINE_ALLOW = "leakpulse:allow"

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".idea",
        ".vscode",
        "dist",
        "build",
        "target",
        ".next",
        ".nuxt",
        "coverage",
        "htmlcov",
    }
)

DEFAULT_EXCLUDED_FILES = (
    "*.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.svg",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.webp",
    "*.ico",
    "*.pdf",
    "*.zip",
    "*.gz",
    "*.tgz",
    "*.whl",
    "*.jar",
)

MAX_LINE_LENGTH = 20_000


@dataclass(frozen=True)
class ScanOptions:
    entropy: bool = True
    entropy_threshold: float = 3.6
    entropy_min_length: int = 24
    max_file_bytes: int = 1_000_000
    include_default_excluded: bool = False
    inline_allow: str = INLINE_ALLOW


@dataclass(frozen=True)
class Finding:
    rule_id: str
    description: str
    severity: str
    path: str
    line: int
    value: str
    commit: str = ""

    @property
    def masked(self) -> str:
        return mask_secret(self.value)

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(f"{self.rule_id}\0{self.path}\0{self.value}".encode("utf-8"))
        return digest.hexdigest()[:20]

    @property
    def location(self) -> str:
        location = f"{self.path}:{self.line}"
        return f"{location} @{self.commit}" if self.commit else location

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "commit": self.commit or None,
            "match": self.masked,
            "description": self.description,
        }

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return f"{self.severity.upper()} {self.rule_id} {self.location} {self.masked}"


def mask_secret(value: str, prefix: int = 4, suffix: int = 4) -> str:
    """Redact a secret while keeping enough context to locate it."""
    value = value.strip()
    if len(value) <= prefix + suffix:
        return "*" * len(value)
    hidden = len(value) - prefix - suffix
    return f"{value[:prefix]}{'*' * min(hidden, 16)}{value[-suffix:]}"


class IgnoreList:
    """A small, ordered ignore list (gitignore-ish: later patterns win)."""

    def __init__(self, patterns: Sequence[str] = ()):
        self._rules: List[Tuple[bool, str]] = []
        for raw in patterns:
            pattern = raw.strip()
            if not pattern or pattern.startswith("#"):
                continue
            negated = pattern.startswith("!")
            if negated:
                pattern = pattern[1:].strip()
            if pattern:
                self._rules.append((negated, pattern))

    @classmethod
    def load(cls, path: Path, extra: Sequence[str] = ()) -> "IgnoreList":
        patterns = list(extra)
        if path.is_file():
            patterns.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())
        return cls(patterns)

    def __bool__(self) -> bool:
        return bool(self._rules)

    def ignored(self, relpath: str) -> bool:
        rel = relpath.replace(os.sep, "/")
        while rel.startswith("./"):
            rel = rel[2:]
        base = rel.rsplit("/", 1)[-1]
        state = False
        for negated, pattern in self._rules:
            if self._matches(pattern, rel, base):
                state = not negated
        return state

    @staticmethod
    def _matches(pattern: str, rel: str, base: str) -> bool:
        if pattern.endswith("/"):
            pattern = pattern.rstrip("/") + "/**"
        if "/" in pattern:
            return fnmatch.fnmatchcase(rel, pattern) or fnmatch.fnmatchcase(rel, pattern.rstrip("/") + "/**")
        return fnmatch.fnmatchcase(base, pattern)


def _overlaps(spans: Sequence[Tuple[int, int]], start: int, end: int) -> bool:
    return any(start < span_end and end > span_start for span_start, span_end in spans)


def _scan_line(
    line: str,
    path: str,
    line_no: int,
    options: ScanOptions,
    commit: str = "",
) -> List[Finding]:
    findings: List[Finding] = []
    covered: List[Tuple[int, int]] = []

    for rule in RULES:
        for match, value in rule.extract(line):
            start, end = match.span(rule.group)
            if _overlaps(covered, start, end):
                continue
            if is_placeholder(value) or is_reference(value):
                continue
            if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                continue
            covered.append((start, end))
            findings.append(
                Finding(
                    rule_id=rule.id,
                    description=rule.description,
                    severity=rule.severity,
                    path=path,
                    line=line_no,
                    value=value,
                    commit=commit,
                )
            )
            break  # one finding per rule per line is enough

    if options.entropy:
        for start, end, value in candidates(line):
            if _overlaps(covered, start, end):
                continue
            if looks_random(value, options.entropy_threshold, options.entropy_min_length):
                covered.append((start, end))
                findings.append(
                    Finding(
                        rule_id="high-entropy-string",
                        description="High-entropy string (possible secret)",
                        severity="medium",
                        path=path,
                        line=line_no,
                        value=value,
                        commit=commit,
                    )
                )

    return findings


def scan_text(text: str, path: str, options: Optional[ScanOptions] = None, commit: str = "") -> List[Finding]:
    """Scan an in-memory text blob (used by tests and the history parser)."""
    options = options or ScanOptions()
    findings: List[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if options.inline_allow and options.inline_allow in line:
            continue
        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]
        findings.extend(_scan_line(line, path, line_no, options, commit))
    return findings


def is_default_excluded(relpath: str) -> bool:
    base = relpath.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(base, pattern) for pattern in DEFAULT_EXCLUDED_FILES)


def scan_file(
    file_path: Path,
    relpath: str,
    options: Optional[ScanOptions] = None,
    ignore: Optional[IgnoreList] = None,
) -> List[Finding]:
    options = options or ScanOptions()
    if ignore and ignore.ignored(relpath):
        return []
    if not options.include_default_excluded and is_default_excluded(relpath):
        return []
    try:
        if file_path.stat().st_size > options.max_file_bytes:
            return []
        data = file_path.read_bytes()
    except OSError:
        return []
    if b"\x00" in data[:8192]:
        return []
    text = data.decode("utf-8", errors="replace")
    return scan_text(text, relpath, options)


def scan_path(
    target: Path,
    options: Optional[ScanOptions] = None,
    ignore: Optional[IgnoreList] = None,
    root: Optional[Path] = None,
) -> Tuple[List[Finding], int]:
    """Scan a file or directory tree. Returns (findings, files_scanned)."""
    options = options or ScanOptions()
    target = Path(target)
    if not target.is_absolute():
        target = target.resolve()
    base = Path(root).resolve() if root is not None else target
    if target.is_file():
        try:
            rel = str(target.relative_to(base)).replace(os.sep, "/")
        except ValueError:
            rel = target.name
        return scan_file(target, rel, options, ignore), 1

    findings: List[Finding] = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = sorted(d for d in dirnames if d not in DEFAULT_EXCLUDED_DIRS)
        for filename in sorted(filenames):
            file_path = Path(dirpath) / filename
            try:
                rel = str(file_path.relative_to(base)).replace(os.sep, "/")
            except ValueError:
                rel = filename
            if file_path.is_symlink():
                continue
            results = scan_file(file_path, rel, options, ignore)
            scanned += 1
            findings.extend(results)
    return findings, scanned


HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_patch(patch: str, options: Optional[ScanOptions] = None, commit: str = "") -> List[Finding]:
    """Extract added lines from a unified diff and scan them."""
    options = options or ScanOptions()
    findings: List[Finding] = []
    path: Optional[str] = None
    new_line = 0
    for raw in patch.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            if target == "/dev/null":
                path = None
            else:
                if target.startswith("b/"):
                    target = target[2:]
                path = target.strip('"')
            new_line = 0
            continue
        hunk = HUNK_HEADER.match(raw)
        if hunk:
            new_line = int(hunk.group(1))
            continue
        if raw.startswith(("diff --git", "index ", "--- ", "new file mode", "deleted file mode", "similarity index")):
            continue
        if path is None:
            continue
        if raw.startswith("+"):
            findings.extend(_scan_line(raw[1:], path, new_line, options, commit))
            new_line += 1
        elif raw.startswith(" "):
            new_line += 1
        # '-' (removed) and '\' (no newline) do not advance the new-file counter
    return findings


def dedupe(findings: Iterable[Finding]) -> List[Finding]:
    """Collapse identical secrets and sort by severity, then location."""
    seen = set()
    unique: List[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        unique.append(finding)
    unique.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.line))
    return unique
