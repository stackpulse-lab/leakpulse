"""Command line interface for leakpulse."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from . import gitutil
from .exporters import render_html, render_sarif
from .report import render_text
from .rules import RULES, SEVERITY_RANK
from .scanner import (
    IgnoreList,
    ScanOptions,
    dedupe,
    is_default_excluded,
    parse_patch,
    scan_path,
    scan_text,
)

HOOK_MARKER = "# Installed by leakpulse"
HOOK_TEMPLATE = """#!/bin/sh
# Installed by leakpulse: scan staged changes before every commit.
# Remove this file to disable the hook, or reinstall with --force.
if command -v leakpulse >/dev/null 2>&1; then
  exec leakpulse scan --staged --fail-on high --quiet
fi
if [ -n "$LEAKPULSE_SRC" ] && [ -d "$LEAKPULSE_SRC" ]; then
  exec env PYTHONPATH="$LEAKPULSE_SRC" python3 -m leakpulse scan --staged --fail-on high --quiet
fi
echo "leakpulse: command not found. Install it (pipx install leakpulse) or set LEAKPULSE_SRC." >&2
exit 1
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakpulse",
        description="Zero-dependency secret scanner for worktrees, staged changes and git history.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan files, staged changes or git history")
    scan.add_argument("paths", nargs="*", default=["."], help="files or directories to scan (default: .)")
    scan.add_argument("--staged", action="store_true", help="scan only content staged for commit")
    scan.add_argument(
        "--history",
        type=int,
        default=None,
        metavar="N",
        help="scan the last N commits (default: 50; 0 disables history scanning)",
    )
    scan.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    scan.add_argument(
        "--format",
        choices=["text", "json", "sarif", "html"],
        default=None,
        help="report format: text (default), json, sarif for code scanning, html for audits",
    )
    scan.add_argument("--output", metavar="FILE", default=None, help="write the report to FILE instead of stdout")
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    scan.add_argument("--no-entropy", action="store_true", help="disable high-entropy detection")
    scan.add_argument("--entropy-threshold", type=float, default=3.6, help="entropy threshold (default: 3.6)")
    scan.add_argument("--min-length", type=int, default=24, help="minimum entropy candidate length (default: 24)")
    scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "never"],
        default="high",
        help="exit non-zero at or above this severity (default: high)",
    )
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="extra ignore glob (repeatable)")
    scan.add_argument("--all", action="store_true", help="also scan lockfiles and minified assets")
    scan.add_argument("--max-file-bytes", type=int, default=1_000_000, help="skip files larger than this")
    scan.add_argument("--no-ignore-file", action="store_true", help="ignore .leakpulseignore")
    scan.add_argument("--quiet", action="store_true", help="print nothing when clean")

    rules = subparsers.add_parser("rules", help="list detection rules")
    rules.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    hook = subparsers.add_parser("install-hook", help="install a pre-commit hook")
    hook.add_argument("--repo", default=".", help="repository path (default: .)")
    hook.add_argument("--force", action="store_true", help="overwrite an existing pre-commit hook")

    subparsers.add_parser("version", help="print version")
    return parser


def _load_ignore(args: argparse.Namespace, root: Path) -> IgnoreList:
    if args.no_ignore_file:
        return IgnoreList(args.exclude)
    return IgnoreList.load(root / ".leakpulseignore", args.exclude)


def _exit_code(findings, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = SEVERITY_RANK[fail_on]
    return 1 if any(SEVERITY_RANK[f.severity] >= threshold for f in findings) else 0


def _scan_staged(root: Path, options: ScanOptions, ignore: IgnoreList):
    findings = []
    files_scanned = 0
    for path in gitutil.staged_files(root):
        if ignore.ignored(path):
            continue
        if not options.include_default_excluded and is_default_excluded(path):
            continue
        content = gitutil.staged_content(root, path)
        if content is None:
            continue
        if len(content) > options.max_file_bytes or b"\x00" in content[:8192]:
            continue
        files_scanned += 1
        findings.extend(scan_text(content.decode("utf-8", "replace"), path, options))
    return findings, files_scanned


def _write_report(report: str, output: Optional[str]) -> bool:
    """Emit a rendered report to stdout or to a UTF-8 file."""
    if output is None:
        print(report)
        return True
    path = Path(output)
    try:
        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report if report.endswith("\n") else report + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"leakpulse: cannot write {path}: {exc}", file=sys.stderr)
        return False
    print(f"leakpulse: wrote {path}", file=sys.stderr)
    return True


def run_scan(args: argparse.Namespace) -> int:
    started = time.time()
    report_format = args.format or ("json" if args.json else "text")
    if args.json and args.format and args.format != "json":
        print("leakpulse: --json conflicts with --format " + args.format, file=sys.stderr)
        return 2
    base = Path.cwd()
    options = ScanOptions(
        entropy=not args.no_entropy,
        entropy_threshold=args.entropy_threshold,
        entropy_min_length=args.min_length,
        max_file_bytes=args.max_file_bytes,
        include_default_excluded=args.all,
    )
    root = gitutil.repo_root(base)
    ignore = _load_ignore(args, root or base)
    findings = []
    files_scanned = 0
    commits_scanned = 0

    if args.staged:
        if root is None:
            print("leakpulse: --staged requires a git repository", file=sys.stderr)
            return 2
        findings, files_scanned = _scan_staged(root, options, ignore)
        history = args.history or 0
    else:
        for target in args.paths:
            if not Path(target).exists():
                print(f"leakpulse: no such file or directory: {target}", file=sys.stderr)
                return 2
            results, count = scan_path(Path(target), options, ignore, root=root)
            findings.extend(results)
            files_scanned += count
        history = 50 if args.history is None else args.history

    if history > 0 and root is not None:
        for sha in gitutil.rev_list(root, history):
            commits_scanned += 1
            for finding in parse_patch(gitutil.show_patch(root, sha), options, sha[:8]):
                if ignore.ignored(finding.path):
                    continue
                findings.append(finding)

    findings = dedupe(findings)
    elapsed = time.time() - started
    code = _exit_code(findings, args.fail_on)

    if report_format == "json":
        payload = {
            "tool": "leakpulse",
            "version": __version__,
            "scanned": {"files": files_scanned, "commits": commits_scanned},
            "summary": {
                "total": len(findings),
                "high": sum(1 for f in findings if f.severity == "high"),
                "medium": sum(1 for f in findings if f.severity == "medium"),
                "low": sum(1 for f in findings if f.severity == "low"),
            },
            "findings": [finding.to_dict() for finding in findings],
            "elapsed_seconds": round(elapsed, 3),
            "exit_code": code,
        }
        return code if _write_report(json.dumps(payload, ensure_ascii=False, indent=2), args.output) else 2

    if report_format == "sarif":
        report = render_sarif(findings, files_scanned, commits_scanned, elapsed, code, __version__)
        return code if _write_report(report, args.output) else 2

    if report_format == "html":
        report = render_html(findings, files_scanned, commits_scanned, elapsed, code, __version__)
        return code if _write_report(report, args.output) else 2

    if args.quiet and not findings and args.output is None:
        return code

    color = (
        args.output is None
        and sys.stdout.isatty()
        and not args.no_color
        and os.environ.get("NO_COLOR") is None
    )
    report = render_text(findings, files_scanned, commits_scanned, elapsed, color=color)
    return code if _write_report(report, args.output) else 2


def run_rules(args: argparse.Namespace) -> int:
    if args.json:
        print(
            json.dumps(
                [
                    {"id": rule.id, "severity": rule.severity, "description": rule.description}
                    for rule in RULES
                ],
                indent=2,
            )
        )
        return 0
    for rule in RULES:
        print(f"{rule.severity.upper():<7} {rule.id:<28} {rule.description}")
    print(f"\n{len(RULES)} rules (+ high-entropy heuristic)")
    return 0


def run_install_hook(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    root = gitutil.repo_root(repo)
    if root is None:
        print(f"leakpulse: {repo} is not inside a git repository", file=sys.stderr)
        return 2
    hooks = gitutil.hooks_dir(root)
    hooks.mkdir(parents=True, exist_ok=True)
    hook_path = hooks / "pre-commit"
    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8", errors="replace")
        if HOOK_MARKER not in existing and not args.force:
            print(
                f"leakpulse: {hook_path} already exists and was not created by leakpulse; "
                "use --force to overwrite",
                file=sys.stderr,
            )
            return 2
    hook_path.write_text(HOOK_TEMPLATE, encoding="utf-8")
    hook_path.chmod(0o755)
    print(f"Installed pre-commit hook at {hook_path}")
    print("Set LEAKPULSE_SRC=/path/to/leakpulse/src if leakpulse is not on PATH inside the hook.")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return run_scan(args)
        if args.command == "rules":
            return run_rules(args)
        if args.command == "install-hook":
            return run_install_hook(args)
        if args.command == "version":
            print(__version__)
            return 0
    except gitutil.GitError as exc:
        print(f"leakpulse: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    parser.error("unknown command")
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
