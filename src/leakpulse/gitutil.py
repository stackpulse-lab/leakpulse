"""Thin, testable wrappers around the git CLI (no third-party dependencies)."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Optional


class GitError(RuntimeError):
    pass


def _run(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            ["git", "-c", "core.quotepath=false", *args],
            cwd=str(repo),
            capture_output=True,
            text=False,
        )
    except FileNotFoundError as exc:  # pragma: no cover - git is required for these paths
        raise GitError("git executable not found") from exc
    if check and result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"git {' '.join(args)} failed: {stderr}")
    return result


def repo_root(path: Path) -> Optional[Path]:
    if not Path(path).exists():
        return None
    result = _run(Path(path), "rev-parse", "--show-toplevel", check=False)
    if result.returncode != 0:
        return None
    root = result.stdout.decode("utf-8", "replace").strip()
    return Path(root) if root else None


def hooks_dir(repo: Path) -> Path:
    result = _run(repo, "rev-parse", "--git-path", "hooks")
    return repo / result.stdout.decode("utf-8", "replace").strip()


def staged_files(repo: Path) -> List[str]:
    result = _run(repo, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z", check=False)
    if result.returncode != 0:
        return []
    raw = result.stdout.decode("utf-8", "replace")
    return [item for item in raw.split("\0") if item]


def staged_content(repo: Path, path: str) -> Optional[bytes]:
    result = _run(repo, "show", f":{path}", check=False)
    return result.stdout if result.returncode == 0 else None


def is_repo_dirty(repo: Path) -> bool:
    result = _run(repo, "status", "--porcelain", check=False)
    return bool(result.stdout.strip())


def rev_list(repo: Path, max_commits: int) -> List[str]:
    if max_commits <= 0:
        return []
    result = _run(repo, "rev-list", f"--max-count={max_commits}", "HEAD", check=False)
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.decode("utf-8", "replace").splitlines() if line]


def show_patch(repo: Path, sha: str) -> str:
    result = _run(repo, "show", "--format=", "--no-ext-diff", "--no-color", "--unified=0", sha, check=False)
    if result.returncode != 0:
        return ""
    return result.stdout.decode("utf-8", "replace")
