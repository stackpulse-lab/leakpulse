# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-24

### Added

- `leakpulse scan` for worktrees, directories and individual files.
- `--staged` mode that scans the git index (pre-commit friendly).
- `--history N` mode that scans added lines of recent commits, with commit attribution.
- 18 detection rules covering major cloud, VCS, mail, payment and package-registry tokens,
  private keys, URLs with embedded credentials, bearer tokens and JWTs.
- Shannon-entropy heuristic for unknown secrets (`--no-entropy`, `--entropy-threshold`).
- Redacted output, JSON reports and deterministic exit codes (`--fail-on`).
- `.leakpulseignore` (gitignore-style, with negation), inline `leakpulse:allow` and `--exclude`.
- `leakpulse install-hook` for a fail-closed native pre-commit hook.
- Stdlib-only test suite (rules, entropy, scanner, git integration, CLI) and GitHub Actions CI
  on Python 3.9–3.13.

[0.1.0]: https://github.com/stackpulse-lab/leakpulse/releases/tag/v0.1.0
