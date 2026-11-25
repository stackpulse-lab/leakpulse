# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-26

### Added

- Ten localized rules for Chinese cloud providers and domestic SaaS:
  - `deepseek-key` (DeepSeek `sk-…`, reported separately from OpenAI keys),
  - `aliyun-access-key-id` (`LTAI…`) and `aliyun-access-key-secret`,
  - `tencent-secret-id` (`AKID…`) and `tencent-secret-key`,
  - `volcengine-access-key-id` (`AKLT…`),
  - `feishu-webhook`, `wecom-webhook`, `dingtalk-webhook` (only the token is captured),
  - `afdian-token` (爱发电).
- Redaction regression tests for every localized rule: masked text, JSON `match` and
  text reports never contain the captured credential; webhook findings never print
  the full URL.
- False-positive guards: documentation URLs, env references and placeholder
  values (`your_…`, `${VAR}`, repeated characters) stay quiet.
- Rule count is now 28; 77 stdlib tests (18 new).

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

[0.2.0]: https://github.com/stackpulse-lab/leakpulse/releases/tag/v0.2.0
[0.1.0]: https://github.com/stackpulse-lab/leakpulse/releases/tag/v0.1.0
