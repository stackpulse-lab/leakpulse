# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-11-27

### Added

- **Baseline mode** (`leakpulse/baseline.py`): `scan --write-baseline FILE`
  snapshots the fingerprints of current findings (always exits `0`), and
  `scan --baseline FILE` suppresses those known findings so CI fails only on
  newly introduced secrets. Fingerprints are SHA-256 hashes of rule id, path and
  matched value — no credential, not even a masked fragment, is written to the
  baseline file. Line moves keep a finding suppressed; changing the secret
  (rotation) makes it new again.
- JSON output adds `baseline: {file, suppressed}` (and `baseline_written` when
  snapshotting); SARIF carries the same info in `runs[0].properties.baseline`;
  the text report names how many known findings were suppressed.
- `action.yml`: new `baseline` input, so a repository can adopt the Action
  without turning existing legacy findings into a permanently red job.
- `docs/baseline.md`: rollout recipe (write → review → commit → enable in CI),
  refresh flow after rotation, and the security rationale for hashes only.
- `tests/test_baseline.py`: 13 tests for fingerprint behaviour, document
  validation, write/load roundtrip, CLI exit codes, line moves, mutual
  exclusion and suppressed-free SARIF/HTML.

### Changed

- README (zh/en) documents baseline mode and pins examples to `v0.5.0`;
  `docs/distribution.md` gains the `baseline` input row.

## [0.4.0] - 2026-11-26

### Added

- `scan --format {text,json,sarif,html}` and `--output FILE` for shareable reports.
  `--json` stays as an alias for `--format json`; `--quiet` still suppresses clean
  text output, and an explicit `--output` is always written.
- SARIF 2.1.0 export (`leakpulse/exporters.py`): all 28 regex rules plus
  `high-entropy-string` in `tool.driver.rules`, severity mapped to
  `error`/`warning`/`note`, percent-encoded repo-relative artifact URIs,
  `partialFingerprints.leakpulse/v1`, and masked match text only.
- Self-contained HTML audit report: inline CSS, no scripts or remote assets, escaped
  paths/descriptions, masked matches.
- `docs/sarif.md`: GitHub code scanning workflow (`upload-sarif`), SARIF shape,
  HTML usage and a GitLab CI artifact example.
- `action.yml`: new `format` and `output` inputs; existing inputs and `exit-code`
  output are unchanged.
- `tests/test_reports.py`: 15 tests covering SARIF structure/levels/URI encoding/
  redaction/fingerprints, HTML escaping/no-remote-assets, and CLI format/output
  behavior including the `--json` conflict.

### Changed

- README documents the new report formats in both languages, and pins Action /
  pre-commit examples to `v0.4.0`.

## [0.3.0] - 2026-11-26

### Added

- Zero-config composite GitHub Action (`action.yml`): installs the scanner from the
  pinned tag checkout and scans with `path`, `history`, `fail-on` and `extra-args`
  inputs; exposes the scanner `exit-code` and fails the step on findings.
- Expanded `.pre-commit-hooks.yaml`: visible (uncolored) output, text-only file types,
  explicit `pass_filenames: false`/`always_run: true`, and a second
  `leakpulse-worktree` hook for whole-tree scans without history.
- `publish.yml` using PyPI Trusted Publishing (OIDC): tag-only trigger, tests before
  build, tag/`__version__` consistency check, `id-token: write`, no stored API token.
- `docs/distribution.md`: GitHub Action, pre-commit and PyPI setup, plus a comparison
  of the three paths.
- `tests/test_distribution.py`: cross-checks every CLI flag used by the action/hooks
  against the argparse definitions and asserts the publish workflow stays OIDC-only.

### Changed

- README CI section now leads with the Action and documents both pre-commit hook ids.

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

[0.3.0]: https://github.com/stackpulse-lab/leakpulse/releases/tag/v0.3.0
[0.2.0]: https://github.com/stackpulse-lab/leakpulse/releases/tag/v0.2.0
[0.1.0]: https://github.com/stackpulse-lab/leakpulse/releases/tag/v0.1.0
