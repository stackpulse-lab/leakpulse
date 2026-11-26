# LeakPulse

**A zero-dependency secret scanner for worktrees, staged changes and git history.**
Catch `ghp_…`, `sk-…`, private keys and high-entropy tokens before they leave your laptop.

[![CI](https://github.com/stackpulse-lab/leakpulse/actions/workflows/ci.yml/badge.svg)](https://github.com/stackpulse-lab/leakpulse/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Dependencies: none](https://img.shields.io/badge/dependencies-0-brightgreen)](pyproject.toml)

```
$ leakpulse scan .
HIGH   github-token               src/config.py:12  ghp_****q7R8   GitHub token (classic app/OAuth/refresh)
MEDIUM generic-secret-assignment  deploy/prod.env:5  Tr0u****9xyz   Secret-like value assigned to a sensitive name

2 potential secrets found (1 high, 1 medium) Scanned 84 files and 50 commits in 0.09s.
```

---

## 中文速览

**LeakPulse** 是一个**零依赖**的密钥泄露扫描器，一条命令同时检查：

1. **工作区**文件（自动跳过 `.git`、虚拟环境、二进制与压缩产物）；
2. **暂存区**（`--staged`，适合 pre-commit 钩子）；
3. **提交历史**（`--history N`，发现「已经提交过一次」的密钥）。

它只做本地静态检查：**不联网、不上传、无遥测**，命中结果默认脱敏输出，避免二次泄露。

```bash
pipx install git+https://github.com/stackpulse-lab/leakpulse
leakpulse scan .                       # 工作区 + 最近 50 个提交
leakpulse scan --staged                # 只看暂存区（pre-commit）
leakpulse scan . --history 200 --json  # 输出 JSON 给 CI
leakpulse install-hook                 # 安装 pre-commit 钩子
```

支持以下忽略方式：仓库根目录 `.leakpulseignore`（gitignore 风格，支持 `!` 反选）、行内注释 `leakpulse:allow`、命令行 `--exclude 'vendor/**'`。

**v0.2.0 起内置国内生态规则**（共 28 条）：DeepSeek `sk-…`、阿里云 `LTAI…` AccessKey ID / Secret、腾讯云 `AKID…` SecretId / SecretKey、火山引擎 `AKLT…`、飞书/企微/钉钉群机器人 Webhook、爱发电 API Token。Webhook 只截取并脱敏 token 部分，报告里不会出现完整回调 URL。

**开箱即用分发**：GitHub Action 一行 `uses: stackpulse-lab/leakpulse@v0.5.0`（无需 `setup-python`）；`pre-commit` 钩子 `id: leakpulse`；以及基于 OIDC 的 PyPI Trusted Publishing workflow（不存任何 API Token）。三种接入方式见 [`docs/distribution.md`](docs/distribution.md)。

**审计与 CI 报告**：`--format sarif` 输出 SARIF 2.1.0（可直接交给 GitHub Code Scanning），`--format html` 输出单文件、无脚本、无远程资源的审计报告，交给不做命令行评审的人看；用法与可直接复制的 workflow 见 [`docs/sarif.md`](docs/sarif.md)。

**基线模式（v0.5.0）**：`--write-baseline leakpulse-baseline.json` 记录当前命中的指纹快照，`--baseline leakpulse-baseline.json` 只对**新增**密钥报错。基线文件只保存 `规则+路径+匹配值` 的 SHA-256 指纹，不含密钥也不含脱敏片段，可安全提交；适合「老仓库先接入 CI，再逐步清理历史问题」。详见 [`docs/baseline.md`](docs/baseline.md)。

适用场景：个人项目推送前自检、CI 门禁、给团队补一层低成本的「防手滑」保险。它不是 SAST 的替代品，也不能判断密钥是否仍然有效——**发现即轮换**。

---

## Why another secret scanner?

Because the good ones are either heavy (Go binaries, container images, cloud accounts) or noisy enough that people disable them. LeakPulse is deliberately small:

- **Zero third-party dependencies** — Python standard library only, so the audit surface is a handful of files.
- **Three scopes in one binary** — worktree, index and history share the same rule engine.
- **Redacted output** — findings never print the full secret; safe to paste into an issue or CI log.
- **Fail-closed hook** — `install-hook` writes a pre-commit gate that refuses to commit when the scanner is unavailable.
- **Deterministic exit codes** — `0` clean, `1` findings at/above `--fail-on`, `2` usage or git error.

## Install

Requires Python 3.9+ and (for history/staged modes) git.

```bash
# Isolated install from the repository
pipx install git+https://github.com/stackpulse-lab/leakpulse

# or into a virtualenv
python -m venv .venv && . .venv/bin/activate
pip install git+https://github.com/stackpulse-lab/leakpulse

# development
git clone https://github.com/stackpulse-lab/leakpulse
cd leakpulse
python run_tests.py
PYTHONPATH=src python -m leakpulse scan .
```

No PyPI release yet — `v0.5.0` is distributed from GitHub Releases. PyPI publishing is
wired through Trusted Publishing (OIDC) and activates after the one-time project setup
in [`docs/distribution.md`](docs/distribution.md); no API token is stored in the repo.

## Usage

```bash
leakpulse scan [PATH ...] [options]   # scan files/directories
leakpulse scan --staged               # scan staged content only
leakpulse scan . --history 0          # skip git history
leakpulse rules                       # list detection rules
leakpulse install-hook [--repo PATH] [--force]
leakpulse version
```

### Common options

| Option | Default | Description |
| --- | --- | --- |
| `--history N` | `50` | Scan the last N commits (`0` disables) |
| `--staged` | off | Scan the git index only; history defaults to `0` |
| `--json` | off | Machine-readable report with redacted matches |
| `--format {text,json,sarif,html}` | `text` | Report format; `sarif` for code scanning, `html` for audits |
| `--output FILE` | stdout | Write the report to a file (parent dirs created) |
| `--fail-on {low,medium,high,never}` | `high` | Severity threshold for exit code `1` |
| `--no-entropy` | off | Disable the high-entropy heuristic |
| `--entropy-threshold` | `3.6` | Shannon entropy threshold (bits/char) |
| `--exclude GLOB` | — | Extra ignore glob (repeatable) |
| `--all` | off | Also scan lockfiles and minified assets |
| `--max-file-bytes` | `1000000` | Skip larger files |
| `--quiet` | off | Print nothing when clean (hook-friendly) |

`--json` output:

```json
{
  "tool": "leakpulse",
  "version": "0.5.0",
  "scanned": { "files": 84, "commits": 50 },
  "summary": { "total": 1, "high": 1, "medium": 0, "low": 0 },
  "findings": [
    {
      "rule": "github-token",
      "severity": "high",
      "path": "src/config.py",
      "line": 12,
      "commit": null,
      "match": "ghp_****q7R8",
      "description": "GitHub token (classic app/OAuth/refresh)"
    }
  ],
  "elapsed_seconds": 0.091,
  "exit_code": 1
}
```

### SARIF and HTML reports

```bash
leakpulse scan . --history 0 --format sarif --output leakpulse.sarif
leakpulse scan . --format html --output audit-report.html
```

SARIF 2.1.0 output plugs into GitHub code scanning (rule metadata, masked matches,
stable fingerprints, repo-relative URIs). HTML output is a single self-contained file
for tickets or reviewers — inline CSS, no scripts, no remote assets. Copy-paste
workflow and notes: [`docs/sarif.md`](docs/sarif.md).

## Detection rules

28 high-signal rules plus an entropy heuristic. Full list: `leakpulse rules`.

| Rule | Severity | Catches |
| --- | --- | --- |
| `private-key-block` | high | PEM/PGP private key headers |
| `aws-access-key-id` | high | `AKIA…` / `ASIA…` access key IDs |
| `github-pat` / `github-token` | high | `github_pat_…`, `ghp_…`, `gho_…`, `ghs_…` |
| `deepseek-key` | high | `sk-…` used with a `deepseek` config name |
| `anthropic-key` / `openai-key` | high | `sk-ant-…`, `sk-…`, `sk-proj-…` |
| `resend-key` / `sendgrid-key` | high | transactional-mail API keys |
| `slack-token` / `stripe-key` | high | `xox…`, `sk_live_…`, `rk_live_…` |
| `google-api-key` / `npm-token` / `pypi-token` | high | cloud and package-registry credentials |
| `aliyun-access-key-id` / `aliyun-access-key-secret` | high | `LTAI…` and `ALIBABA_CLOUD_ACCESS_KEY_SECRET=…` |
| `tencent-secret-id` / `tencent-secret-key` | high | `AKID…` and `TENCENTCLOUD_SECRET_KEY=…` |
| `volcengine-access-key-id` | high | `AKLT…` |
| `feishu-webhook` / `wecom-webhook` / `dingtalk-webhook` | high | bot webhook tokens (Feishu/Lark, WeCom, DingTalk) |
| `afdian-token` | high | Afdian `AFDIAN_TOKEN=…` |
| `discord-webhook` | high | webhook URLs with embedded token |
| `url-basic-auth` | high | `scheme://user:pass@host` |
| `bearer-token` | high | `Authorization: Bearer …` |
| `jwt` | medium | three-part JSON Web Tokens |
| `generic-secret-assignment` | medium | `password = "…"`, `api_key: "…"` |
| `high-entropy-string` | medium | unknown random-looking 24+ char strings |

For webhook rules only the token is captured, so text and JSON reports never expose the
full callback URL. Placeholders (`example`, `your_…`, `${VAR}`, `changeme`, repeated characters) and code references (`os.environ.get`, `process.env`) are suppressed to keep noise low.

## Ignoring findings

`.leakpulseignore` in the repository root, gitignore-style:

```gitignore
tests/fixtures/**
vendor/**
!vendor/keep-this.txt
```

Inline, per line (use sparingly, always with a reason):

```python
DEMO_TOKEN = "..."  # leakpulse:allow: documented sample, revoked
```

Command line: `--exclude 'docs/**' --exclude '*.snap'`.

Lockfiles and minified assets are skipped by default because integrity hashes look random; pass `--all` to include them.

### Baseline mode

Legacy repositories rarely start clean. A baseline records the findings you have
reviewed and accepted, so CI fails only on new ones:

```bash
leakpulse scan . --history 200 --write-baseline leakpulse-baseline.json  # exits 0
leakpulse scan . --history 200 --baseline leakpulse-baseline.json        # new-only gate
```

The baseline holds SHA-256 fingerprints of `rule + path + match` — no credential and
no masked fragment — so it can be committed and reviewed. Line moves stay suppressed;
rotating a secret produces a new fingerprint and therefore a new finding. JSON, SARIF
and HTML reports only contain new findings and record the suppressed count. Rollout,
refresh and CI details: [`docs/baseline.md`](docs/baseline.md).

## CI and pre-commit

Zero-config GitHub Action (recommended — installs the scanner from the pinned tag,
no `setup-python` step needed):

```yaml
name: secrets
on: [push, pull_request]
permissions:
  contents: read
jobs:
  leakpulse:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # only needed when history > 0
      - uses: stackpulse-lab/leakpulse@v0.5.0
        with:
          history: "0"            # set to 100+ to scan recent commits
          fail-on: high
```

Inputs: `path`, `history`, `fail-on`, `extra-args`, `format`, `output`, `baseline`; output `exit-code`.
For code scanning, set `format: sarif` and `output: leakpulse.sarif`, then upload with
`github/codeql-action/upload-sarif` — see [`docs/sarif.md`](docs/sarif.md).
A plain CLI step works too if you prefer explicit control:

```bash
pipx install git+https://github.com/stackpulse-lab/leakpulse
leakpulse scan . --history 100 --fail-on high --no-color
```

`pre-commit` framework (`.pre-commit-config.yaml`):

```yaml
repos:
  - repo: https://github.com/stackpulse-lab/leakpulse
    rev: v0.5.0
    hooks:
      - id: leakpulse            # staged changes only
      # - id: leakpulse-worktree # whole worktree, no history
```

Maintainer-side PyPI publishing (tag → OIDC → PyPI, tests re-run, tag/version checked)
lives in `.github/workflows/publish.yml`. Full setup for all three paths:
[`docs/distribution.md`](docs/distribution.md).

Native hook (no framework):

```bash
leakpulse install-hook            # writes .git/hooks/pre-commit
```

The hook fails closed: if `leakpulse` is not on `PATH`, the commit is blocked with an install hint. In a source checkout, export `LEAKPULSE_SRC=/absolute/path/to/leakpulse/src` so the hook can run `python3 -m leakpulse`.

## How it works

1. **Collect** — walk the requested paths (or `git diff --cached`, or `git rev-list` + `git show`).
2. **Scan** — run ordered regex rules per line; the first matching rule owns the span. Then apply Shannon entropy to remaining long strings.
3. **Filter** — drop placeholders, env references and ignored paths.
4. **Deduplicate** — one finding per `(rule, path, secret)`; history duplicates collapse to the newest commit.
5. **Report** — mask the secret, sort by severity, set the exit code.

There is no network access anywhere in the codebase. Scan results stay on your machine unless you paste them somewhere.

## Limitations

- Regex + entropy is a heuristic, not formal verification. False negatives are possible (encoded or split secrets); false positives are possible (random identifiers).
- History mode inspects **added lines** of the last N commits; it does not rewrite history or revoke anything.
- Binary files, archives and files over `--max-file-bytes` are skipped; `.git` internals are never walked.
- Finding a secret does not prove it is live, and *not* finding one does not prove the repo is clean.

When you do find one: **rotate/revoke first**, then remove it from history if the repository is public.

## Development

```bash
python run_tests.py          # stdlib unittest, no deps
PYTHONPATH=src python -m leakpulse scan . --history 0
make test lint               # optional convenience targets
```

The test suite covers rule matching, placeholder suppression, masking, ignore lists, staged scanning, history parsing and CLI exit codes. CI runs it on Python 3.9–3.13.

## License

MIT © 2026 StackPulse Lab. See [LICENSE](LICENSE).
