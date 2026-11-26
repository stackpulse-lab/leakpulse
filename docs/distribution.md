# Distribution & CI integration

LeakPulse ships three integration paths. All of them run the same local scanner —
no account, no upload, no telemetry.

## 1. GitHub Action (zero config)

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
      - uses: stackpulse-lab/leakpulse@v0.5.0
        with:
          path: "."
          history: "0"     # set to 100+ to scan recent commits
          fail-on: high
```

The action installs the package from its own pinned checkout, so the scanner version
is exactly the tag you reference. Inputs:

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | File or directory to scan |
| `history` | `0` | Commits to scan; `0` disables history (fastest) |
| `fail-on` | `high` | `low`, `medium`, `high` or `never` |
| `extra-args` | empty | Extra `leakpulse scan` flags, e.g. `--exclude 'docs/**'` |
| `format` | `text` | `text`, `json`, `sarif` or `html` |
| `output` | empty | Report file to write, e.g. `leakpulse.sarif` |
| `baseline` | empty | Baseline JSON file; findings recorded there are suppressed so only new secrets fail |

Output `exit-code` mirrors the scanner: `0` clean, `1` findings at/above threshold,
`2` usage or git error. The step fails on non-zero by design; use
`continue-on-error: true` if you only want the report.

> Composite actions do not receive `github.token`; no extra permissions are needed
> beyond `contents: read` for the checkout.

## 2. pre-commit framework

`.pre-commit-config.yaml` in your repository:

```yaml
repos:
  - repo: https://github.com/stackpulse-lab/leakpulse
    rev: v0.5.0
    hooks:
      - id: leakpulse            # staged changes only, fastest
      # - id: leakpulse-worktree # whole worktree, no history
```

Then `pre-commit install` and commit as usual. Both hooks pass `--fail-on high`, so a
likely credential blocks the commit; output is redacted. To allow a documented sample,
add `# leakpulse:allow` on the line or list it in `.leakpulseignore`.

The hooks use `language: python`; pre-commit builds an isolated virtualenv per `rev`,
so upgrades are explicit and reproducible.

## 3. PyPI Trusted Publishing (OIDC)

`.github/workflows/publish.yml` publishes on `v*` tags using GitHub's OIDC identity —
**no `PYPI_API_TOKEN` secret exists anywhere**. One-time setup by a project owner:

1. On PyPI: *Account → Publishing → Add a pending publisher*
   - PyPI project name: `leakpulse`
   - Owner: `stackpulse-lab`
   - Repository: `leakpulse`
   - Workflow name: `publish.yml`
   - Environment: `pypi`
2. On GitHub: create an environment named `pypi` (Settings → Environments).
   Optionally add required reviewers to gate uploads.
3. Release flow: bump `__version__` → commit → `git tag vX.Y.Z` → push the tag.
   The workflow re-runs the test suite, checks the tag against `__version__`, builds
   sdist + wheel, and uploads. A version/tag mismatch fails before publishing.

Once the first upload succeeds, install with `pip install leakpulse`; the pending
publisher is promoted automatically.

## Why three paths?

| Path | Best for | Latency |
| --- | --- | --- |
| GitHub Action | Repos already on GitHub, no Python setup step | ~15 s |
| pre-commit | Catching secrets before they enter history | <1 s per commit |
| PyPI + `pipx` | Local CLI, air-gapped mirrors, custom scripts | one-time install |

Defense in depth: pre-commit stops most accidents locally, the Action catches
contributions from machines without hooks, and history scanning (`history: 100`)
catches anything that slipped through before the gate existed.

## 4. SARIF / HTML reports

`--format sarif` targets GitHub code scanning and any SARIF 2.1.0 consumer;
`--format html` writes a self-contained audit report for humans. Both are documented,
with a copy-paste code-scanning workflow, in [`sarif.md`](sarif.md).
