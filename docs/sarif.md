# SARIF & HTML reports

LeakPulse can emit machine-readable reports in addition to the terminal output:

```bash
leakpulse scan . --history 0 --format sarif --output leakpulse.sarif
leakpulse scan . --format html --output audit-report.html
```

`--format` accepts `text` (default), `json`, `sarif` and `html`. `--json` remains a
shortcut for `--format json`. `--output FILE` writes the report to disk (parent
directories are created); without it the report goes to stdout. The process exit
code is unchanged by the report format: `0` clean, `1` findings at/above
`--fail-on`, `2` usage or git error.

## GitHub code scanning (SARIF)

SARIF 2.1.0 is what GitHub's code scanning ingests. The workflow below scans the
worktree and uploads the result; findings appear under **Security → Code scanning**
with rule metadata, masked matches and stable fingerprints (so the same secret is
not re-reported as new on every push).

```yaml
name: leakpulse-sarif
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # required by upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: stackpulse-lab/leakpulse@v0.4.0
        with:
          path: "."
          history: "0"
          fail-on: high          # keep the gate; drop to "never" for report-only
          format: sarif
          output: leakpulse.sarif
        continue-on-error: true  # upload the report even when findings fail the gate
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: leakpulse.sarif
```

Notes:

- The action's `format`/`output` inputs are passed through to `leakpulse scan`; you can
  also use `extra-args: "--format sarif --output leakpulse.sarif"` with any older tag.
- `continue-on-error: true` plus `if: always()` is what makes the report reach code
  scanning when the scan itself fails the job. Remove both if you only want the gate.
- History findings (`history: 100`) point at the file/line in the commit where the
  secret was introduced; the commit SHA is available in the SARIF result `properties`.
- Private repositories need GitHub Advanced Security for code scanning; public
  repositories can use it for free.

Inspect the report locally without GitHub:

```bash
python -m json.tool leakpulse.sarif >/dev/null && echo "valid JSON"
```

## SARIF shape

- `runs[0].tool.driver.rules` lists all 28 regex rules plus `high-entropy-string`,
  each with a `helpUri`, `defaultConfiguration.level` and severity property.
- Each result has `ruleId`, `ruleIndex`, `level` (`error`/`warning`/`note` for
  high/medium/low), a masked `message`, a repo-relative percent-encoded
  `artifactLocation.uri`, `region.startLine`, and `partialFingerprints.leakpulse/v1`.
- `invocations[0].properties` records files/commits scanned, duration and exit code.

## HTML audit report

`--format html` produces a single self-contained file (inline CSS, no scripts, no
remote assets) for attaching to a ticket or handing to a reviewer who does not run
the CLI. All match values are masked exactly like the terminal output, so the report
is safe to share; rotate anything it flags.

## GitLab / other CI

Any CI that can run a command can archive the HTML or SARIF file:

```yaml
leakpulse:
  image: python:3.12
  script:
    - pip install git+https://github.com/stackpulse-lab/leakpulse
    - leakpulse scan . --history 0 --format sarif --output leakpulse.sarif || true
  artifacts:
    when: always
    paths: [leakpulse.sarif]
```
