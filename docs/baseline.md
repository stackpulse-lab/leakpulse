# Baseline: fail only on new secrets

Introducing a scanner into an existing repository usually fails on day one: years of
old fixtures, sample configs and rotated keys show up at once, the job stays red, and
the check gets disabled. Baseline mode fixes adoption without hiding anything new.

## How it works

A baseline is a JSON file of **fingerprints** for findings you have reviewed and
accepted:

```json
{
  "schema": "leakpulse-baseline/1",
  "tool": "leakpulse 0.5.0",
  "created_at": "2026-11-27T06:12:00Z",
  "count": 3,
  "fingerprints": ["1f0c…", "8a42…", "d3b9…"]
}
```

Each fingerprint is a 20-character SHA-256 prefix over `rule id + path + matched
value`. The file therefore contains **no credential and no masked fragment** — it is
safe to commit and review. The line number is deliberately excluded: moving a line
keeps a finding suppressed, while rotating a secret changes its value and produces a
new fingerprint, which is exactly the event CI should catch.

## Rollout recipe

```bash
# 1. Snapshot what is already there (this command always exits 0)
leakpulse scan . --history 200 --write-baseline leakpulse-baseline.json

# 2. Review and commit the snapshot
git add leakpulse-baseline.json
git commit -m "chore: record known leakpulse findings"

# 3. From now on, only new findings fail the scan
leakpulse scan . --history 200 --baseline leakpulse-baseline.json
```

The first command prints the usual report, so you can triage before committing the
snapshot. `--write-baseline` and `--baseline` are mutually exclusive; passing both is
a usage error (exit `2`).

## CI

GitHub Action:

```yaml
      - uses: stackpulse-lab/leakpulse@v0.5.0
        with:
          history: "200"
          baseline: leakpulse-baseline.json
          fail-on: high
```

Plain CLI:

```bash
leakpulse scan . --history 200 --baseline leakpulse-baseline.json --no-color
```

`--fail-on` applies only to findings that are **not** in the baseline, and the exit
codes keep their meaning: `0` clean (or all remaining findings below the threshold),
`1` new findings at/above the threshold, `2` usage error or invalid baseline.

JSON, SARIF and HTML reports only include new findings and record how many were
suppressed:

```json
"baseline": { "file": "leakpulse-baseline.json", "suppressed": 3 }
```

## Refreshing the baseline

Regenerate it after you rotate a credential or deliberately accept a new one:

```bash
leakpulse scan . --history 200 --write-baseline leakpulse-baseline.json
git diff --stat leakpulse-baseline.json   # fingerprint count should shrink, not grow
```

Two habits keep the baseline honest:

- **Review every refresh.** A baseline that only grows is a suppressed backlog, not
  a fix. Prefer rotating or deleting the secret.
- **Keep history in scope.** If the baseline was created with `--history 0`, do not
  run CI with `--history 200`: old history findings are not covered and the job will
  fail on them.

## Limits

- Fingerprints are positional by path: renaming or moving a file makes its findings
  look new. That is intentional — renames are a common way secrets slip past review.
- A baseline cannot prove a credential is revoked. It only says "we have seen this
  exact match in this exact file before".
- Do not baseline findings that were never reviewed. The point is a reviewed
  accept-list, not a mute button.
