# Contributing to LeakPulse

Thanks for helping. This project is intentionally small: Python standard
library only, no runtime dependencies, no network access.

## Ground rules

1. **No new runtime dependencies.** If the standard library can do it, use it.
2. **No network calls, telemetry or uploads.** Scanning must stay local.
3. **Never commit real credentials.** Test fixtures must be generated at
   runtime (see `tests/support.py`) and never look like live keys.
4. **Tests first.** New rules and CLI behavior need unit tests; git features
   need integration tests guarded by `skipUnless(shutil.which("git"))`.
5. **Redact output.** Any new finding path must mask the secret in text and
   JSON output. Raw values stay in memory only.

## Development workflow

```bash
git clone https://github.com/stackpulse-lab/leakpulse
cd leakpulse
python3 run_tests.py
PYTHONPATH=src python3 -m leakpulse scan . --history 0 --fail-on high
```

There is no virtualenv requirement; Python 3.9+ is enough. If you use one,
`.venv/` is already ignored.

## Adding a rule

1. Add a `Rule(...)` entry to `RULES` in `src/leakpulse/rules.py`. Keep the
   regex anchored enough to avoid matching documentation placeholders.
2. Prefer a specific prefix over a broad keyword. Ordered rules win overlaps,
   so put specific patterns first.
3. Add a positive case and a placeholder/negative case to
   `tests/test_rules.py`.
4. Update the rules table in `README.md` if you add a new category.

## Commit style

Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`) with a short
imperative subject. Keep commits focused.

## Code style

- 4-space indentation, type hints on public functions, `from __future__ import annotations`.
- Prefer small pure functions; keep the scanner testable without shelling out.
- Line length around 110 characters; no formatter is enforced.

## License

By contributing you agree that your changes are released under the MIT license.
