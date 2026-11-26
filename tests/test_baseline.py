"""Baseline tests: accept known findings so CI fails only on new secrets."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import support
from leakpulse import baseline
from leakpulse.scanner import Finding

SRC = Path(__file__).resolve().parents[1] / "src"


def run_cli(args, cwd):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC)
    env.pop("NO_COLOR", None)
    return subprocess.run(
        [sys.executable, "-m", "leakpulse", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def finding(value: str, path: str = "config.py", line: int = 1, rule: str = "github-token") -> Finding:
    return Finding(
        rule_id=rule,
        description="GitHub token",
        severity="high",
        path=path,
        line=line,
        value=value,
    )


class BaselineDocumentTests(unittest.TestCase):
    def test_document_records_only_hashes(self):
        secret = support.fake_secret(36, "ghp_")
        document = baseline.build_baseline([finding(secret)], "0.5.0")
        self.assertEqual(document["schema"], baseline.BASELINE_SCHEMA)
        self.assertEqual(document["tool"], "leakpulse 0.5.0")
        self.assertEqual(document["count"], 1)
        self.assertEqual(len(document["fingerprints"]), 1)
        self.assertRegex(document["fingerprints"][0], r"^[0-9a-f]{20}$")
        text = json.dumps(document)
        self.assertNotIn(secret, text)
        self.assertNotIn(secret[:8], text)

    def test_duplicates_collapse_and_order_is_stable(self):
        secret = support.fake_secret(36, "ghp_")
        first = baseline.build_baseline([finding(secret), finding(secret, line=9)], "0.5.0")
        second = baseline.build_baseline([finding(secret, line=9), finding(secret)], "0.5.0")
        self.assertEqual(first["fingerprints"], second["fingerprints"])
        self.assertEqual(first["count"], 1)

    def test_fingerprint_ignores_line_but_tracks_value(self):
        secret = support.fake_secret(36, "ghp_")
        self.assertEqual(finding(secret, line=1).fingerprint, finding(secret, line=42).fingerprint)
        self.assertNotEqual(finding(secret).fingerprint, finding(secret + "x").fingerprint)
        self.assertNotEqual(finding(secret).fingerprint, finding(secret, path="other.py").fingerprint)

    def test_write_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "baseline.json"
            count = baseline.write_baseline(path, [finding(support.fake_secret(36, "ghp_"))], "0.5.0")
            self.assertEqual(count, 1)
            self.assertTrue(path.is_file())
            accepted = baseline.load_baseline(path)
            self.assertEqual(len(accepted), 1)

    def test_load_rejects_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(baseline.BaselineError):
                baseline.load_baseline(Path(tmp) / "missing.json")

    def test_load_rejects_unknown_schema_and_bad_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(json.dumps({"schema": "other/1", "fingerprints": []}), encoding="utf-8")
            with self.assertRaises(baseline.BaselineError):
                baseline.load_baseline(path)
            path.write_text(json.dumps({"schema": baseline.BASELINE_SCHEMA, "fingerprints": [1]}), encoding="utf-8")
            with self.assertRaises(baseline.BaselineError):
                baseline.load_baseline(path)
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(baseline.BaselineError):
                baseline.load_baseline(path)

    def test_split_keeps_only_new_findings(self):
        known = finding(support.fake_secret(36, "ghp_"))
        fresh = finding(support.fake_secret(36, "ghp_"), path="new.py")
        new, suppressed = baseline.split_by_baseline([known, fresh], {known.fingerprint})
        self.assertEqual(new, [fresh])
        self.assertEqual(suppressed, [known])


class BaselineCliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _legacy_repo(self):
        secret = support.fake_secret(36, "ghp_")
        (self.root / "config.py").write_text(f"token = '{secret}'\n", encoding="utf-8")
        return secret

    def test_write_baseline_always_exits_zero(self):
        secret = self._legacy_repo()
        path = self.root / "leakpulse-baseline.json"
        result = run_cli(["scan", ".", "--history", "0", "--write-baseline", str(path)], self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("recorded 1 fingerprint(s)", result.stderr)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["count"], 1)
        self.assertNotIn(secret, path.read_text(encoding="utf-8"))
        self.assertNotIn(secret, result.stdout)

    def test_baseline_suppresses_known_and_fails_on_new(self):
        self._legacy_repo()
        path = self.root / "leakpulse-baseline.json"
        run_cli(["scan", ".", "--history", "0", "--write-baseline", str(path)], self.root)

        result = run_cli(["scan", ".", "--history", "0", "--baseline", str(path), "--json"], self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["summary"]["total"], 0)
        self.assertEqual(payload["baseline"]["suppressed"], 1)

        (self.root / "new.py").write_text("token = '" + support.fake_secret(36, "ghp_") + "'\n", encoding="utf-8")
        result = run_cli(["scan", ".", "--history", "0", "--baseline", str(path), "--json"], self.root)
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["findings"][0]["path"], "new.py")
        self.assertEqual(payload["baseline"]["suppressed"], 1)

    def test_suppression_survives_line_moves(self):
        self._legacy_repo()
        path = self.root / "leakpulse-baseline.json"
        run_cli(["scan", ".", "--history", "0", "--write-baseline", str(path)], self.root)
        secret = support.fake_secret(36, "ghp_")
        (self.root / "config.py").write_text(
            f"# header\n\n\n\ntoken = '{secret}'\n", encoding="utf-8"
        )
        result = run_cli(["scan", ".", "--history", "0", "--baseline", str(path), "--no-color"], self.root)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("1 known finding suppressed by baseline", result.stdout)

    def test_invalid_baseline_is_a_usage_error(self):
        self._legacy_repo()
        path = self.root / "bad.json"
        path.write_text("{}", encoding="utf-8")
        result = run_cli(["scan", ".", "--history", "0", "--baseline", str(path)], self.root)
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsupported schema", result.stderr)

    def test_write_and_read_baseline_are_mutually_exclusive(self):
        self._legacy_repo()
        path = str(self.root / "leakpulse-baseline.json")
        result = run_cli(
            ["scan", ".", "--history", "0", "--baseline", path, "--write-baseline", path], self.root
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("mutually exclusive", result.stderr)

    def test_sarif_and_html_exclude_suppressed_findings(self):
        self._legacy_repo()
        path = self.root / "leakpulse-baseline.json"
        run_cli(["scan", ".", "--history", "0", "--write-baseline", str(path)], self.root)

        sarif = run_cli(
            ["scan", ".", "--history", "0", "--baseline", str(path), "--format", "sarif"], self.root
        )
        self.assertEqual(sarif.returncode, 0, sarif.stderr)
        payload = json.loads(sarif.stdout)
        self.assertEqual(payload["runs"][0]["results"], [])
        self.assertEqual(payload["runs"][0]["properties"]["baseline"]["suppressed"], 1)

        html = run_cli(
            ["scan", ".", "--history", "0", "--baseline", str(path), "--format", "html"], self.root
        )
        self.assertEqual(html.returncode, 0, html.stderr)
        self.assertIn("1 known finding(s) suppressed by", html.stdout)


class BaselineDocsTests(unittest.TestCase):
    def test_baseline_guide_pins_the_current_version(self):
        from leakpulse import __version__

        text = (Path(__file__).resolve().parents[1] / "docs" / "baseline.md").read_text(encoding="utf-8")
        self.assertIn(f"stackpulse-lab/leakpulse@v{__version__}", text)

    def test_readme_links_the_baseline_guide(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/baseline.md", readme)


if __name__ == "__main__":
    unittest.main()
