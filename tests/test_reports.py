"""Tests for SARIF and HTML report exporters (stdlib only)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import support

from leakpulse import __version__
from leakpulse.exporters import render_html, render_sarif
from leakpulse.rules import RULES
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


def sample_findings():
    secret = support.fake_secret(36, "ghp_")
    return [
        Finding(
            rule_id="github-token",
            description="GitHub token (classic app/OAuth/refresh)",
            severity="high",
            path="config dir/app.py",
            line=12,
            value=secret,
        ),
        Finding(
            rule_id="high-entropy-string",
            description="High-entropy string (possible secret)",
            severity="medium",
            path="deploy/prod.env",
            line=5,
            value=support.fake_secret(40),
            commit="deadbeef",
        ),
    ]


class SarifTests(unittest.TestCase):
    def setUp(self):
        self.findings = sample_findings()
        self.doc = json.loads(render_sarif(self.findings, 12, 3, 0.25, 1, __version__))

    def test_top_level_shape(self):
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", self.doc["$schema"])
        self.assertEqual(len(self.doc["runs"]), 1)

    def test_driver_lists_every_rule_plus_entropy(self):
        rules = self.doc["runs"][0]["tool"]["driver"]["rules"]
        ids = [rule["id"] for rule in rules]
        self.assertEqual(ids[: len(RULES)], [rule.id for rule in RULES])
        self.assertEqual(ids[-1], "high-entropy-string")
        self.assertEqual(len(ids), len(RULES) + 1)

    def test_results_map_severity_to_sarif_level(self):
        results = self.doc["runs"][0]["results"]
        self.assertEqual([r["level"] for r in results], ["error", "warning"])
        self.assertEqual(results[0]["ruleId"], "github-token")
        self.assertEqual(results[1]["properties"]["commit"], "deadbeef")

    def test_locations_are_relative_and_encoded(self):
        location = self.doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "config%20dir/app.py")
        self.assertEqual(location["region"]["startLine"], 12)

    def test_no_full_secret_in_sarif(self):
        rendered = json.dumps(self.doc)
        for finding in self.findings:
            self.assertNotIn(finding.value, rendered)
        self.assertIn("*", self.doc["runs"][0]["results"][0]["message"]["text"])

    def test_fingerprints_are_stable_and_present(self):
        first = self.doc["runs"][0]["results"][0]["partialFingerprints"]["leakpulse/v1"]
        again = json.loads(
            render_sarif(self.findings, 12, 3, 9.0, 1, __version__)
        )["runs"][0]["results"][0]["partialFingerprints"]["leakpulse/v1"]
        self.assertEqual(first, again)
        self.assertEqual(len(first), 20)

    def test_invocation_records_scope_and_exit_code(self):
        invocation = self.doc["runs"][0]["invocations"][0]
        self.assertTrue(invocation["executionSuccessful"])
        self.assertEqual(invocation["properties"]["exitCode"], 1)
        self.assertEqual(invocation["properties"]["filesScanned"], 12)
        self.assertEqual(self.doc["runs"][0]["properties"]["summary"]["high"], 1)


class HtmlTests(unittest.TestCase):
    def test_report_contains_counts_and_masked_matches(self):
        findings = sample_findings()
        text = render_html(
            findings, 7, 0, 0.1, 1, __version__, generated_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        )
        self.assertIn("<!DOCTYPE html>", text)
        self.assertIn("2026-01-02 03:04:05 UTC", text)
        self.assertIn(">1</span>high", text)
        self.assertIn(">2</span>total", text)
        self.assertIn("github-token", text)
        for finding in findings:
            self.assertNotIn(finding.value, text)

    def test_report_escapes_untrusted_text(self):
        finding = Finding(
            rule_id="generic-secret-assignment",
            description="<script>alert('x')</script>",
            severity="low",
            path="docs/<img src=x>.md",
            line=3,
            value="abcdefghijklmnopqrstuvwxyz123456",
        )
        text = render_html([finding], 1, 0, 0.0, 0, __version__)
        self.assertNotIn("<script>alert", text)
        self.assertNotIn("<img src=x>", text)
        self.assertIn("&lt;script&gt;alert", text)

    def test_report_has_no_remote_assets(self):
        text = render_html([], 0, 0, 0.0, 0, __version__)
        self.assertNotIn("http://", text)
        self.assertNotIn("https://", text)
        self.assertIn("No potential secrets found.", text)


class CliReportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.secret = support.fake_secret(36, "ghp_")
        (self.root / "app.py").write_text(f"token = '{self.secret}'\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_sarif_to_stdout(self):
        result = run_cli(["scan", ".", "--history", "0", "--format", "sarif"], self.root)
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(len(payload["runs"][0]["results"]), 1)
        self.assertNotIn(self.secret, result.stdout)

    def test_json_flag_is_an_alias_for_format_json(self):
        result = run_cli(["scan", ".", "--history", "0", "--json"], self.root)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["tool"], "leakpulse")

    def test_conflicting_json_and_format_is_a_usage_error(self):
        result = run_cli(
            ["scan", ".", "--history", "0", "--json", "--format", "html"], self.root
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--json conflicts", result.stderr)

    def test_output_writes_file_and_keeps_exit_code(self):
        out = self.root / "reports" / "audit.html"
        result = run_cli(
            ["scan", ".", "--history", "0", "--format", "html", "--output", str(out)],
            self.root,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("wrote", result.stderr)
        text = out.read_text(encoding="utf-8")
        self.assertIn("LeakPulse audit report", text)
        self.assertNotIn(self.secret, text)

    def test_quiet_still_writes_text_report_when_output_is_set(self):
        out = self.root / "clean.txt"
        (self.root / "app.py").write_text("print('ok')\n", encoding="utf-8")
        result = run_cli(
            ["scan", ".", "--history", "0", "--quiet", "--output", str(out)], self.root
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("No potential secrets found.", out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
