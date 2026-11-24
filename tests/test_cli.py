import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import support

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


class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_version(self):
        result = run_cli(["version"], self.root)
        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stdout.strip(), r"^\d+\.\d+\.\d+$")

    def test_clean_tree(self):
        (self.root / "app.py").write_text("print('hello')\n", encoding="utf-8")
        result = run_cli(["scan", ".", "--history", "0", "--json"], self.root)
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["summary"]["total"], 0)
        self.assertEqual(payload["findings"], [])

    def test_finding_produces_exit_one_and_redacted_json(self):
        secret = support.fake_secret(36, "ghp_")
        (self.root / "config.py").write_text(f"token = '{secret}'\n", encoding="utf-8")
        result = run_cli(["scan", ".", "--history", "0", "--json"], self.root)
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["summary"]["high"], 1)
        self.assertNotIn(secret, result.stdout)
        self.assertIn("*", payload["findings"][0]["match"])

    def test_fail_on_never(self):
        (self.root / "config.py").write_text(
            "token = '" + support.fake_secret(36, "ghp_") + "'\n", encoding="utf-8"
        )
        result = run_cli(["scan", ".", "--history", "0", "--fail-on", "never", "--json"], self.root)
        self.assertEqual(result.returncode, 0)

    def test_entropy_severity_and_threshold(self):
        (self.root / "data.txt").write_text(f'value = "{support.fake_secret(60)}"\n', encoding="utf-8")

        result = run_cli(["scan", ".", "--history", "0", "--json"], self.root)
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["summary"]["medium"], 1)

        result = run_cli(["scan", ".", "--history", "0", "--fail-on", "medium", "--json"], self.root)
        self.assertEqual(result.returncode, 1)

        result = run_cli(["scan", ".", "--history", "0", "--no-entropy", "--json"], self.root)
        self.assertEqual(json.loads(result.stdout)["summary"]["total"], 0)

    def test_exclude_flag(self):
        (self.root / "config.py").write_text(
            "token = '" + support.fake_secret(36, "ghp_") + "'\n", encoding="utf-8"
        )
        result = run_cli(
            ["scan", ".", "--history", "0", "--exclude", "config.py", "--json"], self.root
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["summary"]["total"], 0)

    def test_missing_path_is_usage_error(self):
        result = run_cli(["scan", "does-not-exist", "--history", "0"], self.root)
        self.assertEqual(result.returncode, 2)
        self.assertIn("no such file", result.stderr)

    def test_rules_json(self):
        result = run_cli(["rules", "--json"], self.root)
        self.assertEqual(result.returncode, 0)
        rules = json.loads(result.stdout)
        self.assertGreaterEqual(len(rules), 15)
        ids = [rule["id"] for rule in rules]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
