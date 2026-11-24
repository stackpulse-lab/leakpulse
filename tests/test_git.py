import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import support
from leakpulse.cli import main


@unittest.skipUnless(shutil.which("git"), "git is required for integration tests")
class GitIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.email", "test@example.com")
        self._git("config", "user.name", "Test")

    def tearDown(self):
        self._tmp.cleanup()

    def _git(self, *args):
        subprocess.run(
            ["git", *args],
            cwd=self.repo,
            check=True,
            capture_output=True,
            text=True,
        )

    def _commit(self, message):
        self._git("add", "-A")
        self._git("commit", "-q", "-m", message)

    def _run(self, args):
        out, err = io.StringIO(), io.StringIO()
        with support.chdir(self.repo), redirect_stdout(out), redirect_stderr(err):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    def test_staged_scan_finds_secret_and_ignores_unstaged(self):
        secret = support.fake_secret(36, "ghp_")
        (self.repo / "config.py").write_text(f"token = '{secret}'\n", encoding="utf-8")
        self._git("add", "config.py")
        (self.repo / "untracked.py").write_text("token = '" + support.fake_secret(36, "ghp_") + "'\n")

        code, out, _ = self._run(["scan", "--staged", "--json"])
        payload = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(payload["summary"]["high"], 1)
        self.assertEqual(payload["findings"][0]["path"], "config.py")
        self.assertIsNone(payload["findings"][0]["commit"])
        self.assertNotIn(secret, out)

    def test_staged_scan_is_clean_when_index_is_clean(self):
        (self.repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
        self._commit("initial")
        code, out, _ = self._run(["scan", "--staged", "--json"])
        payload = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(payload["summary"]["total"], 0)
        self.assertEqual(payload["scanned"]["files"], 0)

    def test_history_scan_finds_removed_secret(self):
        secret = support.fake_secret(36, "ghp_")
        (self.repo / "app.py").write_text(f"token = '{secret}'\n", encoding="utf-8")
        self._commit("add config with token")
        (self.repo / "app.py").write_text("token = 'rotated'\n", encoding="utf-8")
        self._commit("rotate token")

        code, out, _ = self._run(["scan", ".", "--history", "2", "--json"])
        payload = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(payload["summary"]["high"], 1)
        finding = payload["findings"][0]
        self.assertIsNotNone(finding["commit"])
        self.assertEqual(len(finding["commit"]), 8)
        self.assertNotIn(secret, out)

        code, out, _ = self._run(["scan", ".", "--history", "0", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["summary"]["total"], 0)

    def test_history_scan_requires_no_duplicate_of_worktree(self):
        secret = support.fake_secret(36, "ghp_")
        (self.repo / "app.py").write_text(f"token = '{secret}'\n", encoding="utf-8")
        self._commit("add token")
        code, out, _ = self._run(["scan", ".", "--history", "5", "--json"])
        payload = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(payload["summary"]["total"], 1)

    def test_install_hook_and_refuse_foreign_hook(self):
        code, out, _ = self._run(["install-hook", "--repo", str(self.repo)])
        self.assertEqual(code, 0)
        hook = self.repo / ".git" / "hooks" / "pre-commit"
        self.assertTrue(hook.is_file())
        self.assertTrue(os.access(hook, os.X_OK))
        self.assertIn("leakpulse scan --staged", hook.read_text(encoding="utf-8"))

        # Re-installing our own hook is fine.
        code, _, _ = self._run(["install-hook", "--repo", str(self.repo)])
        self.assertEqual(code, 0)

        hook.write_text("#!/bin/sh\necho legacy\n", encoding="utf-8")
        code, _, err = self._run(["install-hook", "--repo", str(self.repo)])
        self.assertEqual(code, 2)
        self.assertIn("--force", err)

        code, _, _ = self._run(["install-hook", "--repo", str(self.repo), "--force"])
        self.assertEqual(code, 0)

    def test_staged_scan_outside_repository_fails(self):
        with tempfile.TemporaryDirectory() as outside:
            out, err = io.StringIO(), io.StringIO()
            with support.chdir(outside), redirect_stdout(out), redirect_stderr(err):
                code = main(["scan", "--staged"])
        self.assertEqual(code, 2)
        self.assertIn("git repository", err.getvalue())


if __name__ == "__main__":
    unittest.main()
