"""Distribution metadata tests: GitHub Action, pre-commit hooks, PyPI workflow.

These files are shipped to users, so a typo in an input name or a CLI flag breaks
adoption without any Python test failing. The checks below are deliberately
text-based (stdlib only) and cross-check the documented flags against the real
argparse definitions.
"""
from __future__ import annotations

import argparse
import re
import unittest
from pathlib import Path

from leakpulse import __version__
from leakpulse.cli import build_parser

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"
HOOKS = ROOT / ".pre-commit-hooks.yaml"
PUBLISH = ROOT / ".github" / "workflows" / "publish.yml"
DOCS = ROOT / "docs" / "distribution.md"

FLAG_RE = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)")


def _scan_parser() -> argparse.ArgumentParser:
    parser = build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices["scan"]
    raise AssertionError("scan subcommand is missing")


def _scan_flags() -> set:
    flags = set()
    for action in _scan_parser()._actions:
        flags.update(action.option_strings)
    return flags


class ActionMetadataTests(unittest.TestCase):
    def setUp(self):
        self.text = ACTION.read_text(encoding="utf-8")

    def test_declares_composite_action_with_documented_inputs(self):
        self.assertIn('using: "composite"', self.text)
        for name in ("path", "history", "fail-on", "extra-args"):
            self.assertRegex(self.text, rf"(?m)^  {re.escape(name)}:$")
        self.assertRegex(self.text, r"(?m)^outputs:$")
        self.assertRegex(self.text, r"(?m)^  exit-code:$")

    def test_inputs_are_passed_through_env_not_inlined_in_shell(self):
        self.assertIn("LEAKPULSE_PATH: ${{ inputs.path }}", self.text)
        self.assertIn("LEAKPULSE_FAIL_ON: ${{ inputs.fail-on }}", self.text)
        # The run body must use the env vars so quoting stays safe.
        body = self.text.split("run: |", 2)[-1]
        self.assertIn('"$LEAKPULSE_PATH"', body)
        self.assertIn('--fail-on "$LEAKPULSE_FAIL_ON"', body)

    def test_installs_from_the_pinned_action_checkout(self):
        self.assertIn('"${GITHUB_ACTION_PATH}"', self.text)
        self.assertNotIn("pip install leakpulse", self.text)

    def test_every_cli_flag_used_by_the_action_exists(self):
        known = _scan_flags()
        invocation = self.text.split('leakpulse scan "$LEAKPULSE_PATH"', 1)[1].split("code=$?", 1)[0]
        used = set(FLAG_RE.findall(invocation))
        self.assertTrue(used, "action.yml does not invoke any CLI flags")
        self.assertEqual(sorted(used - known), [], f"unknown flags in action.yml: {sorted(used - known)}")

    def test_reports_exit_code_without_masking_failure(self):
        self.assertIn('echo "exit-code=$code" >> "$GITHUB_OUTPUT"', self.text)
        self.assertIn('exit "$code"', self.text)


class PreCommitHookTests(unittest.TestCase):
    def setUp(self):
        self.text = HOOKS.read_text(encoding="utf-8")

    def test_hooks_are_declared(self):
        ids = re.findall(r"(?m)^- id: (\S+)$", self.text)
        self.assertEqual(ids, ["leakpulse", "leakpulse-worktree"])

    def test_entries_only_use_real_cli_flags(self):
        known = _scan_flags()
        entries = re.findall(r"(?m)^  entry: (.+)$", self.text)
        self.assertEqual(len(entries), 2)
        for entry in entries:
            self.assertTrue(entry.startswith("leakpulse scan "))
            self.assertEqual(sorted(set(FLAG_RE.findall(entry)) - known), [])

    def test_staged_hook_is_fast_and_sees_all_staged_files(self):
        block = self.text.split("- id: leakpulse-worktree")[0]
        self.assertIn("--staged", block)
        self.assertIn("language: python", block)
        self.assertIn("pass_filenames: false", block)
        self.assertIn("always_run: true", block)


class PublishWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = PUBLISH.read_text(encoding="utf-8")

    def test_uses_trusted_publishing_without_stored_secrets(self):
        self.assertIn("id-token: write", self.text)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", self.text)
        self.assertIn("environment:", self.text)
        self.assertIn("name: pypi", self.text)
        self.assertNotRegex(self.text, r"(?i)(password|api[_-]?token)\s*:")
        self.assertNotIn("secrets.", self.text)

    def test_publishes_only_on_version_tags(self):
        self.assertIn('      - "v*"', self.text)
        self.assertIn("startsWith(github.ref, 'refs/tags/')", self.text)

    def test_publish_waits_for_tests_and_build(self):
        self.assertIn("needs: test", self.text)
        self.assertIn("needs: build", self.text)
        self.assertIn("run: python run_tests.py", self.text)

    def test_rejects_tag_version_mismatch(self):
        self.assertIn("src/leakpulse/__init__.py", self.text)
        self.assertIn("does not match package version", self.text)


class DocumentationTests(unittest.TestCase):
    def test_docs_pin_the_current_version(self):
        text = DOCS.read_text(encoding="utf-8")
        self.assertIn(f"stackpulse-lab/leakpulse@v{__version__}", text)
        self.assertIn(f"rev: v{__version__}", text)

    def test_readme_links_the_distribution_guide(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/distribution.md", readme)


if __name__ == "__main__":
    unittest.main()
