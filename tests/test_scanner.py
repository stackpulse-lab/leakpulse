import tempfile
import unittest
from pathlib import Path

import support
from leakpulse.scanner import (
    IgnoreList,
    ScanOptions,
    dedupe,
    mask_secret,
    parse_patch,
    scan_file,
    scan_path,
    scan_text,
)


class MaskTests(unittest.TestCase):
    def test_mask_keeps_context_but_hides_body(self):
        secret = support.fake_secret(36, "ghp_")
        masked = mask_secret(secret)
        self.assertTrue(masked.startswith("ghp_"))
        self.assertIn("*", masked)
        self.assertNotIn(secret[4:-4], masked)
        self.assertLess(len(masked), len(secret))

    def test_short_values_are_fully_masked(self):
        self.assertEqual(mask_secret("short"), "*****")


class IgnoreListTests(unittest.TestCase):
    def test_patterns_and_negation(self):
        ignore = IgnoreList(["secrets/**", "*.log", "!keep.log"])
        self.assertTrue(ignore.ignored("secrets/prod.env"))
        self.assertTrue(ignore.ignored("app.log"))
        self.assertFalse(ignore.ignored("keep.log"))
        self.assertFalse(ignore.ignored(".github/workflows/ci.yml"))

    def test_directory_pattern(self):
        ignore = IgnoreList(["vendor/"])
        self.assertTrue(ignore.ignored("vendor/lib/secret.py"))

    def test_load_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".leakpulseignore"
            path.write_text("# comment\nfixtures/**\n", encoding="utf-8")
            ignore = IgnoreList.load(path, extra=["extra.txt"])
            self.assertTrue(ignore.ignored("fixtures/a.txt"))
            self.assertTrue(ignore.ignored("extra.txt"))


class ScanTextTests(unittest.TestCase):
    def test_detects_secret_and_masks_it(self):
        secret = support.fake_secret(36, "ghp_")
        findings = scan_text(f"token = '{secret}'", "app.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "github-token")
        self.assertNotIn(secret, findings[0].masked)
        self.assertEqual(findings[0].line, 1)

    def test_inline_allow_suppresses_line(self):
        secret = support.fake_secret(36, "ghp_")
        findings = scan_text(f"token = '{secret}'  # leakpulse:allow", "app.py")
        self.assertEqual(findings, [])

    def test_entropy_can_be_disabled(self):
        line = f'data = "{support.fake_secret(60)}"'
        with_entropy = scan_text(line, "a.txt")
        without_entropy = scan_text(line, "a.txt", ScanOptions(entropy=False))
        self.assertEqual(len(with_entropy), 1)
        self.assertEqual(without_entropy, [])

    def test_duplicate_secret_dedupes(self):
        secret = support.fake_secret(36, "ghp_")
        text = f"a = '{secret}'\nb = '{secret}'\n"
        findings = dedupe(scan_text(text, "a.py"))
        self.assertEqual(len(findings), 1)

    def test_line_numbers(self):
        secret = support.fake_secret(36, "ghp_")
        text = "line one\nline two\n" + f"token = '{secret}'\n"
        findings = scan_text(text, "a.py")
        self.assertEqual(findings[0].line, 3)


class FileAndTreeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_scan_file(self):
        secret = support.fake_secret(36, "ghp_")
        path = self.root / "app.py"
        path.write_text(f"token = '{secret}'\n", encoding="utf-8")
        findings = scan_file(path, "app.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "app.py")

    def test_binary_files_are_skipped(self):
        path = self.root / "blob.bin"
        path.write_bytes(b"\x00\x01" + support.fake_secret(36, "ghp_").encode())
        self.assertEqual(scan_file(path, "blob.bin"), [])

    def test_large_files_are_skipped(self):
        path = self.root / "big.txt"
        path.write_text(support.fake_secret(36, "ghp_") + "\n" * 100, encoding="utf-8")
        self.assertEqual(scan_file(path, "big.txt", ScanOptions(max_file_bytes=10)), [])

    def test_scan_path_obeys_ignore_list(self):
        ignored = self.root / "fixtures"
        ignored.mkdir()
        (ignored / "a.py").write_text(f"token = '{support.fake_secret(36, 'ghp_')}'", encoding="utf-8")
        (self.root / "b.py").write_text("print('ok')\n", encoding="utf-8")
        findings, files_scanned = scan_path(self.root, ignore=IgnoreList(["fixtures/"]))
        self.assertEqual(findings, [])
        self.assertEqual(files_scanned, 2)

    def test_lockfiles_are_excluded_by_default(self):
        (self.root / "package-lock.json").write_text(
            '{"integrity": "' + support.fake_secret(60) + '"}', encoding="utf-8"
        )
        findings, _ = scan_path(self.root)
        self.assertEqual(findings, [])
        findings, _ = scan_path(self.root, ScanOptions(include_default_excluded=True))
        self.assertEqual(len(findings), 1)

    def test_dedupe_sorts_by_severity(self):
        low = scan_text(f'data = "{support.fake_secret(60)}"', "a.txt")
        high = scan_text(f"token = '{support.fake_secret(36, 'ghp_')}'", "b.txt")
        ordered = dedupe(high + low)
        self.assertEqual(ordered[0].severity, "high")
        self.assertEqual(ordered[-1].severity, "medium")


class PatchParserTests(unittest.TestCase):
    def test_added_lines_are_scanned_with_line_numbers(self):
        secret = support.fake_secret(36, "ghp_")
        patch = (
            "diff --git a/app.py b/app.py\n"
            "index 111..222 100644\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -10,2 +10,3 @@\n"
            " context\n"
            f"+token = '{secret}'\n"
            "+safe = 1\n"
        )
        findings = parse_patch(patch, commit="abc12345")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 11)
        self.assertEqual(findings[0].commit, "abc12345")
        self.assertEqual(findings[0].path, "app.py")

    def test_removed_lines_are_not_scanned(self):
        secret = support.fake_secret(36, "ghp_")
        patch = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1 +1 @@\n"
            f"-token = '{secret}'\n"
            "+token = 'rotated'\n"
        )
        self.assertEqual(parse_patch(patch), [])

    def test_deleted_files_are_skipped(self):
        secret = support.fake_secret(36, "ghp_")
        patch = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            f"-token = '{secret}'\n"
        )
        self.assertEqual(parse_patch(patch), [])


if __name__ == "__main__":
    unittest.main()
