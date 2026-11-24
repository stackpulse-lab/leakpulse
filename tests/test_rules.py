import unittest

import support
from leakpulse.rules import RULES, RULES_BY_ID, is_placeholder, is_reference
from leakpulse.scanner import ScanOptions, scan_text

NO_ENTROPY = ScanOptions(entropy=False)


def scan(line: str):
    return scan_text(line, "sample.py", NO_ENTROPY)


class RuleDetectionTests(unittest.TestCase):
    def assert_rule(self, line: str, rule_id: str) -> None:
        ids = [finding.rule_id for finding in scan(line)]
        self.assertIn(rule_id, ids, f"expected {rule_id}, got {ids} for {line!r}")

    def assert_no_findings(self, line: str) -> None:
        findings = scan(line)
        self.assertEqual(findings, [], f"unexpected findings {[f.rule_id for f in findings]}")

    def test_rule_ids_are_unique(self):
        ids = [rule.id for rule in RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_private_key_block(self):
        self.assert_rule("-----BEGIN RSA PRIVATE KEY-----", "private-key-block")
        self.assert_rule("-----BEGIN OPENSSH PRIVATE KEY-----", "private-key-block")

    def test_aws_access_key(self):
        self.assert_rule(f"AWS_ACCESS_KEY_ID=AKIA{support.fake_upper(16)}", "aws-access-key-id")

    def test_github_tokens(self):
        self.assert_rule(f"token: {support.fake_secret(36, 'ghp_')}", "github-token")
        self.assert_rule(f"pat = '{support.fake_secret(30, 'github_pat_')}'", "github-pat")

    def test_anthropic_wins_over_generic_openai_rule(self):
        line = f'key = "{support.fake_secret(30, "sk-ant-")}"'
        findings = scan(line)
        self.assertEqual([finding.rule_id for finding in findings], ["anthropic-key"])

    def test_openai_key(self):
        self.assert_rule(f'OPENAI_API_KEY="{support.fake_secret(32, "sk-")}"', "openai-key")

    def test_mail_and_payment_keys(self):
        self.assert_rule(f'RESEND_API_KEY="{support.fake_secret(24, "re_")}"', "resend-key")
        self.assert_rule(f'key = "SG.{support.fake_secret(16)}.{support.fake_secret(16)}"', "sendgrid-key")
        self.assert_rule(f'stripe = "{support.fake_secret(24, "sk_live_")}"', "stripe-key")

    def test_slack_google_npm_tokens(self):
        self.assert_rule(f'slack = "{support.fake_secret(20, "xoxb-")}"', "slack-token")
        self.assert_rule(f'g = "{support.fake_secret(35, "AIza")}"', "google-api-key")
        self.assert_rule(f'npm = "{support.fake_secret(36, "npm_")}"', "npm-token")

    def test_url_with_credentials(self):
        line = f"DATABASE_URL=postgres://app:{support.fake_secret(16)}@db.prod.internal:5432/app"
        self.assert_rule(line, "url-basic-auth")

    def test_bearer_token(self):
        self.assert_rule(f"Authorization: Bearer {support.fake_secret(32)}", "bearer-token")

    def test_jwt(self):
        line = (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            + support.fake_secret(43)
        )
        self.assert_rule(line, "jwt")

    def test_generic_assignment(self):
        self.assert_rule('password = "Tr0ub4dor3xyz9Q"', "generic-secret-assignment")
        self.assert_rule(f'api_key: {support.fake_secret(20)}', "generic-secret-assignment")

    def test_placeholders_are_suppressed(self):
        for line in (
            'api_key = "your_api_key_here_1234"',
            'password = "changeme123456"',
            'secret = "${SECRET_VALUE}"',
            'token = "example-token-123456"',
            'api_key = "xxxxxxxxxxxxxxxxxxxx"',
        ):
            self.assert_no_findings(line)

    def test_code_references_are_suppressed(self):
        for line in (
            'API_KEY = os.environ.get("API_KEY")',
            "token = process.env.GITHUB_TOKEN",
            "api_key = config.get_api_key()",
        ):
            self.assert_no_findings(line)

    def test_ordinary_code_is_clean(self):
        for line in (
            "def load_secret(path):",
            "    return path.read_text()",
            "max_retries = 3",
            "url = 'https://api.github.com/user'",
        ):
            self.assert_no_findings(line)


class HelperTests(unittest.TestCase):
    def test_placeholder_detection(self):
        self.assertTrue(is_placeholder("your_token_here_1234"))
        self.assertTrue(is_placeholder("aaaa"))
        self.assertFalse(is_placeholder(support.fake_secret(32)))

    def test_reference_detection(self):
        self.assertTrue(is_reference("os.environ.get"))
        self.assertTrue(is_reference("process.env.X"))
        self.assertFalse(is_reference(support.fake_secret(32)))

    def test_rules_registry(self):
        self.assertIn("github-token", RULES_BY_ID)
        self.assertGreaterEqual(len(RULES), 15)


if __name__ == "__main__":
    unittest.main()
