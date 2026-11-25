"""Localization rules: Chinese cloud providers and domestic SaaS webhooks.

Every sample token is generated at runtime so this repository never stores a
literal that looks like a live credential.
"""
import unittest

import support
from leakpulse.report import render_text
from leakpulse.rules import RULES, RULES_BY_ID
from leakpulse.scanner import ScanOptions, mask_secret, scan_text

NO_ENTROPY = ScanOptions(entropy=False)


def scan(line: str):
    return scan_text(line, "config.py", NO_ENTROPY)


def hex_secret(length: int = 32) -> str:
    alphabet = "0123456789abcdef"
    return "".join(alphabet[(index * 7 + 3) % len(alphabet)] for index in range(length))


class ChinaRuleDetectionTests(unittest.TestCase):
    def assert_rule(self, line: str, rule_id: str) -> None:
        ids = [finding.rule_id for finding in scan(line)]
        self.assertIn(rule_id, ids, f"expected {rule_id}, got {ids} for {line!r}")

    def test_deepseek_key_wins_and_is_not_reported_as_openai(self):
        line = f'DEEPSEEK_API_KEY="{support.fake_secret(32, "sk-")}"'
        findings = scan(line)
        self.assertEqual([finding.rule_id for finding in findings], ["deepseek-key"])

    def test_plain_openai_key_still_uses_openai_rule(self):
        line = f'OPENAI_API_KEY="{support.fake_secret(32, "sk-")}"'
        self.assertEqual([f.rule_id for f in scan(line)], ["openai-key"])

    def test_aliyun_access_key_id(self):
        self.assert_rule(f"ALIBABA_CLOUD_ACCESS_KEY_ID=LTAI{support.fake_secret(20)}", "aliyun-access-key-id")

    def test_aliyun_access_key_secret(self):
        line = f"ALIBABA_CLOUD_ACCESS_KEY_SECRET={support.fake_secret(30)}"
        self.assert_rule(line, "aliyun-access-key-secret")

    def test_tencent_secret_id(self):
        self.assert_rule(f"secret_id = 'AKID{support.fake_secret(32)}'", "tencent-secret-id")

    def test_tencent_secret_key(self):
        line = f"TENCENTCLOUD_SECRET_KEY={support.fake_secret(32)}"
        self.assert_rule(line, "tencent-secret-key")

    def test_volcengine_access_key_id(self):
        self.assert_rule(f"VOLC_ACCESSKEY=AKLT{support.fake_secret(32)}", "volcengine-access-key-id")

    def test_feishu_webhook(self):
        line = "hook = https://open.feishu.cn/open-apis/bot/v2/hook/" + hex_secret(36)
        self.assert_rule(line, "feishu-webhook")
        lark = "hook = https://open.larksuite.com/open-apis/bot/v2/hook/" + hex_secret(36)
        self.assert_rule(lark, "feishu-webhook")

    def test_wecom_webhook(self):
        line = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=" + hex_secret(36)
        self.assert_rule(line, "wecom-webhook")

    def test_dingtalk_webhook(self):
        line = "https://oapi.dingtalk.com/robot/send?access_token=" + hex_secret(64)
        self.assert_rule(line, "dingtalk-webhook")

    def test_afdian_token(self):
        self.assert_rule(f"AFDIAN_TOKEN={hex_secret(32)}", "afdian-token")


class ChinaRuleMaskingTests(unittest.TestCase):
    """Redaction must never echo the captured credential."""

    SAMPLES = (
        ("deepseek-key", f'DEEPSEEK_API_KEY="{support.fake_secret(32, "sk-")}"'),
        ("aliyun-access-key-id", f"AK=LTAI{support.fake_secret(20)}"),
        ("aliyun-access-key-secret", f"ALIYUN_ACCESS_KEY_SECRET={support.fake_secret(30)}"),
        ("tencent-secret-id", f"id=AKID{support.fake_secret(32)}"),
        ("tencent-secret-key", f"TENCENT_SECRET_KEY={support.fake_secret(32)}"),
        ("volcengine-access-key-id", f"k=AKLT{support.fake_secret(32)}"),
        ("feishu-webhook", "https://open.feishu.cn/open-apis/bot/v2/hook/" + hex_secret(36)),
        ("wecom-webhook", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=" + hex_secret(36)),
        ("dingtalk-webhook", "https://oapi.dingtalk.com/robot/send?access_token=" + hex_secret(64)),
        ("afdian-token", f"AFDIAN_TOKEN={hex_secret(32)}"),
    )

    def test_masked_value_hides_body(self):
        for rule_id, line in self.SAMPLES:
            findings = scan(line)
            self.assertEqual(len(findings), 1, f"{rule_id}: {findings}")
            finding = findings[0]
            self.assertEqual(finding.rule_id, rule_id)
            self.assertNotIn(finding.value, finding.masked)
            self.assertIn("*", finding.masked)
            # only the 4-char prefix/suffix may survive
            self.assertEqual(finding.masked[4:-4], "*" * len(finding.masked[4:-4]))
            self.assertNotIn(finding.value, finding.to_dict()["match"])

    def test_text_report_hides_body(self):
        for rule_id, line in self.SAMPLES:
            findings = scan(line)
            rendered = render_text(findings, 1, 0, 0.0, color=False)
            self.assertNotIn(findings[0].value, rendered, rule_id)
            self.assertIn(rule_id, rendered)

    def test_webhook_reports_only_mask_not_full_url(self):
        url = "https://oapi.dingtalk.com/robot/send?access_token=" + hex_secret(64)
        finding = scan(url)[0]
        self.assertNotIn("https://", finding.masked)
        self.assertNotIn("access_token=", finding.masked)

    def test_mask_boundary_for_short_values(self):
        self.assertEqual(mask_secret(hex_secret(8)), "*" * 8)


class ChinaRuleQuietTests(unittest.TestCase):
    def assert_no_findings(self, line: str) -> None:
        findings = scan(line)
        self.assertEqual(findings, [], f"unexpected findings {[f.rule_id for f in findings]}")

    def test_placeholders_are_suppressed(self):
        for line in (
            "ALIBABA_CLOUD_ACCESS_KEY_SECRET=your_access_key_secret_here",
            "TENCENT_SECRET_KEY=${TENCENT_SECRET_KEY}",
            "AK=LTAIxxxxxxxxxxxxxxxxxxxx",
            "DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx",
            "AFDIAN_TOKEN=00000000000000000000000000000000",
        ):
            self.assert_no_findings(line)

    def test_documentation_urls_are_clean(self):
        for line in (
            "See https://open.feishu.cn/document/server-docs/im-v1/message/create",
            "docs: https://qyapi.weixin.qq.com/cgi-bin/webhook/send",
            "docs: https://oapi.dingtalk.com/robot/send",
            "AccessKey ID 以 LTAI 开头，SecretKey 不单独出现",
            "secret_id = os.environ['TENCENT_SECRET_ID']",
        ):
            self.assert_no_findings(line)

    def test_registry_contains_localized_rules(self):
        for rule_id in (
            "deepseek-key",
            "aliyun-access-key-id",
            "aliyun-access-key-secret",
            "tencent-secret-id",
            "tencent-secret-key",
            "volcengine-access-key-id",
            "feishu-webhook",
            "wecom-webhook",
            "dingtalk-webhook",
            "afdian-token",
        ):
            self.assertIn(rule_id, RULES_BY_ID)
        self.assertGreaterEqual(len(RULES), 28)


if __name__ == "__main__":
    unittest.main()
