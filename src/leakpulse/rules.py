"""Detection rules for leakpulse.

Every rule is a compiled regular expression plus metadata. Rules are evaluated
in order; if two rules match overlapping spans on the same line the earlier
(more specific) rule wins. That keeps reports clean without deduplicating in
the caller.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern, Tuple


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    id: str
    description: str
    pattern: Pattern[str]
    severity: str = "high"
    group: int = 0
    #: Minimum Shannon entropy for the captured value (0 disables the check).
    min_entropy: float = 0.0
    keywords: Tuple[str, ...] = field(default_factory=tuple)

    def extract(self, line: str):
        for match in self.pattern.finditer(line):
            value = match.group(self.group)
            if value:
                yield match, value


def _c(pattern: str) -> Pattern[str]:
    return re.compile(pattern)


RULES: Tuple[Rule, ...] = (
    Rule(
        "private-key-block",
        "Private key material (PEM/PGP)",
        _c(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
        severity="high",
    ),
    Rule(
        "aws-access-key-id",
        "AWS access key ID",
        _c(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        severity="high",
    ),
    Rule(
        "github-pat",
        "GitHub fine-grained personal access token",
        _c(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
        severity="high",
    ),
    Rule(
        "github-token",
        "GitHub token (classic app/OAuth/refresh)",
        _c(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        severity="high",
    ),
    Rule(
        "anthropic-key",
        "Anthropic API key",
        _c(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        severity="high",
    ),
    Rule(
        "openai-key",
        "OpenAI-compatible API key (sk-…)",
        _c(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        severity="high",
    ),
    Rule(
        "resend-key",
        "Resend API key",
        _c(r"\bre_[A-Za-z0-9]{20,}\b"),
        severity="high",
    ),
    Rule(
        "sendgrid-key",
        "SendGrid API key",
        _c(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
        severity="high",
    ),
    Rule(
        "slack-token",
        "Slack token",
        _c(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        severity="high",
    ),
    Rule(
        "stripe-key",
        "Stripe secret/restricted key",
        _c(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        severity="high",
    ),
    Rule(
        "google-api-key",
        "Google API key",
        _c(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        severity="high",
    ),
    Rule(
        "npm-token",
        "npm access token",
        _c(r"\bnpm_[A-Za-z0-9]{36}\b"),
        severity="high",
    ),
    Rule(
        "pypi-token",
        "PyPI API token",
        _c(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b"),
        severity="high",
    ),
    Rule(
        "discord-webhook",
        "Discord webhook URL",
        _c(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{50,}"),
        severity="high",
    ),
    Rule(
        "url-basic-auth",
        "Credentials embedded in a URL",
        _c(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:@/]+:[^\s@/]{3,}@[^\s/]+"),
        severity="high",
    ),
    Rule(
        "bearer-token",
        "Bearer token in an Authorization header",
        _c(r"(?i)\bauthorization\s*:\s*bearer\s+([A-Za-z0-9._\-]{20,})"),
        severity="high",
        group=1,
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        _c(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        severity="medium",
    ),
    Rule(
        "generic-secret-assignment",
        "Secret-like value assigned to a sensitive name",
        _c(
            r"(?i)(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|"
            r"auth[_-]?token|password|passwd|pwd|private[_-]?key)"
            r"[^\S\n]*[:=][^\S\n]*[\"']?([A-Za-z0-9_\-./+=]{12,})[\"']?"
        ),
        severity="medium",
        group=1,
        min_entropy=2.5,
    ),
)

RULES_BY_ID = {rule.id: rule for rule in RULES}

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}

#: Values containing these markers are documentation/template placeholders,
#: not credentials. "test" is deliberately absent: live test-mode keys are
#: still credentials.
PLACEHOLDER_MARKERS = (
    "example",
    "sample",
    "dummy",
    "fake",
    "placeholder",
    "changeme",
    "change_me",
    "change-me",
    "redacted",
    "your_",
    "your-",
    "notreal",
    "not-real",
    "todo",
    "fixme",
    "xxxxxxxx",
    "********",
    "user:password",
    "user:pass@",
    "username:password",
)


_REFERENCE_PREFIXES = (
    "os.",
    "env.",
    "getenv",
    "process.env",
    "config.",
    "settings.",
    "self.",
    "this.",
    "system.getenv",
)


def is_reference(value: str) -> bool:
    """True for code references such as ``os.environ.get`` — not literals."""
    lowered = value.lower()
    return lowered.startswith(_REFERENCE_PREFIXES)


def is_placeholder(value: str) -> bool:
    """Return True when a captured value is clearly a placeholder."""
    if not value:
        return True
    if len(set(value)) < 5:
        return True
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    if value.startswith(("${", "{{", "$(", "<", "%(")):
        return True
    if lowered in {"null", "none", "true", "false", "undefined"}:
        return True
    return False
