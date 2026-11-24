# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). Include:

- affected version / commit,
- a minimal reproduction (command, input file shape, observed output),
- impact assessment (what an attacker could read, write or bypass).

You can expect an initial response within 7 days. Once a fix is available we
will publish a patched release and credit reporters who ask to be named.

## Scope notes

LeakPulse performs **local static analysis only**. It never transmits scanned
content. Reports worth a security fix include:

- a crafted input that causes a crash, hang or unbounded memory use,
- a secret type that is silently skipped when it should match,
- output that reveals more of a secret than the documented masking policy,
- hook installation that can be tricked into executing untrusted code.

False negatives caused by the fundamental limits of regex/entropy scanning are
documented limitations rather than vulnerabilities.
