# Security policy

GateShield executes third-party security scanners against source repositories. Treat repository content and pull requests as untrusted input.

## Public repositories

Do not attach a persistent self-hosted runner containing credentials or sensitive local resources to an untrusted public-repository workflow. The official GitHub example targets GitHub-hosted Ubuntu runners.

## DAST

DAST requires an explicit allowlist and is skipped on fork pull requests. Do not configure targets you are not authorized to test.

## Secrets artifacts

Normalized secret findings redact secret material. Raw secret-scanner output is disabled by default because raw tool reports may contain sensitive values.

## Reporting vulnerabilities

Do not open a public issue for a vulnerability that would expose exploit details or secret material. Use the repository's private security-advisory channel when available.
