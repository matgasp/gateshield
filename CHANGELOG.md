# Changelog

All notable changes to GateShield will be documented in this file.

## 0.0.1 - 2026-09-25

Initial public alpha release.

### Added

- Stack autodetection for Python, Java, Go, C/C++, JavaScript/TypeScript, .NET, Terraform, Docker, Helm, and Kubernetes.
- Policy-driven orchestration for SAST, SCA, secrets scanning, IaC, container checks, SBOM generation, and DAST.
- Local scanner execution with Docker fallback.
- `true`, `false`, and `auto` scan selectors.
- Baseline-aware findings with `NEW`, `EXISTING`, and `RESOLVED` states.
- Gate modes: `enforce`, `report`, and `external`.
- Stable exit codes for CI/CD integration.
- Raw and normalized artifacts with configurable names, paths, and retention.
- Consolidated JSON, Markdown, and SARIF reports.
- Custom artifact support for organization-specific tooling.
- DAST target allowlists and fork pull-request protections.
- Composite GitHub Action and reusable GitHub workflow.
- Version-pinned scanner toolchain and `tools list/check` commands.
