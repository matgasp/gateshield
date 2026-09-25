from __future__ import annotations

EXIT_OK = 0
EXIT_GATE_BLOCKED = 1
EXIT_CONFIG_ERROR = 2
EXIT_MISSING_TOOL = 3
EXIT_SCANNER_ERROR = 4
EXIT_INVALID_REPORT = 5

MODULES = ("sast", "sca", "secrets", "iac", "container", "sbom", "dast")
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
GATE_ACTIONS = ("block", "warn", "report", "ignore")
GATE_MODES = ("enforce", "report", "external")
MAX_GITHUB_CUSTOM_ARTIFACTS = 5
