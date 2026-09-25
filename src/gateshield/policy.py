from __future__ import annotations

from typing import Any

from gateshield.models import GateResult


def evaluate(report: dict[str, Any], gate_config: dict[str, Any]) -> GateResult:
    mode = str(gate_config.get("mode", "enforce")).lower()
    severity_actions = {
        str(key).lower(): str(value).lower()
        for key, value in (gate_config.get("severity", {}) or {}).items()
    }
    category_rules = gate_config.get("categories", {}) or {}
    new_only = bool(gate_config.get("new_findings_only", True)) and bool(report.get("baseline", {}).get("active"))

    blocking: list[dict[str, Any]] = []
    warnings: list[str] = []

    for finding in report.get("findings", []) or []:
        if new_only and finding.get("baseline_status") != "new":
            continue

        module = str(finding.get("module", "unknown")).lower()
        severity = str(finding.get("severity", "unknown")).lower()
        category = category_rules.get(module, {}) or {}
        category_action = category.get("any")
        action = str(category_action or severity_actions.get(severity, "report")).lower()

        if action == "block":
            blocking.append(finding)
        elif action == "warn":
            warnings.append(
                f"{module}/{severity}: {finding.get('title', 'finding')}"
            )

    would_block = bool(blocking)
    enforced_block = mode == "enforce" and would_block
    reasons: list[str] = []
    if would_block:
        scope = "new findings" if new_only else "findings"
        reasons.append(f"{len(blocking)} {scope} match blocking policy")
    if mode in {"report", "external"} and would_block:
        reasons.append(f"gate mode '{mode}' reports would-block without stopping the pipeline")

    return GateResult(
        mode=mode,
        would_block=would_block,
        enforced_block=enforced_block,
        blocking_findings=blocking,
        warnings=warnings,
        reasons=reasons,
    )
