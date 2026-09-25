from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gateshield.models import GateResult, ScanPlan, ToolRun


SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "warning",
}


def _git(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def run_metadata(root: Path, gate_mode: str) -> dict[str, Any]:
    return {
        "id": os.environ.get("GITHUB_RUN_ID") or None,
        "commit": os.environ.get("GITHUB_SHA") or _git(root, "rev-parse", "HEAD"),
        "branch": os.environ.get("GITHUB_REF_NAME") or _git(root, "branch", "--show-current"),
        "event": os.environ.get("GITHUB_EVENT_NAME") or "local",
        "gate_mode": gate_mode,
    }


def build_report(
    root: Path,
    plan: ScanPlan,
    runs: list[ToolRun],
    baseline_summary: dict[str, Any],
    gate_mode: str,
    imported_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    findings = [finding.to_dict() for run in runs for finding in run.findings]
    findings.extend(imported_findings or [])
    counts = Counter(str(item.get("severity", "unknown")) for item in findings)
    status_counts = Counter(str(item.get("baseline_status", "new")) for item in findings)
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run": run_metadata(root, gate_mode),
        "plan": plan.to_dict(),
        "summary": {
            "total": len(findings),
            "by_severity": dict(sorted(counts.items())),
            "by_baseline_status": dict(sorted(status_counts.items())),
            "tools_requested": len(plan.tools),
            "tools_executed": sum(1 for run in runs if run.executed),
            "tools_missing": [run.tool for run in runs if not run.installed],
            "tool_errors": [run.tool for run in runs if run.error and run.installed],
        },
        "baseline": baseline_summary,
        "runs": [run.to_dict() for run in runs],
        "findings": findings,
    }


def add_gate(report: dict[str, Any], gate: GateResult) -> None:
    report["gate"] = gate.to_dict()


def write_json(data: Any, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return output


def load_report(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid GateShield report: {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != "1.0":
        raise ValueError(f"Unsupported GateShield report schema: {path}")
    return data


def write_markdown_report(report: dict[str, Any], output: Path) -> Path:
    summary = report.get("summary", {})
    gate = report.get("gate", {})
    baseline = report.get("baseline", {})
    findings = report.get("findings", [])
    lines = [
        "# GateShield Security Report",
        "",
        f"**Gate mode:** `{gate.get('mode', 'not evaluated')}`  ",
        f"**Gate result:** `{'BLOCK' if gate.get('enforced_block') else 'PASS'}`  ",
        f"**Would block:** `{bool(gate.get('would_block', False))}`  ",
        f"**Findings:** `{summary.get('total', 0)}`  ",
        f"**Tools executed:** `{summary.get('tools_executed', 0)}/{summary.get('tools_requested', 0)}`",
        "",
        "## Severity",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in ("critical", "high", "medium", "low", "info", "unknown"):
        lines.append(f"| {severity.upper()} | {int(summary.get('by_severity', {}).get(severity, 0))} |")

    if baseline.get("active"):
        lines.extend([
            "",
            "## Baseline",
            "",
            f"- NEW: **{baseline.get('new', 0)}**",
            f"- EXISTING: **{baseline.get('existing', 0)}**",
            f"- RESOLVED: **{baseline.get('resolved', 0)}**",
        ])

    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("No normalized findings were reported.")
    else:
        for index, finding in enumerate(findings[:300], start=1):
            location = str(finding.get("file") or "repository")
            if finding.get("line"):
                location += f":{finding['line']}"
            lines.extend([
                f"### {index}. [{str(finding.get('severity', 'unknown')).upper()}] {finding.get('title', 'Finding')}",
                "",
                f"- Status: `{str(finding.get('baseline_status', 'new')).upper()}`",
                f"- Category: `{finding.get('module', 'unknown')}`",
                f"- Tool: `{finding.get('tool', 'unknown')}`",
                f"- Location: `{location}`",
                f"- Rule: `{finding.get('rule_id') or 'n/a'}`",
                f"- Fingerprint: `{finding.get('fingerprint') or 'n/a'}`",
                "",
                str(finding.get("message") or "No additional detail."),
                "",
            ])

    if baseline.get("resolved_findings"):
        lines.extend(["", "## Resolved since baseline", ""])
        for item in baseline["resolved_findings"][:200]:
            lines.append(f"- `{item.get('tool')}` {item.get('title')} — `{item.get('file') or 'repository'}`")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return output


def _sarif_result(finding: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": str(finding.get("rule_id") or f"gateshield/{finding.get('tool', 'unknown')}")[:512],
        "level": SARIF_LEVELS.get(str(finding.get("severity", "unknown")).lower(), "warning"),
        "message": {"text": str(finding.get("message") or finding.get("title") or "GateShield finding")[:4000]},
        "properties": {
            "tool": finding.get("tool"),
            "category": finding.get("module"),
            "severity": finding.get("severity"),
            "baseline_status": finding.get("baseline_status"),
            "fingerprint": finding.get("fingerprint"),
        },
    }
    if finding.get("file"):
        region: dict[str, Any] = {}
        if finding.get("line"):
            try:
                region["startLine"] = max(1, int(finding["line"]))
            except (TypeError, ValueError):
                pass
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": str(finding["file"]).replace("\\", "/")},
        }
        if region:
            physical["region"] = region
        result["locations"] = [{"physicalLocation": physical}]
    return result


def write_sarif_report(report: dict[str, Any], output: Path) -> Path:
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GateShield",
                        "informationUri": "https://github.com/matgasp/gateshield",
                        "rules": [],
                    }
                },
                "results": [_sarif_result(item) for item in report.get("findings", [])],
            }
        ],
    }
    return write_json(sarif, output)


def append_github_summary(markdown_path: Path) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with Path(summary_path).open("a", encoding="utf-8") as handle:
        handle.write(markdown_path.read_text(encoding="utf-8"))
        handle.write("\n")
