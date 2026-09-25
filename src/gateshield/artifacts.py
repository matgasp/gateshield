from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from gateshield.constants import MAX_GITHUB_CUSTOM_ARTIFACTS, MODULES
from gateshield.models import ArtifactSpec, Finding, ToolRun
from gateshield.report import write_json


def _run_suffix() -> str:
    pr = os.environ.get("GITHUB_REF_NAME", "").replace("/", "-")
    sha = (os.environ.get("GITHUB_SHA") or "")[:7]
    run = os.environ.get("GITHUB_RUN_NUMBER")
    parts = [item for item in (pr, sha, run) if item]
    return "-" + "-".join(parts) if parts else ""


def _category_settings(config: dict[str, Any], module: str) -> dict[str, Any]:
    return (config.get("artifacts", {}).get("categories", {}) or {}).get(module, {}) or {}


def artifact_specs(root: Path, config: dict[str, Any]) -> list[ArtifactSpec]:
    artifacts = config.get("artifacts", {})
    base_root = root / str(artifacts.get("root", ".gateshield/artifacts"))
    default_retention = int(artifacts.get("retention_days", 14))
    specs: list[ArtifactSpec] = []
    for module in MODULES:
        settings = _category_settings(config, module)
        if not settings.get("enabled", True):
            continue
        path = root / str(settings.get("path") or (base_root / module).relative_to(root))
        name = str(settings.get("name") or f"gateshield-{module}{_run_suffix()}")
        retention = int(settings.get("retention_days", default_retention))
        specs.append(ArtifactSpec(module, name, str(path), retention, module))

    for index, item in enumerate(artifacts.get("custom", []) or []):
        path = root / str(item["path"])
        specs.append(
            ArtifactSpec(
                key=f"custom_{index}",
                name=str(item["name"]),
                path=str(path),
                retention_days=int(item.get("retention_days", default_retention)),
                category=str(item.get("category", "custom")),
                custom=True,
            )
        )
    return specs


def import_normalized_custom_findings(root: Path, config: dict[str, Any]) -> list[Finding]:
    imported: list[Finding] = []
    for item in config.get("artifacts", {}).get("custom", []) or []:
        if str(item.get("format", "raw")).lower() != "gateshield":
            continue
        path = root / str(item["path"])
        if not path.exists() or not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        findings = data.get("findings", []) if isinstance(data, dict) else []
        for finding in findings:
            if isinstance(finding, dict):
                imported.append(
                    Finding(
                        tool=str(finding.get("tool") or f"custom:{item['name']}"),
                        module=str(finding.get("module") or item.get("category", "custom")),
                        severity=str(finding.get("severity", "unknown")),
                        title=str(finding.get("title", "Custom finding")),
                        file=finding.get("file"),
                        line=finding.get("line"),
                        rule_id=finding.get("rule_id"),
                        message=finding.get("message"),
                        context=finding.get("context"),
                    )
                )
    return imported


def assemble_artifacts(
    root: Path,
    config: dict[str, Any],
    report: dict[str, Any],
    runs: list[ToolRun],
    consolidated_sarif: Path,
) -> list[ArtifactSpec]:
    if not config.get("artifacts", {}).get("enabled", True):
        return []

    all_specs = artifact_specs(root, config)
    active_modules = set(report.get("plan", {}).get("modules", []) or [])
    active_modules.update(str(item.get("module")) for item in report.get("findings", []) if item.get("module"))
    specs = [spec for spec in all_specs if spec.custom or spec.key in active_modules]
    by_key = {spec.key: spec for spec in specs if not spec.custom}
    raw_by_tool = {run.tool: Path(run.output_file) for run in runs if run.output_file and Path(run.output_file).exists()}

    for module in MODULES:
        spec = by_key.get(module)
        if not spec:
            continue
        path = Path(spec.path)
        path.mkdir(parents=True, exist_ok=True)
        category_findings = [item for item in report.get("findings", []) if item.get("module") == module]
        category_report = {
            "schema_version": "1.0",
            "category": module,
            "gate": report.get("gate"),
            "summary": {
                "total": len(category_findings),
            },
            "findings": category_findings,
        }
        write_json(category_report, path / f"gateshield-{module}.json")

        settings = _category_settings(config, module)
        include_raw = bool(settings.get("raw", module != "secrets"))
        if include_raw:
            raw_dir = path / "raw"
            raw_dir.mkdir(exist_ok=True)
            for run in runs:
                if run.module != module or run.tool not in raw_by_tool:
                    continue
                source = raw_by_tool[run.tool]
                shutil.copy2(source, raw_dir / source.name)

        if module in {"sast", "sca", "secrets", "iac", "container", "dast"}:
            shutil.copy2(consolidated_sarif, path / "gateshield.sarif")

    manifest: list[dict[str, Any]] = []
    for spec in specs:
        if spec.custom:
            exists = Path(spec.path).exists()
            manifest.append(spec.to_dict() | {"exists": exists})
        else:
            manifest.append(spec.to_dict() | {"exists": Path(spec.path).exists()})

    manifest_path = root / str(config.get("artifacts", {}).get("root", ".gateshield/artifacts")) / "manifest.json"
    write_json({"schema_version": "1.0", "artifacts": manifest}, manifest_path)
    return specs


def write_github_outputs(specs: list[ArtifactSpec], final_exit_code: int, report_path: Path, sarif_path: Path) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    lines = [
        f"final_exit_code={final_exit_code}",
        f"report_path={report_path}",
        f"sarif_path={sarif_path}",
    ]
    custom_index = 0
    for spec in specs:
        if spec.custom:
            if custom_index >= MAX_GITHUB_CUSTOM_ARTIFACTS:
                continue
            prefix = f"custom_{custom_index}"
            custom_index += 1
        else:
            prefix = spec.key
        lines.extend([
            f"{prefix}_name={spec.name}",
            f"{prefix}_path={spec.path}",
            f"{prefix}_retention={spec.retention_days}",
        ])
    with Path(output_file).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
