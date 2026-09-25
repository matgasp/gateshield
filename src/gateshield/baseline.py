from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gateshield.models import Finding


def _normalize(value: Any) -> str:
    text = str(value or "")
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text[:500]


def fingerprint(finding: Finding) -> str:
    material = "|".join(
        [
            _normalize(finding.tool),
            _normalize(finding.rule_id),
            _normalize((finding.file or "").replace("\\", "/")),
            _normalize(finding.title),
            _normalize(finding.context or finding.message),
        ]
    )
    return "sha256:" + hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()


def load_baseline(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid baseline JSON: {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != "1.0":
        raise ValueError(f"Unsupported baseline format: {path}")
    return data


def apply_baseline(findings: list[Finding], baseline: dict[str, Any] | None) -> dict[str, Any]:
    previous_entries = (baseline or {}).get("findings", []) or []
    previous = {str(item.get("fingerprint")): item for item in previous_entries if item.get("fingerprint")}
    current: set[str] = set()
    new_count = 0
    existing_count = 0

    for finding in findings:
        finding.fingerprint = fingerprint(finding)
        current.add(finding.fingerprint)
        if finding.fingerprint in previous:
            finding.baseline_status = "existing"
            existing_count += 1
        else:
            finding.baseline_status = "new"
            new_count += 1

    resolved = [
        {
            "fingerprint": fp,
            "tool": item.get("tool"),
            "module": item.get("module"),
            "severity": item.get("severity"),
            "title": item.get("title"),
            "file": item.get("file"),
            "status": "resolved",
        }
        for fp, item in previous.items()
        if fp not in current
    ]

    return {
        "active": baseline is not None,
        "new": new_count,
        "existing": existing_count,
        "resolved": len(resolved),
        "resolved_findings": resolved,
    }


def baseline_from_report(report: dict[str, Any]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for item in report.get("findings", []) or []:
        fp = item.get("fingerprint")
        if not fp:
            continue
        entries.append(
            {
                "fingerprint": fp,
                "tool": item.get("tool"),
                "module": item.get("module"),
                "severity": item.get("severity"),
                "title": item.get("title"),
                "file": item.get("file"),
                "rule_id": item.get("rule_id"),
            }
        )
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_report_schema": report.get("schema_version"),
        "findings": entries,
    }


def write_baseline(report: dict[str, Any], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    data = baseline_from_report(report)
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return output
