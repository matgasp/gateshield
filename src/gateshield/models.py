from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Finding:
    tool: str
    module: str
    severity: str
    title: str
    file: str | None = None
    line: int | None = None
    rule_id: str | None = None
    message: str | None = None
    context: str | None = None
    fingerprint: str | None = None
    baseline_status: str = "new"
    raw: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ToolRun:
    tool: str
    module: str
    command: list[str]
    installed: bool
    executed: bool
    runner: str = "local"
    return_code: int | None = None
    duration_ms: int | None = None
    output_file: str | None = None
    error: str | None = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [finding.to_dict() for finding in self.findings]
        return data


@dataclass(slots=True)
class ScanPlan:
    root: str
    languages: list[str]
    technologies: list[str]
    changed_files: list[str]
    modules: list[str]
    tools: list[str]
    reasons: dict[str, list[str]]
    full_scan: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class GateResult:
    mode: str
    would_block: bool
    enforced_block: bool
    blocking_findings: list[dict[str, Any]]
    warnings: list[str]
    reasons: list[str]

    @property
    def passed(self) -> bool:
        return not self.enforced_block

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"passed": self.passed}


@dataclass(slots=True)
class ArtifactSpec:
    key: str
    name: str
    path: str
    retention_days: int
    category: str
    custom: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
