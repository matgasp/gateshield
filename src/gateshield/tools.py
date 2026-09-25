from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any


TOOL_BINARIES = {
    "semgrep": "semgrep",
    "bandit": "bandit",
    "pip-audit": "pip-audit",
    "gitleaks": "gitleaks",
    "trivy": "trivy",
    "checkov": "checkov",
    "syft": "syft",
    "zap": "zap-baseline.py",
}

VERSION_ARGS = {
    "semgrep": ["--version"],
    "bandit": ["--version"],
    "pip-audit": ["--version"],
    "gitleaks": ["version"],
    "trivy": ["--version"],
    "checkov": ["--version"],
    "syft": ["version"],
    "zap": ["--help"],
}


@dataclass(slots=True)
class ToolStatus:
    name: str
    pinned: str
    installed: bool
    path: str | None
    local_version: str | None
    docker_fallback: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "pinned": self.pinned,
            "installed": self.installed,
            "path": self.path,
            "local_version": self.local_version,
            "docker_fallback": self.docker_fallback,
        }


def _local_version(binary: str, args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            [binary, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (result.stdout or result.stderr or "").strip()
    return text.splitlines()[0][:200] if text else None


def inspect_tools(config: dict[str, Any]) -> list[ToolStatus]:
    toolchain = config.get("toolchain", {})
    docker_available = shutil.which("docker") is not None
    statuses: list[ToolStatus] = []
    for name, binary in TOOL_BINARIES.items():
        path = shutil.which(binary)
        statuses.append(
            ToolStatus(
                name=name,
                pinned=str(toolchain.get(name, "unknown")),
                installed=path is not None,
                path=path,
                local_version=_local_version(binary, VERSION_ARGS[name]) if path else None,
                docker_fallback=docker_available,
            )
        )
    return statuses


def render_tools(statuses: list[ToolStatus], as_json: bool = False) -> str:
    if as_json:
        return json.dumps([item.to_dict() for item in statuses], indent=2)
    lines = ["GateShield toolchain", "=" * 72]
    for item in statuses:
        state = "LOCAL" if item.installed else ("DOCKER" if item.docker_fallback else "MISSING")
        lines.append(f"{item.name:12} pinned={item.pinned:10} status={state:7} local={item.local_version or '-'}")
    return "\n".join(lines)
