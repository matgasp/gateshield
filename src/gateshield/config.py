from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from gateshield.constants import GATE_ACTIONS, GATE_MODES, MODULES


DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "project": {"name": None},
    "stack": {
        "auto_detect": True,
        "languages": [],
    },
    "scan": {
        "sast": True,
        "sca": True,
        "secrets": True,
        "iac": "auto",
        "container": "auto",
        "sbom": True,
        "dast": False,
    },
    "scope": {
        "mode": "auto",
        "base_ref": "origin/main",
    },
    "execution": {
        "mode": "auto",
        "timeout_seconds": 600,
        "require_tools": True,
    },
    "scanners": {},
    "container": {
        "image": None,
    },
    "dast": {
        "target": None,
        "mode": "baseline",
        "allowed_hosts": ["localhost", "127.0.0.1", "::1"],
        "headers": {},
    },
    "gate": {
        "mode": "enforce",
        "new_findings_only": True,
        "severity": {
            "critical": "block",
            "high": "block",
            "medium": "warn",
            "low": "report",
            "info": "report",
            "unknown": "warn",
        },
        "categories": {
            "secrets": {"any": "block"},
        },
    },
    "baseline": {
        "path": ".gateshield/baseline.json",
        "enabled": "auto",
    },
    "artifacts": {
        "enabled": True,
        "root": ".gateshield/artifacts",
        "retention_days": 14,
        "categories": {
            "sast": {"enabled": True, "name": None, "path": None, "raw": True},
            "sca": {"enabled": True, "name": None, "path": None, "raw": True},
            "secrets": {"enabled": True, "name": None, "path": None, "raw": False, "retention_days": 3},
            "iac": {"enabled": True, "name": None, "path": None, "raw": True},
            "container": {"enabled": True, "name": None, "path": None, "raw": True},
            "sbom": {"enabled": True, "name": None, "path": None, "raw": True},
            "dast": {"enabled": True, "name": None, "path": None, "raw": True},
        },
        "custom": [],
    },
    "toolchain": {
        "semgrep": "1.175.0",
        "bandit": "1.9.4",
        "pip-audit": "2.10.1",
        "gitleaks": "8.29.1",
        "trivy": "0.74.0",
        "checkov": "3.3.19",
        "syft": "1.52.0",
        "zap": "2.17.0",
    },
}


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def _validate_tri_state(name: str, value: Any) -> None:
    if value in (True, False):
        return
    if isinstance(value, str) and value.lower() == "auto":
        return
    raise ValueError(f"{name} must be true, false, or 'auto'")


def validate_config(config: dict[str, Any]) -> None:
    for module in MODULES:
        _validate_tri_state(f"scan.{module}", config.get("scan", {}).get(module))

    mode = str(config.get("execution", {}).get("mode", "auto")).lower()
    if mode not in {"auto", "local", "docker"}:
        raise ValueError("execution.mode must be auto, local, or docker")

    gate_mode = str(config.get("gate", {}).get("mode", "enforce")).lower()
    if gate_mode not in GATE_MODES:
        raise ValueError(f"gate.mode must be one of: {', '.join(GATE_MODES)}")

    for severity, action in config.get("gate", {}).get("severity", {}).items():
        if str(action).lower() not in GATE_ACTIONS:
            raise ValueError(f"Invalid gate action for {severity}: {action}")

    dast = config.get("dast", {})
    if config.get("scan", {}).get("dast") is True and not dast.get("target"):
        raise ValueError("dast.target is required when scan.dast is true")
    if str(dast.get("mode", "baseline")) not in {"baseline", "full"}:
        raise ValueError("dast.mode must be baseline or full")

    custom = config.get("artifacts", {}).get("custom", []) or []
    if not isinstance(custom, list):
        raise ValueError("artifacts.custom must be a list")
    for index, item in enumerate(custom):
        if not isinstance(item, dict):
            raise ValueError(f"artifacts.custom[{index}] must be a mapping")
        if not item.get("name") or not item.get("path"):
            raise ValueError(f"artifacts.custom[{index}] requires name and path")
        fmt = str(item.get("format", "raw")).lower()
        if fmt not in {"raw", "sarif", "gateshield"}:
            raise ValueError(f"artifacts.custom[{index}].format must be raw, sarif, or gateshield")


def load_config(root: Path, config_path: str | None = None) -> dict[str, Any]:
    path = root / (config_path or ".gateshield.yml")
    if not path.exists():
        config = deepcopy(DEFAULT_CONFIG)
        validate_config(config)
        return config

    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Configuration must be a YAML mapping: {path}")

    config = _merge(DEFAULT_CONFIG, loaded)
    validate_config(config)
    return config


def write_default_config(root: Path, overwrite: bool = False) -> Path:
    path = root / ".gateshield.yml"
    if path.exists() and not overwrite:
        raise FileExistsError(f"Configuration already exists: {path}")

    template = deepcopy(DEFAULT_CONFIG)
    template["project"]["name"] = root.name
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(template, handle, sort_keys=False)
    return path
