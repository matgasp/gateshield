from __future__ import annotations

import fnmatch
import json
import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from gateshield.models import Finding, ToolRun


@dataclass(slots=True)
class ScannerDefinition:
    name: str
    module: str
    binary: str
    parser: Callable[[Path], list[Finding]]
    local_builder: Callable[[Path, Path, dict[str, Any]], list[str]]
    docker_builder: Callable[[Path, Path, dict[str, Any]], list[str]] | None = None
    allowed_return_codes: tuple[int, ...] = (0,)
    capture_stdout: bool = False


def _severity(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower()
    aliases = {
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "note": "low",
        "informational": "info",
    }
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in {"critical", "high", "medium", "low", "info", "unknown"} else "unknown"


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None


def parse_semgrep(path: Path) -> list[Finding]:
    data = _load_json(path) or {}
    findings: list[Finding] = []
    for item in data.get("results", []) or []:
        extra = item.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        start = item.get("start", {}) or {}
        findings.append(Finding(
            tool="semgrep",
            module="sast",
            severity=_severity(extra.get("severity") or metadata.get("severity")),
            title=extra.get("message") or item.get("check_id") or "Semgrep finding",
            file=item.get("path"),
            line=start.get("line"),
            rule_id=item.get("check_id"),
            message=extra.get("message"),
            context=extra.get("lines"),
        ))
    return findings


def parse_bandit(path: Path) -> list[Finding]:
    data = _load_json(path) or {}
    findings: list[Finding] = []
    for item in data.get("results", []) or []:
        findings.append(Finding(
            tool="bandit",
            module="sast",
            severity=_severity(item.get("issue_severity")),
            title=item.get("issue_text") or item.get("test_name") or "Bandit finding",
            file=item.get("filename"),
            line=item.get("line_number"),
            rule_id=item.get("test_id"),
            message=item.get("issue_text"),
            context=item.get("code"),
        ))
    return findings


def parse_pip_audit(path: Path) -> list[Finding]:
    data = _load_json(path)
    dependencies = data.get("dependencies", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    findings: list[Finding] = []
    for dependency in dependencies:
        name = dependency.get("name", "dependency")
        version = dependency.get("version", "unknown")
        for vuln in dependency.get("vulns", []) or []:
            findings.append(Finding(
                tool="pip-audit",
                module="sca",
                severity="high",
                title=f"{name} {version}: {vuln.get('id', 'known vulnerability')}",
                rule_id=vuln.get("id"),
                message=vuln.get("description") or ", ".join(vuln.get("fix_versions", []) or []),
                context=f"{name}=={version}",
            ))
    return findings


def parse_gitleaks(path: Path) -> list[Finding]:
    data = _load_json(path) or []
    if not isinstance(data, list):
        return []
    findings: list[Finding] = []
    for item in data:
        findings.append(Finding(
            tool="gitleaks",
            module="secrets",
            severity="critical",
            title=item.get("Description") or item.get("RuleID") or "Potential secret",
            file=item.get("File"),
            line=item.get("StartLine"),
            rule_id=item.get("RuleID"),
            message="Potential secret detected. Secret material is redacted by GateShield.",
            context=item.get("RuleID"),
        ))
    return findings


def _parse_trivy(path: Path, tool: str, module: str) -> list[Finding]:
    data = _load_json(path) or {}
    findings: list[Finding] = []
    if not isinstance(data, dict):
        return findings
    for result in data.get("Results", []) or []:
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(Finding(
                tool=tool,
                module=module,
                severity=_severity(vuln.get("Severity")),
                title=f"{vuln.get('PkgName', 'package')}: {vuln.get('VulnerabilityID', 'vulnerability')}",
                file=target,
                rule_id=vuln.get("VulnerabilityID"),
                message=vuln.get("Title") or vuln.get("Description"),
                context=f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}",
            ))
        for misconfig in result.get("Misconfigurations", []) or []:
            cause = misconfig.get("CauseMetadata") or {}
            findings.append(Finding(
                tool=tool,
                module=module,
                severity=_severity(misconfig.get("Severity")),
                title=misconfig.get("Title") or misconfig.get("ID") or "Misconfiguration",
                file=cause.get("Resource") or target,
                line=cause.get("StartLine") if isinstance(cause, dict) else None,
                rule_id=misconfig.get("ID"),
                message=misconfig.get("Description") or misconfig.get("Message"),
                context=misconfig.get("CauseMetadata", {}).get("Code", {}).get("Lines") if isinstance(misconfig.get("CauseMetadata"), dict) else None,
            ))
        for secret in result.get("Secrets", []) or []:
            findings.append(Finding(
                tool=tool,
                module=module,
                severity=_severity(secret.get("Severity") or "critical"),
                title=secret.get("Title") or secret.get("RuleID") or "Potential secret",
                file=target,
                line=secret.get("StartLine"),
                rule_id=secret.get("RuleID"),
                message="Potential secret detected. Secret material is redacted by GateShield.",
            ))
    return findings


def parse_trivy_fs(path: Path) -> list[Finding]:
    return _parse_trivy(path, "trivy-fs", "sca")


def parse_trivy_config(path: Path) -> list[Finding]:
    return _parse_trivy(path, "trivy-config", "iac")


def parse_trivy_container(path: Path) -> list[Finding]:
    return _parse_trivy(path, "trivy-container", "container")


def parse_trivy_image(path: Path) -> list[Finding]:
    return _parse_trivy(path, "trivy-image", "container")


def parse_checkov(path: Path) -> list[Finding]:
    data = _load_json(path)
    blocks = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    findings: list[Finding] = []
    for block in blocks:
        results = (block or {}).get("results", {}) or {}
        for item in results.get("failed_checks", []) or []:
            file_path = item.get("file_path")
            if isinstance(file_path, list):
                file_path = "/".join(str(part).strip("/") for part in file_path)
            line_range = item.get("file_line_range") or []
            line = line_range[0] if line_range and isinstance(line_range[0], int) else None
            findings.append(Finding(
                tool="checkov",
                module="iac",
                severity=_severity(item.get("severity") or "high"),
                title=item.get("check_name") or item.get("check_id") or "Checkov finding",
                file=file_path,
                line=line,
                rule_id=item.get("check_id"),
                message=item.get("guideline") or item.get("check_name"),
                context=item.get("resource"),
            ))
    return findings


def parse_zap(path: Path) -> list[Finding]:
    data = _load_json(path) or {}
    findings: list[Finding] = []
    risk_map = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
    for site in data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            risk_code = str(alert.get("riskcode", ""))
            instances = alert.get("instances", []) or [{}]
            instance = instances[0] if instances else {}
            findings.append(Finding(
                tool="zap",
                module="dast",
                severity=risk_map.get(risk_code, _severity(alert.get("riskdesc", "unknown").split(" ")[0])),
                title=alert.get("name") or alert.get("alert") or "ZAP alert",
                file=instance.get("uri") or site.get("@name"),
                rule_id=str(alert.get("pluginid") or "zap"),
                message=alert.get("desc") or alert.get("solution"),
                context=instance.get("method") or alert.get("param"),
            ))
    return findings


def parse_none(path: Path) -> list[Finding]:
    return []


def _rel_out(root: Path, output: Path) -> str:
    return output.resolve().relative_to(root.resolve()).as_posix()


def _py_docker(root: Path, output: Path, package: str, version: str, command: str) -> list[str]:
    mount = f"{root.resolve()}:/src"
    return [
        "docker", "run", "--rm", "-v", mount, "-w", "/src", "python:3.13-slim",
        "sh", "-lc", f"pip install --disable-pip-version-check -q {shlex.quote(package + '==' + version)} && {command}",
    ]




def _changed_targets(config: dict[str, Any], suffixes: set[str]) -> list[str]:
    changed = config.get("_runtime", {}).get("changed_files", []) or []
    return [str(item) for item in changed if Path(str(item)).suffix.lower() in suffixes]

def _semgrep_local(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    targets = _changed_targets(config, {".py", ".java", ".go", ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".js", ".jsx", ".ts", ".tsx", ".cs"}) or ["."]
    return ["semgrep", "scan", "--config", "auto", "--json", "--output", str(out), *targets]


def _semgrep_docker(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    rel = _rel_out(root, out)
    version = str(config["toolchain"]["semgrep"])
    targets = _changed_targets(config, {".py", ".java", ".go", ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".js", ".jsx", ".ts", ".tsx", ".cs"}) or ["."]
    target_args = " ".join(shlex.quote(item) for item in targets)
    return _py_docker(root, out, "semgrep", version, f"semgrep scan --config auto --json --output /src/{shlex.quote(rel)} {target_args}")


def _bandit_local(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    targets = _changed_targets(config, {".py"}) or ["."]
    return ["bandit", "-r", *targets, "-f", "json", "-o", str(out)]


def _bandit_docker(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    rel = _rel_out(root, out)
    version = str(config["toolchain"]["bandit"])
    targets = _changed_targets(config, {".py"}) or ["."]
    target_args = " ".join(shlex.quote(item) for item in targets)
    return _py_docker(root, out, "bandit", version, f"bandit -r {target_args} -f json -o /src/{shlex.quote(rel)}")


def _pip_audit_local(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    return ["pip-audit", "-r", "requirements.txt", "--format", "json", "--output", str(out)]


def _pip_audit_docker(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    rel = _rel_out(root, out)
    version = str(config["toolchain"]["pip-audit"])
    return _py_docker(root, out, "pip-audit", version, f"pip-audit -r requirements.txt --format json --output /src/{shlex.quote(rel)}")


def _gitleaks_local(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    return ["gitleaks", "dir", ".", "--report-format", "json", "--report-path", str(out), "--no-banner", "--redact"]


def _gitleaks_docker(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    rel = _rel_out(root, out)
    version = str(config["toolchain"]["gitleaks"])
    return [
        "docker", "run", "--rm", "-v", f"{root.resolve()}:/src", "-w", "/src",
        f"zricethezav/gitleaks:v{version}", "dir", ".", "--report-format", "json",
        "--report-path", f"/src/{rel}", "--no-banner", "--redact",
    ]


def _trivy_local(kind: str, out: Path, target: str = ".") -> list[str]:
    return ["trivy", kind, "--format", "json", "--output", str(out), target]


def _trivy_docker(root: Path, out: Path, config: dict[str, Any], kind: str, target: str = ".") -> list[str]:
    rel = _rel_out(root, out)
    version = str(config["toolchain"]["trivy"])
    args = [
        "docker", "run", "--rm", "-v", f"{root.resolve()}:/src", "-w", "/src",
        f"aquasec/trivy:{version}", kind, "--format", "json", "--output", f"/src/{rel}", target,
    ]
    return args


def _checkov_local(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    return ["checkov", "-d", ".", "-o", "json", "--compact", "--quiet", "--skip-download"]


def _checkov_docker(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    rel = _rel_out(root, out)
    version = str(config["toolchain"]["checkov"])
    return _py_docker(root, out, "checkov", version, f"checkov -d . -o json --compact --quiet --skip-download > /src/{shlex.quote(rel)}")


def _syft_local(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    return ["syft", ".", "-o", f"cyclonedx-json={out}"]


def _syft_docker(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    rel = _rel_out(root, out)
    version = str(config["toolchain"]["syft"])
    return [
        "docker", "run", "--rm", "-v", f"{root.resolve()}:/src", "-w", "/src",
        f"anchore/syft:v{version}", ".", "-o", f"cyclonedx-json=/src/{rel}",
    ]


def _zap_target_for_docker(target: str) -> str:
    parsed = urlparse(target)
    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return target
    host = "host.docker.internal"
    netloc = host + (f":{parsed.port}" if parsed.port else "")
    return parsed._replace(netloc=netloc).geturl()


def validate_dast_target(config: dict[str, Any]) -> None:
    dast = config.get("dast", {})
    target = str(dast.get("target") or "")
    if not target:
        raise ValueError("dast.target is required")
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("dast.target must be an http(s) URL")
    allowed = dast.get("allowed_hosts", []) or []
    if not any(fnmatch.fnmatch(parsed.hostname, pattern) for pattern in allowed):
        raise ValueError(f"DAST target host '{parsed.hostname}' is not in dast.allowed_hosts")


def _zap_replacer_options(config: dict[str, Any]) -> str | None:
    headers = config.get("dast", {}).get("headers", {}) or {}
    options: list[str] = []
    for index, (name, template) in enumerate(headers.items()):
        value = os.path.expandvars(str(template))
        if value == str(template) and "${" in str(template):
            raise ValueError(f"DAST header environment variable is not set for {name}")
        prefix = f"replacer.full_list({index})"
        options.extend([
            f"-config {prefix}.description=GateShield-{index}",
            f"-config {prefix}.enabled=true",
            f"-config {prefix}.matchtype=REQ_HEADER",
            f"-config {prefix}.matchstr={name}",
            f"-config {prefix}.replacement={value}",
        ])
    return " ".join(options) if options else None


def _zap_local(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    validate_dast_target(config)
    target = str(config["dast"]["target"])
    script = "zap-baseline.py" if config["dast"].get("mode", "baseline") == "baseline" else "zap-full-scan.py"
    command = [script, "-t", target, "-J", str(out)]
    options = _zap_replacer_options(config)
    if options:
        command.extend(["-z", options])
    return command


def _zap_docker(root: Path, out: Path, config: dict[str, Any]) -> list[str]:
    validate_dast_target(config)
    rel = _rel_out(root, out)
    target = _zap_target_for_docker(str(config["dast"]["target"]))
    version = str(config["toolchain"]["zap"])
    script = "zap-baseline.py" if config["dast"].get("mode", "baseline") == "baseline" else "zap-full-scan.py"
    command = [
        "docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
        "-v", f"{root.resolve()}:/zap/wrk/:rw", f"ghcr.io/zaproxy/zaproxy:{version}",
        script, "-t", target, "-J", f"/{'zap/wrk'}/{rel}",
    ]
    options = _zap_replacer_options(config)
    if options:
        command.extend(["-z", options])
    return command


def _redact_command(tool: str, command: list[str]) -> list[str]:
    if tool != "zap":
        return command
    redacted: list[str] = []
    skip_next = False
    for arg in command:
        if skip_next:
            redacted.append("[REDACTED_ZAP_OPTIONS]")
            skip_next = False
            continue
        redacted.append(arg)
        if arg == "-z":
            skip_next = True
    return redacted


def registry(config: dict[str, Any]) -> dict[str, ScannerDefinition]:
    return {
        "semgrep": ScannerDefinition("semgrep", "sast", "semgrep", parse_semgrep, _semgrep_local, _semgrep_docker, (0, 1)),
        "bandit": ScannerDefinition("bandit", "sast", "bandit", parse_bandit, _bandit_local, _bandit_docker, (0, 1)),
        "pip-audit": ScannerDefinition("pip-audit", "sca", "pip-audit", parse_pip_audit, _pip_audit_local, _pip_audit_docker, (0, 1)),
        "gitleaks": ScannerDefinition("gitleaks", "secrets", "gitleaks", parse_gitleaks, _gitleaks_local, _gitleaks_docker, (0, 1)),
        "trivy-fs": ScannerDefinition("trivy-fs", "sca", "trivy", parse_trivy_fs, lambda r, o, c: _trivy_local("fs", o), lambda r, o, c: _trivy_docker(r, o, c, "fs")),
        "checkov": ScannerDefinition("checkov", "iac", "checkov", parse_checkov, _checkov_local, _checkov_docker, (0, 1), True),
        "trivy-config": ScannerDefinition("trivy-config", "iac", "trivy", parse_trivy_config, lambda r, o, c: _trivy_local("config", o), lambda r, o, c: _trivy_docker(r, o, c, "config")),
        "trivy-container": ScannerDefinition("trivy-container", "container", "trivy", parse_trivy_container, lambda r, o, c: _trivy_local("config", o, "."), lambda r, o, c: _trivy_docker(r, o, c, "config", ".")),
        "trivy-image": ScannerDefinition("trivy-image", "container", "trivy", parse_trivy_image, lambda r, o, c: _trivy_local("image", o, str(c["container"]["image"])), lambda r, o, c: _trivy_docker(r, o, c, "image", str(c["container"]["image"]))),
        "syft": ScannerDefinition("syft", "sbom", "syft", parse_none, _syft_local, _syft_docker),
        "zap": ScannerDefinition("zap", "dast", "zap-baseline.py", parse_zap, _zap_local, _zap_docker, (0, 1, 2)),
    }


def run_scanner(tool: str, root: Path, raw_dir: Path, config: dict[str, Any]) -> ToolRun:
    definitions = registry(config)
    if tool not in definitions:
        return ToolRun(tool=tool, module="unknown", command=[], installed=False, executed=False, error="unknown scanner")
    definition = definitions[tool]
    raw_dir.mkdir(parents=True, exist_ok=True)
    output = raw_dir / f"{tool}.json"
    mode = str(config.get("execution", {}).get("mode", "auto")).lower()
    timeout = int(config.get("execution", {}).get("timeout_seconds", 600))

    local_available = shutil.which(definition.binary) is not None
    docker_available = shutil.which("docker") is not None and definition.docker_builder is not None
    runner = "local"
    command: list[str]

    try:
        if mode == "local":
            if not local_available:
                return ToolRun(tool, definition.module, [], False, False, runner="local", error=f"{definition.binary} not found")
            command = definition.local_builder(root, output, config)
        elif mode == "docker":
            if not docker_available:
                return ToolRun(tool, definition.module, [], False, False, runner="docker", error="Docker fallback unavailable")
            runner = "docker"
            command = definition.docker_builder(root, output, config)  # type: ignore[misc]
        else:
            if local_available:
                command = definition.local_builder(root, output, config)
            elif docker_available:
                runner = "docker"
                command = definition.docker_builder(root, output, config)  # type: ignore[misc]
            else:
                return ToolRun(tool, definition.module, [], False, False, runner="auto", error=f"{definition.binary} and Docker fallback unavailable")
    except ValueError as exc:
        return ToolRun(tool, definition.module, [], True, False, runner=runner, error=str(exc))

    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        duration = int((time.perf_counter() - started) * 1000)
        return ToolRun(tool, definition.module, _redact_command(tool, command), True, True, runner, duration_ms=duration, error=str(exc))

    duration = int((time.perf_counter() - started) * 1000)
    if definition.capture_stdout and result.stdout and not output.exists():
        output.write_text(result.stdout, encoding="utf-8")

    error = None
    if result.returncode not in definition.allowed_return_codes:
        error = (result.stderr or result.stdout or f"scanner exited with {result.returncode}").strip()[:4000]

    findings: list[Finding] = []
    if output.exists():
        try:
            findings = definition.parser(output)
        except Exception as exc:  # parser errors are operational failures
            error = f"Unable to parse {tool} output: {exc}"

    return ToolRun(
        tool=tool,
        module=definition.module,
        command=_redact_command(tool, command),
        installed=True,
        executed=True,
        runner=runner,
        return_code=result.returncode,
        duration_ms=duration,
        output_file=str(output),
        error=error,
        findings=findings,
    )
