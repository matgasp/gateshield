from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Iterable

from gateshield.models import ScanPlan


LANGUAGE_MARKERS: dict[str, tuple[str, ...]] = {
    "python": ("pyproject.toml", "requirements.txt", "Pipfile", "setup.py"),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "go": ("go.mod",),
    "cpp": ("CMakeLists.txt", "conanfile.py", "conanfile.txt", "vcpkg.json"),
    "javascript": ("package.json",),
    "dotnet": ("*.csproj", "*.sln"),
}

SOURCE_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "python": (".py",),
    "java": (".java",),
    "go": (".go",),
    "cpp": (".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"),
    "javascript": (".js", ".jsx", ".ts", ".tsx"),
    "dotnet": (".cs",),
}

KNOWN_TOOLS = {
    "semgrep",
    "bandit",
    "pip-audit",
    "gitleaks",
    "trivy-fs",
    "checkov",
    "trivy-config",
    "trivy-container",
    "trivy-image",
    "syft",
    "zap",
}


def _iter_files(root: Path) -> Iterable[Path]:
    ignored = {".git", ".venv", "venv", "node_modules", ".gateshield", "dist", "build"}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in ignored for part in path.parts):
            continue
        yield path


def _exists_marker(root: Path, marker: str) -> bool:
    if "*" in marker:
        return any(root.rglob(marker))
    return (root / marker).exists()


def detect_languages(root: Path) -> list[str]:
    languages: set[str] = set()
    for language, markers in LANGUAGE_MARKERS.items():
        if any(_exists_marker(root, marker) for marker in markers):
            languages.add(language)

    for path in _iter_files(root):
        for language, extensions in SOURCE_EXTENSIONS.items():
            if path.suffix.lower() in extensions:
                languages.add(language)
    return sorted(languages)


def detect_technologies(root: Path) -> list[str]:
    technologies: set[str] = set()
    if any(root.rglob("*.tf")):
        technologies.add("terraform")
    if any(path.name.lower() == "dockerfile" for path in _iter_files(root)):
        technologies.add("docker")
    if any(root.rglob("Chart.yaml")):
        technologies.add("helm")

    for path in _iter_files(root):
        if path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:4096]
        except OSError:
            continue
        if "apiVersion:" in text and "kind:" in text:
            technologies.add("kubernetes")
            break
    return sorted(technologies)


def get_changed_files(root: Path, base_ref: str) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    return sorted(line.strip() for line in result.stdout.splitlines() if line.strip())


def is_fork_pull_request() -> bool:
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        return False
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return False
    try:
        data = json.loads(Path(event_path).read_text(encoding="utf-8"))
        return bool(data.get("pull_request", {}).get("head", {}).get("repo", {}).get("fork", False))
    except (OSError, json.JSONDecodeError):
        return False


def _scope_is_incremental(config: dict) -> bool:
    mode = str(config.get("scope", {}).get("mode", "auto")).lower()
    if mode == "full":
        return False
    if mode == "incremental":
        return True
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    return event == "pull_request"


def _requested(value: object, auto_condition: bool) -> bool:
    if value is True:
        return True
    if value is False:
        return False
    return isinstance(value, str) and value.lower() == "auto" and auto_condition


def _modules_for_changes(changed_files: list[str]) -> set[str]:
    modules: set[str] = set()
    source_exts = {ext for values in SOURCE_EXTENSIONS.values() for ext in values}
    manifests = {
        "requirements.txt", "pyproject.toml", "pipfile", "pom.xml", "build.gradle",
        "build.gradle.kts", "go.mod", "go.sum", "package.json", "package-lock.json",
        "yarn.lock", "pnpm-lock.yaml", "vcpkg.json", "conanfile.py", "conanfile.txt",
        "packages.lock.json", "*.csproj",
    }
    for name in changed_files:
        path = Path(name)
        lower = name.lower()
        if path.suffix.lower() in source_exts:
            modules.update({"sast", "secrets"})
        if path.name.lower() in manifests or path.suffix.lower() == ".csproj":
            modules.update({"sca", "sbom", "secrets"})
        if path.suffix.lower() == ".tf" or "terraform" in lower:
            modules.update({"iac", "secrets"})
        if path.name.lower() == "dockerfile" or lower.endswith("/dockerfile"):
            modules.update({"container", "sbom", "secrets"})
        if path.name == "Chart.yaml" or "k8s" in lower or "kubernetes" in lower:
            modules.update({"iac", "secrets"})
        if lower.startswith(".github/workflows/"):
            modules.update({"iac", "secrets"})
    return modules


def _default_tools(root: Path, languages: list[str], technologies: list[str], modules: set[str], config: dict) -> list[str]:
    tools: list[str] = []
    if "sast" in modules:
        tools.append("semgrep")
        if "python" in languages:
            tools.append("bandit")
    if "sca" in modules:
        if "python" in languages and (root / "requirements.txt").exists():
            tools.append("pip-audit")
        tools.append("trivy-fs")
    if "secrets" in modules:
        tools.append("gitleaks")
    if "iac" in modules:
        tools.extend(["checkov", "trivy-config"])
    if "container" in modules:
        tools.append("trivy-container")
        if config.get("container", {}).get("image"):
            tools.append("trivy-image")
    if "sbom" in modules:
        tools.append("syft")
    if "dast" in modules:
        tools.append("zap")
    return list(dict.fromkeys(tools))


def _apply_scanner_overrides(tools: list[str], modules: set[str], config: dict) -> list[str]:
    result = list(tools)
    scanners = config.get("scanners", {}) or {}
    for module in modules:
        override = scanners.get(module, {}) or {}
        for tool in override.get("include", []) or []:
            if tool not in KNOWN_TOOLS:
                raise ValueError(f"Unknown scanner requested for {module}: {tool}")
            if tool not in result:
                result.append(tool)
        excluded = set(override.get("exclude", []) or [])
        result = [tool for tool in result if tool not in excluded]
    return result


def build_plan(root: Path, config: dict) -> ScanPlan:
    configured = config.get("stack", {}).get("languages", []) or []
    languages = sorted(set(configured))
    if config.get("stack", {}).get("auto_detect", True):
        languages = sorted(set(languages) | set(detect_languages(root)))
    technologies = detect_technologies(root)

    incremental = _scope_is_incremental(config)
    base_ref = str(config.get("scope", {}).get("base_ref", "origin/main"))
    changed_files = get_changed_files(root, base_ref) if incremental else []

    scan = config.get("scan", {})
    has_source = bool(languages)
    has_iac = any(item in technologies for item in ("terraform", "helm", "kubernetes"))
    has_container = "docker" in technologies
    has_dast_target = bool(config.get("dast", {}).get("target"))

    modules: set[str] = set()
    reasons: dict[str, list[str]] = {}

    conditions = {
        "sast": has_source,
        "sca": has_source,
        "secrets": True,
        "iac": has_iac,
        "container": has_container,
        "sbom": has_source or has_container,
        "dast": has_dast_target,
    }
    for module, condition in conditions.items():
        if _requested(scan.get(module), condition):
            modules.add(module)
            reasons.setdefault(module, []).append("enabled by configuration/autodetect")

    if incremental and changed_files:
        scoped = _modules_for_changes(changed_files)
        if "secrets" in modules:
            scoped.add("secrets")
        if "dast" in modules:
            scoped.add("dast")
        modules &= scoped
        reasons.setdefault("scope", []).append(f"incremental PR scope from {len(changed_files)} changed file(s)")

    if "dast" in modules and is_fork_pull_request():
        modules.remove("dast")
        reasons.setdefault("dast", []).append("skipped: DAST is disabled for fork pull requests")

    tools = _default_tools(root, languages, technologies, modules, config)
    tools = _apply_scanner_overrides(tools, modules, config)

    return ScanPlan(
        root=str(root),
        languages=languages,
        technologies=technologies,
        changed_files=changed_files,
        modules=sorted(modules),
        tools=tools,
        reasons=reasons,
        full_scan=not incremental,
    )
