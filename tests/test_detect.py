from pathlib import Path

from gateshield.config import DEFAULT_CONFIG
from gateshield.detect import build_plan, detect_languages, detect_technologies


def test_detects_python_terraform_and_docker(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.0\n")
    (tmp_path / "app.py").write_text("print('x')\n")
    (tmp_path / "main.tf").write_text("terraform {}\n")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    assert "python" in detect_languages(tmp_path)
    technologies = detect_technologies(tmp_path)
    assert "terraform" in technologies
    assert "docker" in technologies


def test_plan_selects_scanners_from_detected_stack(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.0\n")
    (tmp_path / "app.py").write_text("print('x')\n")
    config = DEFAULT_CONFIG.copy()
    plan = build_plan(tmp_path, config)
    assert "semgrep" in plan.tools
    assert "bandit" in plan.tools
    assert "pip-audit" in plan.tools
    assert "gitleaks" in plan.tools
