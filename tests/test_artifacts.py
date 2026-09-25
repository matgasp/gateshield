import json
from pathlib import Path

from gateshield.artifacts import assemble_artifacts, artifact_specs, import_normalized_custom_findings
from gateshield.config import DEFAULT_CONFIG
from gateshield.models import Finding, ToolRun
from gateshield.report import write_json


def test_secrets_raw_is_disabled_by_default(tmp_path: Path) -> None:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    raw = tmp_path / ".gateshield" / "tmp" / "raw" / "gitleaks.json"
    raw.parent.mkdir(parents=True)
    raw.write_text("[]")
    run = ToolRun("gitleaks", "secrets", ["gitleaks"], True, True, output_file=str(raw), findings=[])
    report = {"gate": {}, "findings": []}
    sarif = write_json({"version": "2.1.0"}, tmp_path / ".gateshield" / "out" / "gateshield.sarif")
    assemble_artifacts(tmp_path, config, report, [run], sarif)
    secrets = next(item for item in artifact_specs(tmp_path, config) if item.key == "secrets")
    assert not (Path(secrets.path) / "raw" / "gitleaks.json").exists()


def test_custom_gateshield_artifact_is_imported(tmp_path: Path) -> None:
    custom = tmp_path / "custom.json"
    custom.write_text(json.dumps({"findings": [{"severity": "high", "title": "Internal finding"}]}))
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    config["artifacts"]["custom"] = [{
        "name": "internal",
        "path": "custom.json",
        "category": "sast",
        "format": "gateshield",
    }]
    findings = import_normalized_custom_findings(tmp_path, config)
    assert len(findings) == 1
    assert findings[0].module == "sast"
