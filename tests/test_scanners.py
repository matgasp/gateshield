import json
from pathlib import Path

import pytest

from gateshield.scanners import parse_gitleaks, parse_zap, validate_dast_target


def test_gitleaks_normalization_redacts_secret(tmp_path: Path) -> None:
    raw = tmp_path / "gitleaks.json"
    raw.write_text(json.dumps([{
        "Description": "Generic API Key",
        "RuleID": "generic-api-key",
        "File": "config.py",
        "StartLine": 3,
        "Secret": "TOP-SECRET",
    }]))
    finding = parse_gitleaks(raw)[0]
    assert "TOP-SECRET" not in (finding.message or "")
    assert finding.severity == "critical"


def test_zap_parser(tmp_path: Path) -> None:
    raw = tmp_path / "zap.json"
    raw.write_text(json.dumps({
        "site": [{
            "@name": "http://localhost:8080",
            "alerts": [{
                "name": "X-Frame-Options Header Not Set",
                "riskcode": "2",
                "pluginid": "10020",
                "instances": [{"uri": "http://localhost:8080/", "method": "GET"}],
            }],
        }]
    }))
    finding = parse_zap(raw)[0]
    assert finding.module == "dast"
    assert finding.severity == "medium"


def test_dast_allowlist_blocks_unapproved_host() -> None:
    config = {"dast": {"target": "https://example.com", "allowed_hosts": ["localhost"]}}
    with pytest.raises(ValueError):
        validate_dast_target(config)
