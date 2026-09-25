from pathlib import Path

import pytest

from gateshield.config import load_config, validate_config, write_default_config


def test_default_config_writes_gateshield_file(tmp_path: Path) -> None:
    path = write_default_config(tmp_path)
    assert path.name == ".gateshield.yml"
    config = load_config(tmp_path)
    assert config["scan"]["iac"] == "auto"
    assert config["gate"]["mode"] == "enforce"


def test_invalid_tri_state_is_rejected() -> None:
    config = {"scan": {name: False for name in ("sast", "sca", "secrets", "iac", "container", "sbom", "dast")}}
    config["scan"]["sast"] = "sometimes"
    with pytest.raises(ValueError):
        validate_config(config)
