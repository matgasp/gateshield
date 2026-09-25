from gateshield.policy import evaluate


REPORT = {
    "baseline": {"active": True},
    "findings": [
        {"module": "sast", "severity": "high", "title": "new", "baseline_status": "new"},
        {"module": "sast", "severity": "critical", "title": "old", "baseline_status": "existing"},
    ],
}


def config(mode: str) -> dict:
    return {
        "mode": mode,
        "new_findings_only": True,
        "severity": {"critical": "block", "high": "block", "medium": "warn"},
        "categories": {},
    }


def test_enforce_blocks_only_new_findings_with_baseline() -> None:
    result = evaluate(REPORT, config("enforce"))
    assert result.would_block is True
    assert result.enforced_block is True
    assert len(result.blocking_findings) == 1


def test_report_and_external_do_not_enforce() -> None:
    for mode in ("report", "external"):
        result = evaluate(REPORT, config(mode))
        assert result.would_block is True
        assert result.enforced_block is False
