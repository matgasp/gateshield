from gateshield.baseline import apply_baseline, baseline_from_report, fingerprint
from gateshield.models import Finding


def _finding(line: int) -> Finding:
    return Finding(
        tool="semgrep",
        module="sast",
        severity="high",
        title="SQL injection",
        file="src/api.py",
        line=line,
        rule_id="python.sql",
        context="execute(query)",
    )


def test_fingerprint_does_not_depend_on_line_number() -> None:
    assert fingerprint(_finding(10)) == fingerprint(_finding(99))


def test_baseline_marks_existing_new_and_resolved() -> None:
    old = _finding(10)
    apply_baseline([old], None)
    report = {"schema_version": "1.0", "findings": [old.to_dict()]}
    baseline = baseline_from_report(report)

    current_old = _finding(20)
    new = Finding("semgrep", "sast", "high", "Other", "src/new.py", 1, "rule.other", context="x")
    summary = apply_baseline([current_old, new], baseline)
    assert current_old.baseline_status == "existing"
    assert new.baseline_status == "new"
    assert summary["existing"] == 1
    assert summary["new"] == 1

    resolved = apply_baseline([], baseline)
    assert resolved["resolved"] == 1
