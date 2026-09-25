from pathlib import Path

from gateshield.models import ScanPlan
from gateshield.report import add_gate, build_report, write_sarif_report
from gateshield.models import GateResult


def test_report_schema_and_sarif(tmp_path: Path) -> None:
    plan = ScanPlan(str(tmp_path), ["python"], [], [], ["sast"], [], {}, True)
    report = build_report(tmp_path, plan, [], {"active": False, "new": 0, "existing": 0, "resolved": 0, "resolved_findings": []}, "report")
    add_gate(report, GateResult("report", False, False, [], [], []))
    assert report["schema_version"] == "1.0"
    path = write_sarif_report(report, tmp_path / "result.sarif")
    assert path.exists()
