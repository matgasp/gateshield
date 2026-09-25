from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from gateshield import __version__
from gateshield.artifacts import (
    assemble_artifacts,
    import_normalized_custom_findings,
    write_github_outputs,
)
from gateshield.baseline import apply_baseline, load_baseline, write_baseline
from gateshield.config import load_config, write_default_config
from gateshield.constants import (
    EXIT_CONFIG_ERROR,
    EXIT_GATE_BLOCKED,
    EXIT_INVALID_REPORT,
    EXIT_MISSING_TOOL,
    EXIT_OK,
    EXIT_SCANNER_ERROR,
)
from gateshield.detect import build_plan
from gateshield.policy import evaluate
from gateshield.report import (
    add_gate,
    append_github_summary,
    build_report,
    load_report,
    write_json,
    write_markdown_report,
    write_sarif_report,
)
from gateshield.scanners import run_scanner, validate_dast_target
from gateshield.target import is_git_url, materialize_target
from gateshield.tools import inspect_tools, render_tools


def _path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _print_plan(plan: Any) -> None:
    print("GateShield plan")
    print("=" * 72)
    print(f"Languages:    {', '.join(plan.languages) or 'none'}")
    print(f"Technologies: {', '.join(plan.technologies) or 'none'}")
    print(f"Scope:        {'full' if plan.full_scan else 'incremental'}")
    if plan.changed_files:
        print(f"Changed:      {len(plan.changed_files)} file(s)")
    print(f"Categories:   {', '.join(plan.modules) or 'none'}")
    print("Scanners:")
    for tool in plan.tools:
        print(f"  - {tool}")
    if not plan.tools:
        print("  - none")


def _baseline_for(root: Path, config: dict[str, Any]) -> dict[str, Any] | None:
    baseline_cfg = config.get("baseline", {})
    enabled = baseline_cfg.get("enabled", "auto")
    path = root / str(baseline_cfg.get("path", ".gateshield/baseline.json"))
    if enabled is False:
        return None
    if isinstance(enabled, str) and enabled.lower() == "auto" and not path.exists():
        return None
    return load_baseline(path)


def _copy_outputs(source_root: Path, destination: Path) -> None:
    source = source_root / ".gateshield"
    if not source.exists():
        return
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination / ".gateshield", dirs_exist_ok=True)


def command_init(args: argparse.Namespace) -> int:
    root = _path(args.path)
    root.mkdir(parents=True, exist_ok=True)
    try:
        output = write_default_config(root, overwrite=args.force)
    except (FileExistsError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_CONFIG_ERROR
    print(f"Created {output}")
    return EXIT_OK


def command_plan(args: argparse.Namespace) -> int:
    try:
        with materialize_target(args.path) as root:
            config = load_config(root, args.config)
            plan = build_plan(root, config)
            if "dast" in plan.modules:
                validate_dast_target(config)
            if args.json:
                print(json.dumps(plan.to_dict(), indent=2))
            else:
                _print_plan(plan)
            return EXIT_OK
    except (RuntimeError, ValueError) as exc:
        print(f"GateShield configuration/target error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR


def _operational_exit(runs: list[Any], config: dict[str, Any]) -> int:
    missing = [run.tool for run in runs if not run.installed]
    errors = [run.tool for run in runs if run.error and run.installed]
    if missing and bool(config.get("execution", {}).get("require_tools", True)):
        return EXIT_MISSING_TOOL
    if errors:
        return EXIT_SCANNER_ERROR
    return EXIT_OK


def command_scan(args: argparse.Namespace) -> int:
    remote = is_git_url(args.path)
    try:
        with materialize_target(args.path) as root:
            config = load_config(root, args.config)
            plan = build_plan(root, config)
            config.setdefault("_runtime", {})["changed_files"] = [] if plan.full_scan else plan.changed_files
            if "dast" in plan.modules:
                validate_dast_target(config)
            _print_plan(plan)

            raw_dir = root / ".gateshield" / "tmp" / "raw"
            out_dir = root / ".gateshield" / "out"
            runs = []
            print("\nExecution")
            print("=" * 72)
            for tool in plan.tools:
                print(f"-> {tool}")
                run = run_scanner(tool, root, raw_dir, config)
                runs.append(run)
                if not run.installed:
                    print(f"   MISSING: {run.error}")
                elif run.error:
                    print(f"   ERROR: {run.error}")
                else:
                    print(f"   OK: {len(run.findings)} finding(s), runner={run.runner}, {run.duration_ms} ms")

            imported = import_normalized_custom_findings(root, config)
            all_findings = [finding for run in runs for finding in run.findings] + imported
            baseline = _baseline_for(root, config)
            baseline_summary = apply_baseline(all_findings, baseline)

            report = build_report(
                root=root,
                plan=plan,
                runs=runs,
                baseline_summary=baseline_summary,
                gate_mode=str(config.get("gate", {}).get("mode", "enforce")),
                imported_findings=[finding.to_dict() for finding in imported],
            )
            gate = evaluate(report, config.get("gate", {}))
            add_gate(report, gate)

            report_path = write_json(report, out_dir / "report.json")
            markdown_path = write_markdown_report(report, out_dir / "report.md")
            sarif_path = write_sarif_report(report, out_dir / "gateshield.sarif")
            append_github_summary(markdown_path)
            specs = assemble_artifacts(root, config, report, runs, sarif_path)

            if args.output:
                report_path = write_json(report, _path(args.output))
            if args.output_dir:
                _copy_outputs(root, _path(args.output_dir))
            elif remote:
                print("Note: remote target uses a temporary checkout; use --output-dir to persist all artifacts.")

            operational = _operational_exit(runs, config)
            if operational != EXIT_OK:
                final_exit = operational
            elif gate.enforced_block:
                final_exit = EXIT_GATE_BLOCKED
            else:
                final_exit = EXIT_OK

            write_github_outputs(specs, final_exit, report_path, sarif_path)

            print("\nResult")
            print("=" * 72)
            print(f"Report:       {report_path}")
            print(f"SARIF:        {sarif_path}")
            print(f"Findings:     {report['summary']['total']}")
            if baseline_summary.get("active"):
                print(
                    f"Baseline:     NEW={baseline_summary['new']} "
                    f"EXISTING={baseline_summary['existing']} RESOLVED={baseline_summary['resolved']}"
                )
            print(f"Gate mode:    {gate.mode}")
            print(f"Would block:  {gate.would_block}")
            print(f"Enforced:     {gate.enforced_block}")
            print(f"Exit code:    {final_exit}")
            for reason in gate.reasons:
                print(f"  - {reason}")

            return EXIT_OK if args.defer_exit else final_exit
    except ValueError as exc:
        print(f"GateShield configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    except RuntimeError as exc:
        print(f"GateShield target error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR


def command_gate(args: argparse.Namespace) -> int:
    report_path = _path(args.report)
    try:
        report = load_report(report_path)
        root = _path(args.root) if args.root else Path.cwd()
        config = load_config(root, args.config)
        gate = evaluate(report, config.get("gate", {}))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_INVALID_REPORT

    print(f"GateShield gate mode: {gate.mode}")
    print(f"Would block: {gate.would_block}")
    print(f"Enforced block: {gate.enforced_block}")
    for reason in gate.reasons:
        print(f"  - {reason}")
    return EXIT_GATE_BLOCKED if gate.enforced_block else EXIT_OK


def command_baseline_create(args: argparse.Namespace) -> int:
    try:
        report = load_report(_path(args.report))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_INVALID_REPORT
    output = _path(args.output)
    write_baseline(report, output)
    print(f"Baseline written: {output}")
    print(f"Findings recorded: {len(report.get('findings', []))}")
    return EXIT_OK


def command_tools(args: argparse.Namespace) -> int:
    root = _path(args.path)
    try:
        config = load_config(root, args.config)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_CONFIG_ERROR
    statuses = inspect_tools(config)
    if args.tools_command == "list":
        payload = [
            {"name": item.name, "pinned": item.pinned}
            for item in statuses
        ]
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            for item in payload:
                print(f"{item['name']:12} {item['pinned']}")
    else:
        print(render_tools(statuses, as_json=args.json))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gateshield",
        description="Policy-driven security orchestration for hardened CI/CD pipelines",
    )
    parser.add_argument("--version", action="version", version=f"GateShield {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Create .gateshield.yml")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--force", action="store_true")
    init.set_defaults(handler=command_init)

    plan = sub.add_parser("plan", help="Autodetect stack and show the security execution plan")
    plan.add_argument("path", nargs="?", default=".")
    plan.add_argument("--config")
    plan.add_argument("--json", action="store_true")
    plan.set_defaults(handler=command_plan)

    scan = sub.add_parser("scan", help="Run selected security checks")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--config")
    scan.add_argument("--output", help="Also write the consolidated JSON report to this path")
    scan.add_argument("--output-dir", help="Copy .gateshield outputs/artifacts to this directory")
    scan.add_argument("--defer-exit", action="store_true", help="Always return 0 and publish final_exit_code to GITHUB_OUTPUT")
    scan.set_defaults(handler=command_scan)

    gate = sub.add_parser("gate", help="Evaluate an existing GateShield report")
    gate.add_argument("report")
    gate.add_argument("--root")
    gate.add_argument("--config")
    gate.set_defaults(handler=command_gate)

    baseline = sub.add_parser("baseline", help="Manage finding baselines")
    baseline_sub = baseline.add_subparsers(dest="baseline_command", required=True)
    baseline_create = baseline_sub.add_parser("create", help="Create a baseline from an existing report")
    baseline_create.add_argument("report")
    baseline_create.add_argument("--output", default=".gateshield/baseline.json")
    baseline_create.set_defaults(handler=command_baseline_create)

    tools = sub.add_parser("tools", help="Inspect the pinned scanner toolchain")
    tools_sub = tools.add_subparsers(dest="tools_command", required=True)
    for name in ("list", "check"):
        item = tools_sub.add_parser(name)
        item.add_argument("--path", default=".")
        item.add_argument("--config")
        item.add_argument("--json", action="store_true")
        item.set_defaults(handler=command_tools)

    doctor = sub.add_parser("doctor", help="Alias for 'tools check'")
    doctor.add_argument("--path", default=".")
    doctor.add_argument("--config")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(handler=lambda args: command_tools(argparse.Namespace(**vars(args), tools_command="check")))

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
