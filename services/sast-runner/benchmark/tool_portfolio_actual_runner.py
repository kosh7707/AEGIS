from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
from collections import defaultdict
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.errors import RequiredToolUnavailableError
from app.scanner.orchestrator import ALL_TOOLS, ScanOrchestrator
from app.schemas.request import BuildProfile
from app.schemas.response import ExecutionReport, SastFinding
from benchmark.tool_portfolio_acquisition_manifest import (
    build_acquisition_index,
    manifest_checksum,
    validate_acquisition_manifest,
)
from benchmark.tool_portfolio_corpus_readiness import (
    build_corpus_readiness_gate,
)
from benchmark.tool_portfolio_experiment_manifest import (
    required_current_six_configs,
    validate_corpus_manifest,
    validate_tool_set_config,
)
from benchmark.tool_portfolio_experiment_report import (
    build_experiment_report,
    write_experiment_report,
)
from benchmark.tool_portfolio_system_gate import (
    build_system_stability_gate,
    default_not_run_system_gate,
)

ACTUAL_RUN_DEFAULT_MATCHING_POLICY = {
    "schemaVersion": "s4-oracle-matching-policy-v1",
    "lineWindowDefault": 5,
    "functionFallbackDefault": False,
}
ACTUAL_RUN_FAIL_CLOSED_THRESHOLDS = {
    "requiredSplits": ["validation", "test"],
}
ACTUAL_RUN_RULESETS = ["p/c", "p/security-audit"]
_CLI_INPUT_INVALID = "input validation failed"
_CLI_RUN_FAILED = "actual run failed"
_CLI_OUTPUT_FAILED = "output write failed"
_CLI_INPUT_INVALID_REASON = "ACTUAL_RUN_CLI_INPUT_INVALID"
_CLI_RUN_FAILED_REASON = "ACTUAL_RUN_FAILED"
_CLI_OUTPUT_FAILED_REASON = "ACTUAL_RUN_OUTPUT_WRITE_FAILED"


class _FixedDiagnosticArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise ValueError(_CLI_INPUT_INVALID)


def _emit_cli_error(*, error: str, reason_code: str, stage: str) -> None:
    try:
        sys.stderr.write(json.dumps({
            "error": error,
            "reasonCode": reason_code,
            "stage": stage,
        }, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, TypeError, ValueError, UnicodeError):
        return None


def _parse_cli_timeout(raw_timeout: str) -> int:
    value = raw_timeout.strip()
    if not value or not value.isdecimal():
        raise ValueError(_CLI_INPUT_INVALID)
    try:
        parsed = int(value)
    except (OverflowError, ValueError):
        raise ValueError(_CLI_INPUT_INVALID) from None
    if parsed <= 0:
        raise ValueError(_CLI_INPUT_INVALID)
    return parsed


def stage_case_only_corpus(
    *,
    corpus_manifest: Mapping[str, Any],
    acquisition_manifests: Sequence[Mapping[str, Any]],
    work_dir: Path | str,
    base_path: Path | str | None = None,
) -> dict[str, Any]:
    """Create a deterministic case-only staging tree for actual tool runs.

    The production scanner constrains only compile-based tools with
    ``source_files``; text/tree tools inspect their whole ``scan_dir``. This
    staging step makes ``scan_dir`` itself case-only while preserving the
    manifest ``sourcePath`` values used by oracle matching.
    """

    acquisition_index = build_acquisition_index(acquisition_manifests)
    validate_corpus_manifest(corpus_manifest, acquisition_index=acquisition_index)

    stage_root = Path(work_dir) / "staged-cases"
    _reset_stage_root(stage_root)
    stage_root = stage_root.resolve()

    cases_by_acquisition: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in corpus_manifest.get("cases", []):
        if isinstance(case, Mapping):
            cases_by_acquisition[str(case.get("acquisitionId") or "")].append(dict(case))

    staged_acquisitions: list[dict[str, Any]] = []
    staged_checksum_by_acquisition: dict[str, str] = {}
    for acquisition_id in sorted(cases_by_acquisition):
        if acquisition_id not in acquisition_index:
            continue
        original_manifest = dict(acquisition_index[acquisition_id]["manifest"])
        source_root = _resolve_acquisition_root(original_manifest.get("localPath"), base_path)
        staged_local_root = stage_root / acquisition_id
        for case in sorted(cases_by_acquisition[acquisition_id], key=lambda item: str(item.get("sourcePath") or "")):
            source_path = _safe_source_path(case.get("sourcePath"))
            source_file = (source_root / source_path).resolve()
            try:
                source_file.relative_to(source_root)
            except ValueError:
                raise ValueError("case sourcePath escapes acquisition root") from None
            if not source_file.is_file():
                raise ValueError("case source file is missing")
            target = staged_local_root / source_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target)

        staged_manifest = {
            **original_manifest,
            "localPath": str(staged_local_root.resolve()),
            "extractionRootChecksum": _sha256_tree(staged_local_root),
        }
        validate_acquisition_manifest(staged_manifest)
        staged_acquisitions.append(staged_manifest)
        staged_checksum_by_acquisition[acquisition_id] = manifest_checksum(staged_manifest)

    staged_cases: list[dict[str, Any]] = []
    for case in corpus_manifest.get("cases", []):
        staged_case = dict(case)
        acquisition_id = str(staged_case.get("acquisitionId") or "")
        if acquisition_id in staged_checksum_by_acquisition:
            staged_case["acquisitionManifestChecksum"] = staged_checksum_by_acquisition[acquisition_id]
        staged_cases.append(staged_case)

    staged_corpus = {
        **dict(corpus_manifest),
        "cases": staged_cases,
    }
    validate_corpus_manifest(staged_corpus, acquisition_index=build_acquisition_index(staged_acquisitions))
    return {
        "stagingRoot": str(stage_root),
        "corpusManifest": staged_corpus,
        "acquisitionManifests": staged_acquisitions,
    }


async def build_actual_tool_portfolio_report(
    *,
    corpus_manifest: Mapping[str, Any],
    acquisition_manifests: Sequence[Mapping[str, Any]],
    work_dir: Path | str,
    orchestrator: Any | None = None,
    run_id: str = "s4-tool-portfolio-actual-run",
    created_at: str = "2026-05-13T00:00:00Z",
    phase: str = "test",
    required_corpora: Sequence[str] | None = None,
    matching_policy: Mapping[str, Any] | None = None,
    thresholds: Mapping[str, Any] | None = None,
    timeout: int = 300,
    corpus_readiness_base_path: Path | str | None = None,
    repo_root: Path | str | None = None,
) -> dict[str, Any]:
    """Run the current S4 tool portfolio against a pinned local corpus.

    Unit tests pass a fake orchestrator; real CLI use defaults to
    :class:`ScanOrchestrator`.
    """

    required = list(required_corpora) if required_corpora is not None else _acquisition_ids(acquisition_manifests)
    base_path = Path(corpus_readiness_base_path) if corpus_readiness_base_path is not None else None
    original_readiness = build_corpus_readiness_gate(
        acquisition_manifests=acquisition_manifests,
        corpus_manifest=corpus_manifest,
        required_corpora=required,
        base_path=base_path,
    )
    empty_findings = _empty_findings_by_config()
    policy = dict(matching_policy or ACTUAL_RUN_DEFAULT_MATCHING_POLICY)
    threshold_payload = dict(thresholds or ACTUAL_RUN_FAIL_CLOSED_THRESHOLDS)

    if original_readiness.get("status") != "available":
        return build_experiment_report(
            run_id=run_id,
            created_at=created_at,
            phase=phase,
            corpus_manifest=corpus_manifest,
            acquisition_manifests=acquisition_manifests,
            findings_by_config=empty_findings,
            matching_policy=policy,
            thresholds=threshold_payload,
            corpus_readiness_gate=original_readiness,
            system_stability=default_not_run_system_gate(),
            repo_root=repo_root,
        )

    staged = stage_case_only_corpus(
        corpus_manifest=corpus_manifest,
        acquisition_manifests=acquisition_manifests,
        work_dir=work_dir,
        base_path=base_path,
    )
    staged_corpus = staged["corpusManifest"]
    staged_acquisitions = staged["acquisitionManifests"]
    staged_readiness = build_corpus_readiness_gate(
        acquisition_manifests=staged_acquisitions,
        corpus_manifest=staged_corpus,
        required_corpora=required,
    )
    runner = orchestrator or ScanOrchestrator()
    tool_availability = await runner.check_tools(force=True)

    findings_by_config: dict[str, list[SastFinding]] = _empty_findings_by_config()
    full_executions: list[ExecutionReport] = []
    comparative_failures: list[dict[str, Any]] = []
    acquisition_by_id = {item["acquisitionId"]: item for item in staged_acquisitions}
    original_acquisition_by_id = {
        str(item.get("acquisitionId") or ""): dict(item)
        for item in acquisition_manifests
        if isinstance(item, Mapping)
    }
    cases_by_acquisition = _cases_by_acquisition(staged_corpus)

    for config in required_current_six_configs():
        config_info = validate_tool_set_config(config)
        tools = list(config_info.get("tools") or [])
        kind = str(config_info.get("kind") or "")
        if kind in {"parser-only", "contract-canary"}:
            continue
        for acquisition_id, cases in sorted(cases_by_acquisition.items()):
            if acquisition_id not in acquisition_by_id:
                continue
            try:
                findings, execution = await runner.run(
                    scan_dir=Path(acquisition_by_id[acquisition_id]["localPath"]),
                    source_files=_source_files(cases),
                    profile=_profile_for_acquisition(original_acquisition_by_id.get(acquisition_id, {}), base_path=base_path),
                    rulesets=ACTUAL_RUN_RULESETS,
                    tools=tools,
                    timeout=timeout,
                )
            except RequiredToolUnavailableError as exc:
                execution = exc.execution
                if isinstance(execution, ExecutionReport) and config == "full-current-six":
                    full_executions.append(execution)
                comparative_failures.append({
                    "toolSetConfig": config,
                    "acquisitionId": acquisition_id,
                    "reasonCode": exc.code,
                    "toolFailures": [dict(failure) for failure in exc.tool_failures],
                })
                if config == "full-current-six":
                    system_stability = build_system_stability_gate(
                        required_tools=ALL_TOOLS,
                        tool_availability=tool_availability,
                        tool_results=_merge_tool_results(full_executions),
                    )
                    report = build_experiment_report(
                        run_id=run_id,
                        created_at=created_at,
                        phase=phase,
                        corpus_manifest=staged_corpus,
                        acquisition_manifests=staged_acquisitions,
                        findings_by_config=findings_by_config,
                        matching_policy=policy,
                        thresholds=threshold_payload,
                        corpus_readiness_gate=staged_readiness,
                        system_stability=system_stability,
                        repo_root=repo_root,
                    )
                    report["actualRunCompleteness"] = _actual_run_completeness(comparative_failures)
                    return report
                continue
            findings_by_config[config].extend(findings)
            if config == "full-current-six":
                full_executions.append(execution)
            else:
                comparative_failures.extend(_comparative_failures(config, acquisition_id, tools, execution))

    system_stability = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=tool_availability,
        tool_results=_merge_tool_results(full_executions),
    )
    actual_run_completeness = _actual_run_completeness(comparative_failures) if comparative_failures else None
    report = build_experiment_report(
        run_id=run_id,
        created_at=created_at,
        phase=phase,
        corpus_manifest=staged_corpus,
        acquisition_manifests=staged_acquisitions,
        findings_by_config=findings_by_config,
        matching_policy=policy,
        thresholds=threshold_payload,
        corpus_readiness_gate=staged_readiness,
        system_stability=system_stability,
        tool_contribution_completeness=actual_run_completeness,
        repo_root=repo_root,
    )
    if actual_run_completeness is not None:
        report["actualRunCompleteness"] = actual_run_completeness
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = _FixedDiagnosticArgumentParser(
        description="Run S4 actual Tool Portfolio experiment over pinned local corpus manifests.",
    )
    parser.add_argument("--corpus-manifest", required=True)
    parser.add_argument("--acquisition-manifest", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument(
        "--base-path",
        default=None,
        help="Explicit base path for relative acquisition localPath values.",
    )
    parser.add_argument("--run-id", default="s4-tool-portfolio-actual-run")
    parser.add_argument("--created-at", default="2026-05-13T00:00:00Z")
    parser.add_argument("--phase", choices=["validation", "test"], default="test")
    parser.add_argument("--required-corpus", action="append", default=None)
    parser.add_argument("--matching-policy-json", default=None)
    parser.add_argument("--thresholds-json", default=None)
    parser.add_argument("--timeout", default="300")

    try:
        args = parser.parse_args(argv)
        timeout = _parse_cli_timeout(args.timeout)
        corpus_manifest = _load_json_object(Path(args.corpus_manifest))
        acquisition_manifests = [_load_json_object(Path(path)) for path in args.acquisition_manifest]
        matching_policy = _load_json_object(Path(args.matching_policy_json)) if args.matching_policy_json else None
        thresholds = _load_json_object(Path(args.thresholds_json)) if args.thresholds_json else None
    except ValueError:
        _emit_cli_error(
            error=_CLI_INPUT_INVALID,
            reason_code=_CLI_INPUT_INVALID_REASON,
            stage="input",
        )
        return 1
    try:
        report = asyncio.run(build_actual_tool_portfolio_report(
            corpus_manifest=corpus_manifest,
            acquisition_manifests=acquisition_manifests,
            work_dir=args.work_dir,
            run_id=args.run_id,
            created_at=args.created_at,
            phase=args.phase,
            required_corpora=args.required_corpus,
            matching_policy=matching_policy,
            thresholds=thresholds,
            timeout=timeout,
            corpus_readiness_base_path=args.base_path,
        ))
    except Exception:
        _emit_cli_error(
            error=_CLI_RUN_FAILED,
            reason_code=_CLI_RUN_FAILED_REASON,
            stage="run",
        )
        return 1
    try:
        write_experiment_report(report, args.output)
    except (OSError, TypeError, ValueError, UnicodeError):
        _emit_cli_error(
            error=_CLI_OUTPUT_FAILED,
            reason_code=_CLI_OUTPUT_FAILED_REASON,
            stage="output",
        )
        return 1
    return 0 if report.get("qualityGate", {}).get("status") == "pass" else 2


def _reset_stage_root(stage_root: Path) -> None:
    if stage_root.exists():
        if stage_root.name != "staged-cases":
            raise ValueError("refusing to reset non-staging directory")
        shutil.rmtree(stage_root)
    stage_root.mkdir(parents=True, exist_ok=True)


def _safe_source_path(value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("case sourcePath must be a non-empty string")
    path = Path(value)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise ValueError("case sourcePath is unsafe")
    return path


def _resolve_acquisition_root(local_path: Any, base_path: Path | str | None) -> Path:
    if not isinstance(local_path, str) or not local_path:
        raise ValueError("acquisition localPath must be a non-empty string")
    path = Path(local_path)
    if path.is_absolute():
        return path.resolve()
    if base_path is None:
        raise ValueError("relative acquisition localPath requires explicit base path")
    base = Path(base_path).resolve()
    candidate = (base / path).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        raise ValueError("relative acquisition localPath escapes base path") from None
    return candidate


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _sha256_tree(root: Path) -> str:
    digest = sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256_file(path).encode("utf-8"))
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _acquisition_ids(acquisition_manifests: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted({
        str(item.get("acquisitionId"))
        for item in acquisition_manifests
        if isinstance(item, Mapping) and item.get("acquisitionId")
    })


def _empty_findings_by_config() -> dict[str, list[SastFinding]]:
    return {config: [] for config in required_current_six_configs()}


def _cases_by_acquisition(corpus_manifest: Mapping[str, Any]) -> dict[str, list[Mapping[str, Any]]]:
    cases: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for case in corpus_manifest.get("cases", []):
        if isinstance(case, Mapping):
            cases[str(case.get("acquisitionId") or "")].append(case)
    return cases


def _source_files(cases: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted({str(case.get("sourcePath")) for case in cases if case.get("sourcePath")})


def _profile_for_acquisition(acquisition: Mapping[str, Any], *, base_path: Path | str | None = None) -> BuildProfile | None:
    root = _resolve_acquisition_root(acquisition.get("localPath"), base_path)
    support = root / "C" / "testcasesupport"
    if support.is_dir():
        return BuildProfile(
            sdkResolutionMode="none",
            compiler="gcc",
            targetArch="x86_64",
            languageStandard="c11",
            headerLanguage="c",
            includePaths=[str(support)],
        )
    return None


def _merge_tool_results(executions: Sequence[ExecutionReport]) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for tool in ALL_TOOLS:
        observed = [execution.tool_results.get(tool) for execution in executions if tool in execution.tool_results]
        if not observed:
            continue
        status = _merged_status([item.status for item in observed])
        degrade_reasons = sorted({
            reason
            for item in observed
            for reason in (item.degrade_reasons or [])
            if reason
        })
        skip_reasons = sorted({item.skip_reason for item in observed if item.skip_reason})
        versions = sorted({item.version for item in observed if item.version})
        merged[tool] = {
            "status": status,
            "findingsCount": sum(item.findings_count for item in observed),
            "elapsedMs": sum(item.elapsed_ms for item in observed),
            "version": versions[0] if len(versions) == 1 else "mixed" if versions else None,
            "degraded": any(bool(item.degraded) for item in observed),
            "degradeReasons": degrade_reasons or None,
            "skipReason": ";".join(skip_reasons) if skip_reasons and status != "ok" else None,
            "timedOutFiles": _sum_optional(item.timed_out_files for item in observed),
            "failedFiles": _sum_optional(item.failed_files for item in observed),
            "filesAttempted": _sum_optional(item.files_attempted for item in observed),
            "batchCount": _sum_optional(item.batch_count for item in observed),
        }
    return merged


def _merged_status(statuses: Sequence[str]) -> str:
    if any(status == "failed" for status in statuses):
        return "failed"
    if any(status == "partial" for status in statuses):
        return "partial"
    if all(status == "skipped" for status in statuses):
        return "skipped"
    if any(status != "ok" for status in statuses):
        return "partial"
    return "ok"


def _sum_optional(values: Any) -> int | None:
    total = 0
    observed = False
    for value in values:
        if value is None:
            continue
        observed = True
        total += int(value)
    return total if observed else None


def _comparative_failures(
    config: str,
    acquisition_id: str,
    requested_tools: Sequence[str],
    execution: ExecutionReport,
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for tool in requested_tools:
        result = execution.tool_results.get(tool)
        if result is None:
            failures.append({
                "toolSetConfig": config,
                "acquisitionId": acquisition_id,
                "toolId": tool,
                "reasonCode": "TOOL_RESULT_NOT_RECORDED",
            })
            continue
        if result.status != "ok" or result.degraded:
            failures.append({
                "toolSetConfig": config,
                "acquisitionId": acquisition_id,
                "toolId": tool,
                "status": result.status,
                "reasonCode": result.skip_reason or ("tool-degraded" if result.degraded else f"tool-{result.status}"),
                "degradeReasons": list(result.degrade_reasons or []),
            })
    return failures


def _actual_run_completeness(failures: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "status": "fail" if failures else "pass",
        "consumerPolicy": "comparative_config_requested_tool_completeness_not_negative_security_evidence",
        "failures": [dict(failure) for failure in failures],
    }


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        raise ValueError("JSON input could not be read") from None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        raise ValueError("JSON input is malformed") from None
    if not isinstance(value, Mapping):
        raise ValueError("JSON input must be an object")
    return dict(value)


if __name__ == "__main__":
    raise SystemExit(main())
