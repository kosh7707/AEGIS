#!/usr/bin/env python3
"""Build Agent multi-dataset stabilization runner.

Reads a staged dataset manifest, generates strict build-resolve requests, and
classifies Build Agent responses against the canonical Build Agent state/outcome
contract. Dry-run mode is intentionally the default-safe verification path: it
validates the manifest and writes request JSON without contacting live services.
Live POSTs require explicit `--live` opt-in.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import shlex
import sys
import urllib.error
import urllib.request
from typing import Any

DEFAULT_MANIFEST = Path("/home/kosh/AEGIS/uploads/build-agent-stabilization-datasets/manifest.json")
DEFAULT_BUILD_URL = "http://localhost:8003"
DEFAULT_TIMEOUT_SEC = 900

COMPLETED_CLEAN = "completed_clean"
COMPLETED_NON_CLEAN = "completed_non_clean"
PREFLIGHT_FAILED = "preflight_failed"
TASK_FAILED = "task_failed"

NON_COMPLETED_STATUSES = {"validation_failed", "timeout", "model_error", "budget_exceeded"}
TASK_FAILURE_STATUSES = {"timeout", "model_error", "budget_exceeded"}


class StabilizationError(RuntimeError):
    """Base class for runner errors."""


class CaseValidationError(StabilizationError):
    """Raised when a manifest case is not usable as a test input."""


@dataclasses.dataclass(frozen=True)
class ExpectedOracle:
    task_class: str
    status: str | None = None
    clean_pass: bool | None = None
    build_outcome: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ExpectedOracle":
        return cls(
            task_class=str(raw.get("taskClass") or raw.get("task_class") or ""),
            status=raw.get("status"),
            clean_pass=raw.get("cleanPass"),
            build_outcome=raw.get("buildOutcome") or raw.get("build_outcome"),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "taskClass": self.task_class,
            "status": self.status,
            "cleanPass": self.clean_pass,
            "buildOutcome": self.build_outcome,
        }


@dataclasses.dataclass(frozen=True)
class ManifestCase:
    case_id: str
    title: str
    project_path: Path
    build_target_path: str
    build_target_name: str
    build: dict[str, Any]
    expected_artifacts: list[dict[str, Any]]
    expected_oracle: ExpectedOracle
    source_path: str | None = None

    @property
    def script_hint_path(self) -> str | None:
        value = self.build.get("scriptHintPath")
        return str(value) if value else None

    @property
    def build_mode(self) -> str:
        return str(self.build.get("mode") or "native")

    @property
    def effective_target_root(self) -> Path:
        target = self.build_target_path or "."
        if target in {".", ""}:
            return self.project_path
        return self.project_path / target

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ManifestCase":
        return cls(
            case_id=str(raw["caseId"]),
            title=str(raw.get("title") or raw["caseId"]),
            project_path=Path(str(raw["projectPath"])).expanduser(),
            build_target_path=str(raw.get("buildTargetPath") or "."),
            build_target_name=str(raw.get("buildTargetName") or raw["caseId"]),
            build=dict(raw.get("build") or {"mode": "native"}),
            expected_artifacts=list(raw.get("expectedArtifacts") or []),
            expected_oracle=ExpectedOracle.from_dict(dict(raw.get("expectedOracle") or {})),
            source_path=raw.get("sourcePath"),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "caseId": self.case_id,
            "title": self.title,
            "projectPath": str(self.project_path),
            "buildTargetPath": self.build_target_path,
            "buildTargetName": self.build_target_name,
            "build": self.build,
            "expectedArtifacts": self.expected_artifacts,
            "expectedOracle": self.expected_oracle.to_json(),
            "sourcePath": self.source_path,
        }


@dataclasses.dataclass(frozen=True)
class CaseClassification:
    case_id: str
    task_class: str
    status: str | None
    clean_pass: bool | None
    build_outcome: str | None
    build_outcome_clean_pass: bool | None
    failure_code: str | None
    unsafe_command_guard_passed: bool
    generated_script_guard_passed: bool
    generated_script_audit_passed: bool
    notes: list[str]

    def to_json(self) -> dict[str, Any]:
        return {
            "caseId": self.case_id,
            "taskClass": self.task_class,
            "status": self.status,
            "cleanPass": self.clean_pass,
            "buildOutcome": self.build_outcome,
            "buildOutcomeCleanPass": self.build_outcome_clean_pass,
            "failureCode": self.failure_code,
            "unsafeCommandGuardPassed": self.unsafe_command_guard_passed,
            "generatedScriptGuardPassed": self.generated_script_guard_passed,
            "generatedScriptAuditPassed": self.generated_script_audit_passed,
            "notes": self.notes,
        }


@dataclasses.dataclass(frozen=True)
class CaseComparison:
    case_id: str
    passed: bool
    mismatches: list[str]
    classification: CaseClassification
    expected: ExpectedOracle

    def to_json(self) -> dict[str, Any]:
        return {
            "caseId": self.case_id,
            "passed": self.passed,
            "mismatches": self.mismatches,
            "expected": self.expected.to_json(),
            "classification": self.classification.to_json(),
        }


def _is_relative_posix_path(value: str) -> bool:
    if not value or "\x00" in value or "\\" in value:
        return False
    if value.startswith("/") or value.startswith("//"):
        return False
    if len(value) >= 3 and value[1] == ":" and value[2] == "/":
        return False
    normalized = posixpath.normpath(value)
    if normalized == ".." or normalized.startswith("../"):
        return False
    return True


def _is_relative_target_path(value: str) -> bool:
    return value in {"", "."} or _is_relative_posix_path(value)


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def load_manifest(
    path: str | Path,
    selected_cases: set[str] | None = None,
    *,
    include_controls: bool = False,
) -> list[ManifestCase]:
    manifest_path = Path(path).expanduser()
    raw = json.loads(manifest_path.read_text())
    raw_cases = list(raw.get("cases", []))
    if include_controls:
        raw_cases.extend(raw.get("controls", []))
    cases = [ManifestCase.from_dict(item) for item in raw_cases]
    if selected_cases:
        known = {case.case_id for case in cases}
        missing = sorted(selected_cases - known)
        if missing:
            raise CaseValidationError(f"unknown selected case(s): {', '.join(missing)}")
        cases = [case for case in cases if case.case_id in selected_cases]
    if not cases:
        raise CaseValidationError("manifest contains no selected cases")
    for case in cases:
        validate_case(case)
    return cases


def validate_case(case: ManifestCase) -> None:
    if not case.case_id:
        raise CaseValidationError("caseId is required")
    if not case.project_path.is_dir():
        raise CaseValidationError(f"{case.case_id}: projectPath does not exist: {case.project_path}")
    if not _is_relative_target_path(case.build_target_path):
        raise CaseValidationError(f"{case.case_id}: buildTargetPath must be relative: {case.build_target_path}")
    target_root = case.effective_target_root
    if not target_root.is_dir():
        raise CaseValidationError(f"{case.case_id}: effective BuildTarget root not found: {target_root}")
    if not _is_relative_to(target_root, case.project_path):
        raise CaseValidationError(f"{case.case_id}: buildTargetPath escapes projectPath: {case.build_target_path}")
    if not case.expected_artifacts:
        raise CaseValidationError(f"{case.case_id}: expectedArtifacts must not be empty")
    if not case.expected_oracle.task_class:
        raise CaseValidationError(f"{case.case_id}: expectedOracle.taskClass is required")
    if case.script_hint_path:
        if not _is_relative_posix_path(case.script_hint_path):
            raise CaseValidationError(f"{case.case_id}: scriptHintPath must be safe relative POSIX path")
        hint_path = target_root / case.script_hint_path
        if not hint_path.is_file():
            raise CaseValidationError(f"{case.case_id}: scriptHintPath file not found: {hint_path}")
        if not _is_relative_to(hint_path, target_root):
            raise CaseValidationError(f"{case.case_id}: scriptHintPath escapes effective target root: {case.script_hint_path}")
    if case.build_mode == "sdk":
        _validate_sdk_descriptor(case)


def _validate_sdk_descriptor(case: ManifestCase) -> None:
    sdk_root_raw = case.build.get("sdkRootPath")
    if sdk_root_raw is not None:
        sdk_root = Path(str(sdk_root_raw)).expanduser()
        if not sdk_root.is_absolute():
            raise CaseValidationError(f"{case.case_id}: sdkRootPath must be absolute")
        if not sdk_root.is_dir():
            raise CaseValidationError(f"{case.case_id}: sdkRootPath does not exist: {sdk_root}")
    else:
        sdk_root = None

    def resolve_inside_root(field: str, *, must_be_file: bool) -> None:
        raw = case.build.get(field)
        if not raw or sdk_root is None:
            return
        raw_text = str(raw)
        if "\\" in raw_text or "\x00" in raw_text:
            raise CaseValidationError(f"{case.case_id}: {field} must use safe POSIX path text")
        candidate = Path(raw_text).expanduser()
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            normalized = posixpath.normpath(raw_text)
            if normalized == ".." or normalized.startswith("../") or "/../" in f"/{normalized}/":
                raise CaseValidationError(f"{case.case_id}: {field} must resolve inside sdkRootPath")
            resolved = (sdk_root / normalized).resolve()
        if not _is_relative_to(resolved, sdk_root):
            raise CaseValidationError(f"{case.case_id}: {field} must resolve inside sdkRootPath")
        if must_be_file and not resolved.is_file():
            raise CaseValidationError(f"{case.case_id}: {field} file not found: {resolved}")
        if not must_be_file and not resolved.is_dir():
            raise CaseValidationError(f"{case.case_id}: {field} directory not found: {resolved}")

    resolve_inside_root("setupScript", must_be_file=True)
    resolve_inside_root("sysroot", must_be_file=False)


def make_build_request(case: ManifestCase, run_label: str) -> dict[str, Any]:
    build = {"mode": case.build_mode}
    if case.script_hint_path:
        build["scriptHintPath"] = case.script_hint_path
    for key in ("sdkId", "sdkRootPath", "setupScript", "sysroot", "toolchainTriplet", "environment"):
        if key in case.build:
            build[key] = case.build[key]

    return {
        "contractVersion": "build-resolve-v1",
        "strictMode": True,
        "taskType": "build-resolve",
        "taskId": f"build-stabilization-{run_label}-{case.case_id}",
        "context": {
            "trusted": {
                "projectPath": str(case.project_path),
                "buildTargetPath": case.build_target_path or ".",
                "buildTargetName": case.build_target_name,
                "build": build,
                "expectedArtifacts": case.expected_artifacts,
            }
        },
        "constraints": {"maxTokens": 12000, "timeoutMs": DEFAULT_TIMEOUT_SEC * 1000},
    }


def _tokenize_command(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _response_build_fields(response: dict[str, Any]) -> tuple[str, str]:
    result = response.get("result") if isinstance(response.get("result"), dict) else {}
    build_result = result.get("buildResult") if isinstance(result.get("buildResult"), dict) else {}
    build_command = str(build_result.get("buildCommand") or "")
    build_script = str(build_result.get("buildScript") or "")
    return build_command, build_script


def _looks_like_generated_script_ref(value: str) -> bool:
    normalized = value.replace("\\", "/").strip().strip('"').strip("'")
    if not normalized:
        return False
    path = PurePosixPath(normalized)
    return path.name == "aegis-build.sh" and any(part.startswith("build-aegis-") for part in path.parts)


def _generated_script_guard(build_command: str, build_script: str) -> bool:
    script_is_generated = _looks_like_generated_script_ref(build_script)
    command_refs_generated = any(
        _looks_like_generated_script_ref(token)
        for token in _tokenize_command(build_command)
    )
    if not command_refs_generated and _looks_like_generated_script_ref(build_command):
        command_refs_generated = True
    return script_is_generated and command_refs_generated


def _extract_generated_script_path(case: ManifestCase, build_command: str, build_script: str) -> Path | None:
    candidates: list[str] = []
    if build_script:
        candidates.append(build_script)
    candidates.extend(_tokenize_command(build_command))
    for value in candidates:
        normalized = value.strip().strip('"').strip("'").replace("\\", "/")
        if not _looks_like_generated_script_ref(normalized):
            continue
        candidate = Path(normalized)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (case.effective_target_root / normalized).resolve()
        if _is_relative_to(resolved, case.effective_target_root):
            return resolved
    return None


def _allowed_descriptor_paths(case: ManifestCase) -> set[str]:
    allowed: set[str] = {str(case.project_path.resolve()), str(case.effective_target_root.resolve())}
    sdk_root_raw = case.build.get("sdkRootPath")
    if sdk_root_raw:
        sdk_root = Path(str(sdk_root_raw)).expanduser()
        allowed.add(str(sdk_root.resolve()))
        for key in ("setupScript", "sysroot"):
            raw = case.build.get(key)
            if not raw:
                continue
            candidate = Path(str(raw)).expanduser()
            if not candidate.is_absolute():
                candidate = sdk_root / str(raw)
            allowed.add(str(candidate.resolve()))
    return allowed


def _generated_script_content_audit(case: ManifestCase, build_command: str, build_script: str) -> tuple[bool, list[str]]:
    script_path = _extract_generated_script_path(case, build_command, build_script)
    if script_path is None:
        return False, ["generated script audit could not locate build-aegis-*/aegis-build.sh"]
    if not script_path.is_file():
        return False, [f"generated script audit could not read missing script: {script_path}"]
    try:
        content = script_path.read_text(errors="replace")
    except OSError as exc:
        return False, [f"generated script audit could not read script: {exc}"]

    notes: list[str] = []
    forbidden_markers = [
        "ti-processor-sdk-linux-am335x-evm-08.02.00.24",
        "${HOME}/ti-processor-sdk",
        "$HOME/ti-processor-sdk",
        "/home/kosh/ti-processor-sdk",
    ]
    for marker in forbidden_markers:
        if marker in content:
            notes.append(f"generated script contains forbidden host/SDK default marker: {marker}")

    sdk_root_raw = case.build.get("sdkRootPath")
    if "/home/kosh/ti-sdk" in content and str(sdk_root_raw or "") != "/home/kosh/ti-sdk":
        notes.append("generated script contains forbidden /home/kosh/ti-sdk path outside descriptor")

    for case_marker in ("gateway-webserver", "gateway-central", "gateway-mqtt_broker", "gateway-coap_server", "gateway-lwm2m_server"):
        if case_marker in content and case_marker != case.case_id:
            notes.append(f"generated script appears to special-case another fixture name: {case_marker}")

    # Absolute descriptor paths are allowed when they were supplied by the
    # manifest. Any stricter host-path policy belongs in the static guard.
    _ = _allowed_descriptor_paths(case)
    return not notes, notes


def _direct_script_guard(case: ManifestCase, build_command: str, build_script: str) -> tuple[bool, list[str]]:
    notes: list[str] = []
    hint = case.script_hint_path
    if not hint:
        return True, notes

    target_root = case.effective_target_root.resolve()
    direct_abs = (target_root / hint).resolve()
    normalized_hint = posixpath.normpath(hint)
    direct_rel_variants = {normalized_hint, f"./{normalized_hint}"}
    direct_abs_variants = {str(direct_abs)}

    for label, value in (("buildCommand", build_command), ("buildScript", build_script)):
        tokens = _tokenize_command(value)
        token_set = {token.strip().strip('"').strip("'") for token in tokens}
        if token_set & direct_rel_variants:
            notes.append(f"{label} token references scriptHintPath directly: {sorted(token_set & direct_rel_variants)}")
            return False, notes
        if token_set & direct_abs_variants:
            notes.append(f"{label} token references absolute scriptHintPath directly: {sorted(token_set & direct_abs_variants)}")
            return False, notes

        normalized_value = value.strip().strip('"').strip("'").replace("\\", "/")
        if normalized_value in direct_rel_variants:
            notes.append(f"{label} references scriptHintPath directly")
            return False, notes
        if normalized_value in direct_abs_variants:
            notes.append(f"{label} references absolute scriptHintPath directly")
            return False, notes

        # Fallback string containment catches simple shell snippets that shlex cannot
        # faithfully model, while still avoiding a blanket basename-only match.
        if str(direct_abs) in value:
            notes.append(f"{label} contains absolute scriptHintPath")
            return False, notes
        for marker in (f"bash {normalized_hint}", f"sh {normalized_hint}", f"./{normalized_hint}"):
            if marker in value:
                notes.append(f"{label} contains direct scriptHintPath marker: {marker}")
                return False, notes
    return True, notes


def classify_response(case: ManifestCase, response: dict[str, Any]) -> CaseClassification:
    status = response.get("status")
    notes: list[str] = []

    result = response.get("result") if isinstance(response.get("result"), dict) else {}
    build_outcome_blob = result.get("buildOutcome") if isinstance(result.get("buildOutcome"), dict) else {}
    diagnostics = result.get("buildDiagnostics") if isinstance(result.get("buildDiagnostics"), dict) else {}

    clean_pass = result.get("cleanPass") if isinstance(result, dict) else None
    build_outcome = build_outcome_blob.get("outcome") if isinstance(build_outcome_blob, dict) else None
    build_outcome_clean_pass = build_outcome_blob.get("cleanPass") if isinstance(build_outcome_blob, dict) else None
    failure_code = response.get("failureCode") or diagnostics.get("failureCode")

    build_command, build_script = _response_build_fields(response)
    unsafe_guard, guard_notes = _direct_script_guard(case, build_command, build_script)
    notes.extend(guard_notes)
    generated_guard = _generated_script_guard(build_command, build_script)
    script_audit_guard = True
    if status == "completed":
        script_audit_guard, script_audit_notes = _generated_script_content_audit(case, build_command, build_script)
        notes.extend(script_audit_notes)

    if status == "completed":
        if (
            clean_pass is True
            and build_outcome_clean_pass is True
            and build_outcome == "built"
            and unsafe_guard
            and generated_guard
            and script_audit_guard
        ):
            task_class = COMPLETED_CLEAN
        else:
            task_class = COMPLETED_NON_CLEAN
            if clean_pass is True and build_outcome_clean_pass is not True:
                notes.append("result.cleanPass=true but result.buildOutcome.cleanPass is not true")
            if clean_pass is True and build_outcome != "built":
                notes.append(f"result.cleanPass=true but buildOutcome.outcome={build_outcome!r}")
            if clean_pass is True and not generated_guard:
                notes.append("clean response lacks generated build-aegis-*/aegis-build.sh evidence")
            if clean_pass is True and not script_audit_guard:
                notes.append("clean response failed generated script content audit")
            if clean_pass is True and not unsafe_guard:
                notes.append("clean response attempted direct reference script execution")
    elif status == "validation_failed":
        task_class = PREFLIGHT_FAILED
    else:
        if status not in TASK_FAILURE_STATUSES:
            notes.append(f"unrecognized non-completed status treated as task_failed: {status!r}")
        task_class = TASK_FAILED

    return CaseClassification(
        case_id=case.case_id,
        task_class=task_class,
        status=str(status) if status is not None else None,
        clean_pass=clean_pass if isinstance(clean_pass, bool) else None,
        build_outcome=str(build_outcome) if build_outcome is not None else None,
        build_outcome_clean_pass=build_outcome_clean_pass if isinstance(build_outcome_clean_pass, bool) else None,
        failure_code=str(failure_code) if failure_code is not None else None,
        unsafe_command_guard_passed=unsafe_guard,
        generated_script_guard_passed=generated_guard,
        generated_script_audit_passed=script_audit_guard,
        notes=notes,
    )


def compare_to_expected(classification: CaseClassification, expected: ExpectedOracle) -> CaseComparison:
    mismatches: list[str] = []
    if expected.task_class and classification.task_class != expected.task_class:
        mismatches.append(f"taskClass expected {expected.task_class}, got {classification.task_class}")
    if expected.status is not None and classification.status != expected.status:
        mismatches.append(f"status expected {expected.status}, got {classification.status}")
    if expected.clean_pass is not None and classification.clean_pass is not expected.clean_pass:
        mismatches.append(f"cleanPass expected {expected.clean_pass}, got {classification.clean_pass}")
    if expected.build_outcome is not None and classification.build_outcome != expected.build_outcome:
        mismatches.append(f"buildOutcome expected {expected.build_outcome}, got {classification.build_outcome}")
    if not classification.unsafe_command_guard_passed:
        mismatches.append("unsafe command guard failed: direct scriptHintPath execution detected")
    if expected.task_class == COMPLETED_CLEAN and not classification.generated_script_guard_passed:
        mismatches.append("generated script guard failed for expected completed_clean case")
    if expected.task_class == COMPLETED_CLEAN and not classification.generated_script_audit_passed:
        mismatches.append("generated script audit failed for expected completed_clean case")
    return CaseComparison(
        case_id=classification.case_id,
        passed=not mismatches,
        mismatches=mismatches,
        classification=classification,
        expected=expected,
    )


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def _write_summary_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Build Agent stabilization run",
        "",
        f"- Run label: `{summary['runLabel']}`",
        f"- Mode: `{summary['mode']}`",
        f"- Manifest: `{summary['manifest']}`",
        f"- Passed: `{summary['passed']}`",
        "",
        "| Case | Passed | Task class | Status | cleanPass | buildOutcome | Notes |",
        "|---|---:|---|---|---:|---|---|",
    ]
    for case in summary["cases"]:
        classification = case.get("classification") or {}
        notes = "; ".join(classification.get("notes") or case.get("notes") or [])
        lines.append(
            f"| `{case['caseId']}` | {str(case['passed']).lower()} | "
            f"`{classification.get('taskClass', 'dry_run')}` | "
            f"`{classification.get('status', '-')}` | "
            f"`{classification.get('cleanPass', '-')}` | "
            f"`{classification.get('buildOutcome', '-')}` | {notes} |"
        )
    path.write_text("\n".join(lines) + "\n")


def _default_output_dir(run_label: str) -> Path:
    return Path("/home/kosh/AEGIS/uploads/build-agent-stabilization-runs") / run_label


def run_dry_run(cases: list[ManifestCase], manifest: Path, output_dir: Path, run_label: str) -> dict[str, Any]:
    case_summaries: list[dict[str, Any]] = []
    for case in cases:
        case_dir = output_dir / case.case_id
        request = make_build_request(case, run_label)
        _write_json(case_dir / "build-req.json", request)
        _write_json(case_dir / "case-manifest.json", case.to_json())
        case_summaries.append({
            "caseId": case.case_id,
            "passed": True,
            "requestPath": str(case_dir / "build-req.json"),
            "notes": ["dry-run request generated"],
        })
    summary = {
        "runLabel": run_label,
        "mode": "dry-run",
        "manifest": str(manifest),
        "outputDir": str(output_dir),
        "passed": True,
        "cases": case_summaries,
    }
    _write_json(output_dir / "summary.json", summary)
    _write_summary_markdown(output_dir / "summary.md", summary)
    return summary


def _post_json(url: str, payload: dict[str, Any], request_id: str, timeout_sec: int) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url.rstrip("/") + "/v1/tasks",
        data=body,
        headers={"Content-Type": "application/json", "X-Request-Id": request_id},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise StabilizationError(f"HTTP {exc.code} from Build Agent: {raw[:500]}") from exc
    return json.loads(raw)


def _live_error_response(exc: Exception) -> dict[str, Any]:
    message = str(exc) or exc.__class__.__name__
    if isinstance(exc, TimeoutError) or "timed out" in message.lower():
        status = "timeout"
        failure_code = "RUNNER_CLIENT_TIMEOUT"
    else:
        status = "model_error"
        failure_code = "RUNNER_LIVE_REQUEST_ERROR"
    return {
        "status": status,
        "failureCode": failure_code,
        "failureDetail": message[:2000],
        "runnerError": {
            "type": exc.__class__.__name__,
            "message": message[:2000],
        },
    }


def run_live(cases: list[ManifestCase], manifest: Path, output_dir: Path, run_label: str, build_url: str, timeout_sec: int) -> dict[str, Any]:
    case_summaries: list[dict[str, Any]] = []
    all_passed = True
    for case in cases:
        case_dir = output_dir / case.case_id
        request = make_build_request(case, run_label)
        request_id = request["taskId"]
        _write_json(case_dir / "build-req.json", request)
        try:
            response = _post_json(build_url, request, request_id, timeout_sec)
            _write_json(case_dir / "build-resp.json", response)
        except Exception as exc:
            response = _live_error_response(exc)
            _write_json(case_dir / "build-resp.json", response)
            _write_json(case_dir / "build-error.json", response["runnerError"])
        classification = classify_response(case, response)
        comparison = compare_to_expected(classification, case.expected_oracle)
        _write_json(case_dir / "classification.json", comparison.to_json())
        all_passed = all_passed and comparison.passed
        case_summaries.append(comparison.to_json())
    summary = {
        "runLabel": run_label,
        "mode": "live",
        "manifest": str(manifest),
        "outputDir": str(output_dir),
        "buildUrl": build_url,
        "passed": all_passed,
        "cases": case_summaries,
    }
    _write_json(output_dir / "summary.json", summary)
    _write_summary_markdown(output_dir / "summary.md", summary)
    return summary


def _run_label() -> str:
    return "build-agent-stabilization-" + _dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--case", dest="cases", action="append", default=[], help="caseId to run; repeatable")
    parser.add_argument("--run-label", default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--build-url", default=os.environ.get("S3_BUILD_URL", DEFAULT_BUILD_URL))
    parser.add_argument("--timeout-sec", type=int, default=DEFAULT_TIMEOUT_SEC)
    parser.add_argument("--dry-run", action="store_true", help="explicitly use the default safe mode: generate requests without POSTing")
    parser.add_argument("--live", action="store_true", help="opt in to POSTing requests to the live Build Agent")
    parser.add_argument("--include-controls", action="store_true", help="include manifest metamorphic/negative-control cases")
    args = parser.parse_args(argv)
    if args.dry_run and args.live:
        parser.error("--dry-run and --live are mutually exclusive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    run_label = args.run_label or _run_label()
    output_dir = args.output_dir or _default_output_dir(run_label)
    selected = set(args.cases) if args.cases else None

    try:
        cases = load_manifest(args.manifest, selected, include_controls=args.include_controls)
        if args.live:
            summary = run_live(cases, args.manifest, output_dir, run_label, args.build_url, args.timeout_sec)
        else:
            summary = run_dry_run(cases, args.manifest, output_dir, run_label)
    except StabilizationError as exc:
        print(f"[stabilization-runner] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - safety net for CLI use
        print(f"[stabilization-runner] unexpected error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary.get("passed") else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
