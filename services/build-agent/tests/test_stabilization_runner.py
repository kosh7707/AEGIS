from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

import pytest


_RUNNER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "stabilization_runner.py"
_SPEC = importlib.util.spec_from_file_location("stabilization_runner", _RUNNER_PATH)
assert _SPEC and _SPEC.loader
runner = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = runner
_SPEC.loader.exec_module(runner)


def _case(tmp_path: Path, *, case_id: str = "demo", target: str = ".", script_hint: str = "build.sh"):
    project = tmp_path / case_id
    effective_root = project if target == "." else project / target
    effective_root.mkdir(parents=True)
    (effective_root / script_hint).parent.mkdir(parents=True, exist_ok=True)
    (effective_root / script_hint).write_text("#!/bin/sh\nmake\n")
    raw = {
        "caseId": case_id,
        "title": f"{case_id} fixture",
        "projectPath": str(project),
        "buildTargetPath": target,
        "buildTargetName": case_id,
        "build": {"mode": "native", "scriptHintPath": script_hint},
        "expectedArtifacts": [{"artifactType": "executable", "name": case_id}],
        "expectedOracle": {
            "taskClass": "completed_clean",
            "status": "completed",
            "cleanPass": True,
            "buildOutcome": "built",
        },
    }
    return runner.ManifestCase.from_dict(raw)


def _completed_response(*, clean=True, nested_clean=True, outcome="built", command="bash /tmp/p/build-aegis-abc/aegis-build.sh", script="build-aegis-abc/aegis-build.sh"):
    return {
        "status": "completed",
        "result": {
            "cleanPass": clean,
            "buildResult": {
                "success": clean,
                "buildCommand": command,
                "buildScript": script,
            },
            "buildOutcome": {"outcome": outcome, "cleanPass": nested_clean},
            "buildDiagnostics": {"failureCode": None if clean else "COMPILE_FAILED"},
        },
    }


def test_manifest_request_generation_uses_script_hint_path_not_inline_text(tmp_path: Path) -> None:
    case = _case(tmp_path)
    runner.validate_case(case)

    request = runner.make_build_request(case, "unit")
    trusted = request["context"]["trusted"]

    assert request["contractVersion"] == "build-resolve-v1"
    assert request["strictMode"] is True
    assert trusted["build"]["scriptHintPath"] == "build.sh"
    assert "scriptHintText" not in trusted["build"]
    assert "buildScriptHintText" not in trusted


def test_manifest_validation_uses_effective_target_root_for_nested_hint(tmp_path: Path) -> None:
    case = _case(tmp_path, target="firmware", script_hint=".aegis/build-script-hint.sh")

    runner.validate_case(case)

    assert case.effective_target_root == case.project_path / "firmware"


def test_completed_clean_requires_top_level_and_nested_cleanpass(tmp_path: Path) -> None:
    case = _case(tmp_path)

    classification = runner.classify_response(case, _completed_response())
    comparison = runner.compare_to_expected(classification, case.expected_oracle)

    assert classification.task_class == runner.COMPLETED_CLEAN
    assert comparison.passed is True


def test_completed_clean_rejects_contradictory_nested_cleanpass(tmp_path: Path) -> None:
    case = _case(tmp_path)

    classification = runner.classify_response(case, _completed_response(clean=True, nested_clean=False))
    comparison = runner.compare_to_expected(classification, case.expected_oracle)

    assert classification.task_class == runner.COMPLETED_NON_CLEAN
    assert any("buildOutcome.cleanPass" in note for note in classification.notes)
    assert comparison.passed is False


def test_artifact_mismatch_is_completed_non_clean(tmp_path: Path) -> None:
    case = _case(tmp_path)
    expected = runner.ExpectedOracle(
        task_class=runner.COMPLETED_NON_CLEAN,
        status="completed",
        clean_pass=False,
        build_outcome="artifact_mismatch",
    )

    response = _completed_response(clean=False, nested_clean=False, outcome="artifact_mismatch")
    response["result"]["buildDiagnostics"]["failureCode"] = "EXPECTED_ARTIFACTS_MISMATCH"
    classification = runner.classify_response(case, response)
    comparison = runner.compare_to_expected(classification, expected)

    assert classification.task_class == runner.COMPLETED_NON_CLEAN
    assert classification.failure_code == "EXPECTED_ARTIFACTS_MISMATCH"
    assert comparison.passed is True


@pytest.mark.parametrize(
    ("status", "expected_class"),
    [
        ("validation_failed", runner.PREFLIGHT_FAILED),
        ("budget_exceeded", runner.TASK_FAILED),
        ("timeout", runner.TASK_FAILED),
        ("model_error", runner.TASK_FAILED),
    ],
)
def test_non_completed_status_classification(tmp_path: Path, status: str, expected_class: str) -> None:
    case = _case(tmp_path)

    classification = runner.classify_response(case, {"status": status, "failureCode": "X"})

    assert classification.task_class == expected_class


def test_direct_reference_script_execution_fails_guard(tmp_path: Path) -> None:
    case = _case(tmp_path)
    direct = f"bash {case.project_path / 'build.sh'}"

    classification = runner.classify_response(case, _completed_response(command=direct, script="build.sh"))
    comparison = runner.compare_to_expected(classification, case.expected_oracle)

    assert classification.unsafe_command_guard_passed is False
    assert classification.generated_script_guard_passed is False
    assert classification.task_class == runner.COMPLETED_NON_CLEAN
    assert comparison.passed is False
    assert any("scriptHintPath" in item for item in comparison.mismatches)



def test_build_script_direct_reference_fails_guard_even_when_command_is_generated(tmp_path: Path) -> None:
    case = _case(tmp_path)

    classification = runner.classify_response(case, _completed_response(script="build.sh"))
    comparison = runner.compare_to_expected(classification, case.expected_oracle)

    assert classification.unsafe_command_guard_passed is False
    assert classification.generated_script_guard_passed is False
    assert classification.task_class == runner.COMPLETED_NON_CLEAN
    assert comparison.passed is False
    assert any("scriptHintPath" in item for item in comparison.mismatches)


def test_build_script_absolute_direct_reference_fails_guard(tmp_path: Path) -> None:
    case = _case(tmp_path)
    absolute_hint = str(case.project_path / "build.sh")

    classification = runner.classify_response(case, _completed_response(script=absolute_hint))

    assert classification.unsafe_command_guard_passed is False
    assert classification.generated_script_guard_passed is False
    assert classification.task_class == runner.COMPLETED_NON_CLEAN


def test_manifest_loader_rejects_unsafe_script_hint_path(tmp_path: Path) -> None:
    case = _case(tmp_path)
    raw = case.to_json()
    raw["build"]["scriptHintPath"] = "../build.sh"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": [raw]}))

    with pytest.raises(runner.CaseValidationError, match="scriptHintPath"):
        runner.load_manifest(manifest)



def test_cli_defaults_to_safe_dry_run_mode() -> None:
    args = runner.parse_args([])

    assert args.live is False
    assert args.dry_run is False



def test_main_without_live_uses_dry_run_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = _case(tmp_path, case_id="gamma")
    called: dict[str, bool] = {}

    monkeypatch.setattr(runner, "load_manifest", lambda manifest, selected_cases=None: [case])

    def fake_dry_run(cases, manifest, output_dir, run_label):
        called["dry_run"] = True
        assert cases == [case]
        return {
            "runLabel": run_label,
            "mode": "dry-run",
            "manifest": str(manifest),
            "outputDir": str(output_dir),
            "passed": True,
            "cases": [],
        }

    def fail_live(*args, **kwargs):  # pragma: no cover - should never run
        raise AssertionError("default CLI path must not call run_live")

    monkeypatch.setattr(runner, "run_dry_run", fake_dry_run)
    monkeypatch.setattr(runner, "run_live", fail_live)

    exit_code = runner.main([
        "--manifest",
        str(tmp_path / "manifest.json"),
        "--output-dir",
        str(tmp_path / "out"),
        "--run-label",
        "unit-default",
    ])

    assert exit_code == 0
    assert called == {"dry_run": True}

def test_dry_run_writes_requests_and_summary(tmp_path: Path) -> None:
    case_a = _case(tmp_path, case_id="alpha")
    case_b = _case(tmp_path, case_id="beta", target="nested", script_hint=".aegis/build.sh")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": [case_a.to_json(), case_b.to_json()]}))
    output_dir = tmp_path / "out"

    cases = runner.load_manifest(manifest)
    summary = runner.run_dry_run(cases, manifest, output_dir, "unit-run")

    assert summary["passed"] is True
    assert (output_dir / "alpha" / "build-req.json").is_file()
    assert (output_dir / "beta" / "build-req.json").is_file()
    assert (output_dir / "summary.json").is_file()
    assert (output_dir / "summary.md").is_file()
    beta_req = json.loads((output_dir / "beta" / "build-req.json").read_text())
    assert beta_req["context"]["trusted"]["buildTargetPath"] == "nested"
    assert beta_req["context"]["trusted"]["build"]["scriptHintPath"] == ".aegis/build.sh"
