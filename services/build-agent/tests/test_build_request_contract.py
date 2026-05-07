import pytest

from app.routers import tasks
from app.schemas.request import BuildMode, BuildResolveContract, ContractVersion
from app.schemas.response import AssessmentResult, AuditInfo, TaskSuccessResponse, TokenUsage, ValidationInfo
from app.validators.build_request_contract import BuildRequestContractValidator, normalize_contract_version
from app.schemas.request import Context, TaskRequest
from app.types import TaskStatus
from app.types import TaskType


def _request(trusted: dict) -> TaskRequest:
    return TaskRequest(
        taskType=TaskType.BUILD_RESOLVE,
        taskId="build-contract-test",
        context=Context(trusted=trusted),
    )


def _completed_response(task_type: TaskType = TaskType.BUILD_RESOLVE) -> TaskSuccessResponse:
    return TaskSuccessResponse(
        taskId="build-contract-http-001",
        taskType=task_type,
        status=TaskStatus.COMPLETED,
        modelProfile="test",
        promptVersion="build-agent-v1",
        schemaVersion="build-v1.1",
        validation=ValidationInfo(valid=True, errors=[]),
        result=AssessmentResult(
            summary="build completed",
            claims=[],
            caveats=[],
            usedEvidenceRefs=[],
            buildResult={"success": True, "buildCommand": "make", "buildScript": "build.sh"},
        ),
        audit=AuditInfo(
            inputHash="sha256:test",
            latencyMs=0,
            tokenUsage=TokenUsage(prompt=0, completion=0),
            retryCount=0,
            ragHits=0,
            createdAt="2026-04-29T00:00:00Z",
        ),
    )


def test_canonical_strict_contract_fields_parse() -> None:
    contract = BuildResolveContract.model_validate(
        {
            "projectPath": "/tmp/project",
            "buildTargetPath": "gateway",
            "buildTargetName": "gateway",
            "contractVersion": "build-resolve-v1",
            "strictMode": True,
            "build": {"mode": "native", "scriptHintPath": "scripts/build.sh"},
            "expectedArtifacts": [{"kind": "executable", "path": "build-aegis/gateway"}],
        }
    )

    assert contract.buildTargetPath == "gateway"
    assert contract.buildTargetName == "gateway"
    assert contract.targetPath == "gateway"
    assert contract.targetName == "gateway"
    assert contract.buildMode == BuildMode.NATIVE
    assert contract.contractVersion == ContractVersion.BUILD_RESOLVE_V1
    assert normalize_contract_version(contract) == "build-resolve-v1"
    assert contract.expectedArtifacts[0].artifactType.value == "executable"
    assert contract.scriptHintPath == "scripts/build.sh"


@pytest.mark.parametrize(
    "build_blob",
    [
        {"mode": "native", "scriptHintText": "make -j4\n"},
        {"mode": "native", "scriptHint": "make -j4\n"},
    ],
)
def test_inline_build_script_hint_aliases_are_removed(build_blob) -> None:
    with pytest.raises(ValueError, match="inline build script hints"):
        BuildResolveContract.model_validate(
            {
                "projectPath": "/tmp/project",
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": build_blob,
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )


@pytest.mark.parametrize("field_name", ["buildScriptHint", "buildScriptHintText"])
def test_top_level_inline_build_script_hint_aliases_are_removed(field_name) -> None:
    with pytest.raises(ValueError, match="inline build script hints"):
        BuildResolveContract.model_validate(
            {
                "projectPath": "/tmp/project",
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {"mode": "native"},
                field_name: "make -j4\n",
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )


def test_top_level_script_hint_path_alias_is_rejected() -> None:
    with pytest.raises(ValueError, match="context.trusted.build.scriptHintPath"):
        BuildResolveContract.model_validate(
            {
                "projectPath": "/tmp/project",
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {"mode": "native"},
                "scriptHintPath": "scripts/build.sh",
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )



def test_legacy_aliases_normalize_to_canonical_contract() -> None:
    contract = BuildResolveContract.model_validate(
        {
            "projectPath": "/tmp/project",
            "targetPath": "gateway",
            "targetName": "gateway",
            "contractVersion": "compile-first-v1",
            "strictMode": True,
            "buildMode": "sdk",
            "sdkId": "sdk-1",
            "buildEnvironment": {"CC": "arm-linux-gnueabihf-gcc"},
            "expectedArtifacts": [{"artifactType": "executable", "path": "gateway"}],
        }
    )

    assert contract.buildTargetPath == "gateway"
    assert contract.buildTargetName == "gateway"
    assert contract.buildMode == BuildMode.SDK
    assert contract.sdkId == "sdk-1"
    assert contract.buildEnvironment == {"CC": "arm-linux-gnueabihf-gcc"}
    assert contract.contractVersion == ContractVersion.BUILD_RESOLVE_V1
    assert normalize_contract_version(contract) == "build-resolve-v1"


def test_task_request_accepts_top_level_strict_contract_fields() -> None:
    request = TaskRequest.model_validate(
        {
            "taskType": "build-resolve",
            "taskId": "build-contract-top-level-001",
            "contractVersion": "build-resolve-v1",
            "strictMode": True,
            "context": {
                "trusted": {
                    "projectPath": "/tmp/project",
                    "buildTargetPath": "gateway",
                    "buildTargetName": "gateway",
                    "build": {"mode": "native"},
                    "expectedArtifacts": [{"kind": "executable", "path": "gateway"}],
                },
            },
        }
    )

    contract = request.build_resolve_contract()
    assert contract.contractVersion == ContractVersion.BUILD_RESOLVE_V1
    assert contract.strictMode is True
    assert contract.buildTargetPath == "gateway"
    assert contract.buildTargetName == "gateway"



def test_preflight_requires_canonical_build_target_fields_in_strict_mode() -> None:
    validator = BuildRequestContractValidator()
    preflight, errors = validator.validate(
        _request(
            {
                "projectPath": "/tmp/project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {"mode": "native"},
                "expectedArtifacts": [{"kind": "executable", "path": "gateway"}],
            }
        )
    )

    assert preflight is None
    assert any("buildTargetPath" in error for error in errors)
    assert any("buildTargetName" in error for error in errors)


def test_strict_sdk_requires_materialization_source() -> None:
    validator = BuildRequestContractValidator()
    preflight, errors = validator.validate(
        _request(
            {
                "projectPath": "/tmp/project",
                "buildTargetPath": "gateway",
                "buildTargetName": "gateway",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {"mode": "sdk", "sdkId": "sdk-1"},
                "expectedArtifacts": [{"kind": "executable", "path": "gateway"}],
            }
        )
    )

    assert preflight is None
    assert any("materialization source" in error for error in errors)


def test_strict_sdk_accepts_uploaded_project_script_hint_path(tmp_path) -> None:
    project = tmp_path / "project"
    target = project / "target"
    scripts = target / "scripts"
    scripts.mkdir(parents=True)
    hint = scripts / "build.sh"
    hint.write_text("#!/bin/bash\necho build\n")
    sdk_root = tmp_path / "sdk"
    env_script = sdk_root / "environment-setup"
    sdk_root.mkdir()
    env_script.write_text("export CC=arm-gcc\n")

    validator = BuildRequestContractValidator()
    preflight, errors = validator.validate(
        _request(
            {
                "projectPath": str(project),
                "buildTargetPath": "target",
                "buildTargetName": "target",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {
                    "mode": "sdk",
                    "sdkId": "sdk-1",
                    "sdkRootPath": str(sdk_root),
                    "setupScript": "environment-setup",
                    "scriptHintPath": "scripts/build.sh",
                },
                "expectedArtifacts": [{"kind": "executable", "path": "target"}],
            }
        )
    )

    assert errors == []
    assert preflight is not None
    assert preflight.script_hint is not None
    assert preflight.script_hint.path == "scripts/build.sh"
    assert preflight.script_hint.content == "#!/bin/bash\necho build\n"
    assert preflight.script_hint.size_bytes == len("#!/bin/bash\necho build\n".encode())
    assert len(preflight.script_hint.sha256) == 64


def test_strict_sdk_descriptor_resolves_paths_and_derived_env_wins(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    sdk_root = tmp_path / "uploaded-sdk"
    env_script = sdk_root / "linux-devkit" / "environment-setup-arm"
    sysroot = sdk_root / "linux-devkit" / "sysroots" / "arm"
    env_script.parent.mkdir(parents=True)
    sysroot.mkdir(parents=True)
    env_script.write_text("export CC=arm-gcc\n")

    validator = BuildRequestContractValidator()
    preflight, errors = validator.validate(
        _request(
            {
                "projectPath": str(project),
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {
                    "mode": "sdk",
                    "sdkId": "sdk-1",
                    "sdkRootPath": str(sdk_root),
                    "setupScript": "linux-devkit/environment-setup-arm",
                    "sysroot": "linux-devkit/sysroots/arm",
                    "toolchainTriplet": "arm-none-linux-gnueabihf",
                    "environment": {
                        "CUSTOM_FLAG": "1",
                        "AEGIS_SDK_ROOT": "/attacker/override",
                        "SDK_DIR": "/attacker/override",
                    },
                },
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )
    )

    assert errors == []
    assert preflight is not None
    materialization = preflight.sdk_materialization
    assert materialization is not None
    assert materialization.sdk_root_path == str(sdk_root.resolve())
    assert materialization.setup_script == str(env_script.resolve())
    assert materialization.sysroot == str(sysroot.resolve())
    assert materialization.toolchain_triplet == "arm-none-linux-gnueabihf"
    assert materialization.effective_environment["CUSTOM_FLAG"] == "1"
    assert materialization.effective_environment["AEGIS_SDK_ROOT"] == str(sdk_root.resolve())
    assert materialization.effective_environment["SDK_DIR"] == str(sdk_root.resolve())
    assert materialization.effective_environment["AEGIS_SDK_SETUP_SCRIPT"] == str(env_script.resolve())
    assert materialization.effective_environment["AEGIS_SDK_SYSROOT"] == str(sysroot.resolve())
    assert materialization.effective_environment["SDKTARGETSYSROOT"] == str(sysroot.resolve())
    assert materialization.effective_environment["AEGIS_TOOLCHAIN_TRIPLET"] == "arm-none-linux-gnueabihf"


def test_strict_sdk_rejects_setup_script_escape_from_sdk_root(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    sdk_root = tmp_path / "uploaded-sdk"
    sdk_root.mkdir()
    outside = tmp_path / "outside-env"
    outside.write_text("export CC=evil\n")

    validator = BuildRequestContractValidator()
    preflight, errors = validator.validate(
        _request(
            {
                "projectPath": str(project),
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {
                    "mode": "sdk",
                    "sdkId": "sdk-1",
                    "sdkRootPath": str(sdk_root),
                    "setupScript": str(outside),
                },
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )
    )

    assert preflight is None
    assert any("setupScript" in error and "sdkRootPath" in error for error in errors)


def test_strict_sdk_accepts_legacy_absolute_setup_without_sdk_root(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    validator = BuildRequestContractValidator()
    preflight, errors = validator.validate(
        _request(
            {
                "projectPath": str(project),
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {
                    "mode": "sdk",
                    "sdkId": "legacy-sdk",
                    "setupScript": "/legacy/uploaded-sdk/environment-setup",
                },
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )
    )

    assert errors == []
    assert preflight is not None
    assert preflight.sdk_materialization is not None
    assert preflight.sdk_materialization.legacy_transitional is True
    assert preflight.sdk_materialization.setup_script == "/legacy/uploaded-sdk/environment-setup"


def test_strict_sdk_rejects_relative_setup_without_sdk_root(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    validator = BuildRequestContractValidator()
    preflight, errors = validator.validate(
        _request(
            {
                "projectPath": str(project),
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {
                    "mode": "sdk",
                    "sdkId": "legacy-sdk",
                    "setupScript": "relative/environment-setup",
                },
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )
    )

    assert preflight is None
    assert any("sdkRootPath" in error or "relative path" in error for error in errors)


def test_strict_sdk_rejects_environment_only_without_sdk_root(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    validator = BuildRequestContractValidator()
    preflight, errors = validator.validate(
        _request(
            {
                "projectPath": str(project),
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {
                    "mode": "sdk",
                    "sdkId": "legacy-sdk",
                    "environment": {"CC": "arm-gcc"},
                },
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )
    )

    assert preflight is None
    assert any("sdkRootPath" in error for error in errors)


@pytest.mark.parametrize("field_name", ["sdkRootPath", "sysroot"])
def test_top_level_sdk_descriptor_path_fields_are_rejected(field_name) -> None:
    with pytest.raises(ValueError, match=f"context.trusted.{field_name} is not supported"):
        BuildResolveContract.model_validate(
            {
                "projectPath": "/tmp/project",
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {
                    "mode": "sdk",
                    "sdkId": "sdk-1",
                    "setupScript": "/legacy/environment-setup",
                },
                field_name: "/tmp/sdk",
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )


def test_canonical_build_field_conflict_with_legacy_alias_is_rejected() -> None:
    with pytest.raises(ValueError, match="conflicting canonical and legacy build fields"):
        BuildResolveContract.model_validate(
            {
                "projectPath": "/tmp/project",
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "buildMode": "sdk",
                "sdkId": "sdk-1",
                "setupScript": "/legacy/environment-setup",
                "build": {
                    "mode": "sdk",
                    "sdkId": "sdk-1",
                    "setupScript": "linux-devkit/environment-setup",
                },
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("", "must not be empty"),
        ("/abs/build.sh", "relative uploaded-project path"),
        ("C:/build.sh", "relative uploaded-project path"),
        ("\\\\server\\share\\build.sh", "POSIX"),
        ("../build.sh", "path traversal"),
        ("scripts/../build.sh", "not contain path traversal"),
    ],
)
def test_script_hint_path_rejects_unsafe_paths(tmp_path, path, expected) -> None:
    project = tmp_path / "project"
    project.mkdir()

    validator = BuildRequestContractValidator()
    preflight, errors = validator.validate(
        _request(
            {
                "projectPath": str(project),
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {"mode": "native", "scriptHintPath": path},
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )
    )

    assert preflight is None
    assert any(expected in error for error in errors)


def test_script_hint_path_is_relative_to_effective_build_target_root(tmp_path) -> None:
    project = tmp_path / "project"
    (project / "scripts").mkdir(parents=True)
    (project / "scripts" / "build.sh").write_text("#!/bin/bash\necho root\n")
    (project / "target").mkdir()

    validator = BuildRequestContractValidator()
    preflight, errors = validator.validate(
        _request(
            {
                "projectPath": str(project),
                "buildTargetPath": "target",
                "buildTargetName": "target",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {"mode": "native", "scriptHintPath": "scripts/build.sh"},
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )
    )

    assert preflight is None
    assert any("regular file" in error for error in errors)


def test_script_hint_path_rejects_symlink_escape(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.sh"
    outside.write_text("#!/bin/bash\necho outside\n")
    (project / "hint.sh").symlink_to(outside)

    validator = BuildRequestContractValidator()
    preflight, errors = validator.validate(
        _request(
            {
                "projectPath": str(project),
                "buildTargetPath": ".",
                "buildTargetName": "project",
                "contractVersion": "build-resolve-v1",
                "strictMode": True,
                "build": {"mode": "native", "scriptHintPath": "hint.sh"},
                "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
            }
        )
    )

    assert preflight is None
    assert any("inside the build target scope" in error for error in errors)


def test_script_hint_path_rejects_binary_and_oversized_files(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "binary.sh").write_bytes(b"abc\x00def")
    (project / "large.sh").write_text("x" * 20_001)
    validator = BuildRequestContractValidator()

    for path, expected in [
        ("binary.sh", "text file without NUL"),
        ("large.sh", "20000 byte limit"),
    ]:
        preflight, errors = validator.validate(
            _request(
                {
                    "projectPath": str(project),
                    "buildTargetPath": ".",
                    "buildTargetName": "project",
                    "contractVersion": "build-resolve-v1",
                    "strictMode": True,
                    "build": {"mode": "native", "scriptHintPath": path},
                    "expectedArtifacts": [{"kind": "file-set", "path": "out"}],
                }
            )
        )
        assert preflight is None
        assert any(expected in error for error in errors)


def test_build_route_accepts_camel_case_generation_constraints(client, monkeypatch) -> None:
    captured = {}

    async def fake_build(request):
        captured["constraints"] = request.constraints
        return _completed_response()

    monkeypatch.setattr(tasks, "_handle_build_resolve", fake_build)

    response = client.post(
        "/v1/tasks",
        json={
            "taskType": "build-resolve",
            "taskId": "build-contract-http-constraints-001",
            "context": {
                "trusted": {
                    "projectPath": "/tmp/project",
                    "buildTargetPath": "gateway",
                    "buildTargetName": "gateway",
                },
            },
            "constraints": {
                "maxTokens": 32768,
                "enableThinking": False,
                "temperature": 0.7,
                "topP": 0.85,
                "topK": -1,
                "minP": 0.15,
                "presencePenalty": 0.3,
                "repetitionPenalty": 1.05,
            },
        },
    )

    assert response.status_code == 200
    constraints = captured["constraints"]
    assert constraints.maxTokens == 32768
    assert constraints.enableThinking is False
    assert constraints.temperature == 0.7
    assert constraints.topP == 0.85
    assert constraints.topK == -1
    assert constraints.minP == 0.15
    assert constraints.presencePenalty == 0.3
    assert constraints.repetitionPenalty == 1.05


def test_build_route_rejects_snake_case_generation_constraints(client) -> None:
    response = client.post(
        "/v1/tasks",
        json={
            "taskType": "build-resolve",
            "taskId": "build-contract-http-constraints-bad-001",
            "context": {
                "trusted": {
                    "projectPath": "/tmp/project",
                    "buildTargetPath": "gateway",
                    "buildTargetName": "gateway",
                },
            },
            "constraints": {"top_p": 0.8},
        },
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any("top_p" in str(item.get("loc", ())) for item in detail)


def test_build_route_rejects_max_tokens_above_32768(client) -> None:
    response = client.post(
        "/v1/tasks",
        json={
            "taskType": "build-resolve",
            "taskId": "build-contract-http-max-001",
            "context": {
                "trusted": {
                    "projectPath": "/tmp/project",
                    "buildTargetPath": "gateway",
                    "buildTargetName": "gateway",
                },
            },
            "constraints": {"maxTokens": 32769},
        },
    )

    assert response.status_code == 422
