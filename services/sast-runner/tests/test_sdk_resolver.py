"""sdk_resolver 단위 테스트 — resolve_sdk_paths, get_sdk_compiler, validate_sdk, register/unregister, _infer_arch."""

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from app.scanner import sdk_resolver
from app.scanner.sdk_resolver import (
    _get_registry,
    _infer_arch,
    _invalidate_cache,
    get_sdk_compiler,
    profile_sdk_id,
    register_sdk,
    resolve_sdk_paths,
    sdk_reference_exists,
    unregister_sdk,
    validate_sdk,
)
from app.schemas.request import BuildProfile


@pytest.fixture(autouse=True)
def clear_registry_cache():
    """매 테스트 전후로 SDK 레지스트리 캐시를 초기화."""
    _invalidate_cache()
    yield
    _invalidate_cache()


def _make_sdk_structure(base: Path, sdk_id: str, prefix: str, gcc_ver: str) -> Path:
    """tmp_path 아래에 SDK 디렉토리 구조를 생성하고 SDK 루트를 반환."""
    sdk_dir = base / sdk_id
    sysroot = sdk_dir / "sysroots" / f"{prefix}-linux-gnueabi"
    sysroot.mkdir(parents=True)

    # GCC 내장 헤더
    gcc_include = sysroot / "usr" / "lib" / "gcc" / prefix / gcc_ver / "include"
    gcc_include.mkdir(parents=True)
    gcc_include_fixed = sysroot / "usr" / "lib" / "gcc" / prefix / gcc_ver / "include-fixed"
    gcc_include_fixed.mkdir(parents=True)

    # C++ 표준 라이브러리
    cpp_include = sysroot / "usr" / prefix / "include" / "c++" / gcc_ver
    cpp_include.mkdir(parents=True)
    (cpp_include / prefix).mkdir()
    (cpp_include / "backward").mkdir()

    # ARM 타겟 헤더
    (sysroot / "usr" / prefix / "include").mkdir(parents=True, exist_ok=True)

    # libc 헤더
    libc_include = sysroot / "usr" / prefix / "libc" / "usr" / "include"
    libc_include.mkdir(parents=True)

    # 컴파일러 바이너리
    compiler_dir = sysroot / "usr" / "bin"
    compiler_dir.mkdir(parents=True, exist_ok=True)
    compiler = compiler_dir / f"{prefix}-gcc"
    compiler.write_text("#!/bin/sh\n")
    compiler.chmod(0o755)

    # environment-setup 스크립트
    env_setup = sdk_dir / f"environment-setup-{prefix}"
    env_setup.write_text("#!/bin/sh\nexport CC=...\n")

    return sdk_dir


def _write_registry(base: Path, registry: dict) -> None:
    """tmp_path에 sdk-registry.json 작성."""
    registry_path = base / "sdk-registry.json"
    registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")


def _assert_log_records_do_not_contain(caplog, *secrets: str) -> None:
    """Assert neither rendered text nor structured LogRecord fields contain secrets."""
    for secret in secrets:
        assert secret not in caplog.text
        for record in caplog.records:
            assert secret not in record.getMessage()
            assert secret not in repr(record.__dict__)


# ---------------------------------------------------------------------------
# _infer_arch
# ---------------------------------------------------------------------------

class TestInferArch:
    def test_arm_prefix(self):
        assert _infer_arch("arm-linux-gnueabihf") == "arm"

    def test_aarch64_prefix(self):
        assert _infer_arch("aarch64-linux-gnu") == "aarch64"

    def test_x86_64_prefix(self):
        assert _infer_arch("x86_64-linux-gnu") == "x86_64"

    def test_unknown_prefix_splits_first(self):
        """알 수 없는 prefix는 첫 번째 '-' 앞 부분을 반환."""
        assert _infer_arch("riscv64-unknown-elf") == "riscv64"

    def test_no_dash_returns_whole(self):
        assert _infer_arch("mips") == "mips"


# ---------------------------------------------------------------------------
# _invalidate_cache
# ---------------------------------------------------------------------------

class TestInvalidateCache:
    def test_cache_cleared(self, tmp_path):
        """_invalidate_cache 호출 후 레지스트리가 다시 로드되는지 확인."""
        registry = {"test-sdk": {"sysroot": "sysroots/test", "compiler_prefix": "arm-test", "gcc_version": "9.0"}}
        _write_registry(tmp_path, registry)

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            reg1 = _get_registry()
            assert "test-sdk" in reg1

            # 파일 변경 후 캐시 무효화 → 재로드
            registry["new-sdk"] = {"sysroot": "s", "compiler_prefix": "x", "gcc_version": "1"}
            _write_registry(tmp_path, registry)
            _invalidate_cache()

            reg2 = _get_registry()
            assert "new-sdk" in reg2


# ---------------------------------------------------------------------------
# _load_sdk_registry logging
# ---------------------------------------------------------------------------

class TestLoadSdkRegistryLogging:
    def test_missing_registry_log_uses_category_without_path(self, tmp_path, caplog):
        """레지스트리 부재 로그는 host-local SDK root 경로를 노출하지 않는다."""
        secret_root = tmp_path / "SECRET_SDK_ROOT_SHOULD_NOT_LEAK"
        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=secret_root):
            registry = sdk_resolver._load_sdk_registry()

        assert registry == {}
        assert "SDK registry not found" in caplog.text
        assert "SECRET_SDK_ROOT_SHOULD_NOT_LEAK" not in caplog.text
        assert "sdk-registry.json" not in caplog.text

    def test_malformed_registry_log_uses_category_without_parser_detail(
        self, tmp_path, caplog
    ):
        """레지스트리 파싱 실패 로그는 parser detail/path를 노출하지 않는다."""
        secret_root = tmp_path / "SECRET_SDK_ROOT_SHOULD_NOT_LEAK"
        secret_root.mkdir()
        (secret_root / "sdk-registry.json").write_text("{", encoding="utf-8")
        caplog.set_level(logging.ERROR, logger="aegis-sast-runner")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=secret_root):
            registry = sdk_resolver._load_sdk_registry()

        assert registry == {}
        assert "Failed to load SDK registry" in caplog.text
        assert "SECRET_SDK_ROOT_SHOULD_NOT_LEAK" not in caplog.text
        assert "sdk-registry.json" not in caplog.text
        assert "Expecting" not in caplog.text
        assert "line" not in caplog.text
        assert "column" not in caplog.text


# ---------------------------------------------------------------------------
# validate_sdk
# ---------------------------------------------------------------------------

class TestValidateSdk:
    def test_valid_sdk(self, tmp_path):
        """모든 구성 요소가 존재하면 에러 없음."""
        sdk_dir = _make_sdk_structure(tmp_path, "ti-am335x", "arm-linux-gnueabihf", "9.2.0")
        data = {
            "path": str(sdk_dir),
            "sysroot": "sysroots/arm-linux-gnueabihf-linux-gnueabi",
            "compilerPrefix": "arm-linux-gnueabihf",
            "environmentSetup": "environment-setup-arm-linux-gnueabihf",
        }
        errors = validate_sdk(data)
        assert errors == []

    def test_path_not_found(self, tmp_path):
        """SDK 경로가 존재하지 않으면 에러."""
        data = {"path": str(tmp_path / "SECRET_SDK_PATH_SHOULD_NOT_LEAK")}
        errors = validate_sdk(data)
        assert errors == ["SDK path not found"]
        assert "SECRET_SDK_PATH_SHOULD_NOT_LEAK" not in errors[0]

    def test_sysroot_not_found(self, tmp_path):
        """SDK 경로는 있지만 sysroot가 없으면 에러."""
        sdk_dir = tmp_path / "sdk"
        sdk_dir.mkdir()
        data = {
            "path": str(sdk_dir),
            "sysroot": "SECRET_SYSROOT_SHOULD_NOT_LEAK",
        }
        errors = validate_sdk(data)
        assert errors == ["Sysroot not found"]
        assert "SECRET_SYSROOT_SHOULD_NOT_LEAK" not in errors[0]

    def test_env_setup_not_found(self, tmp_path):
        """environment setup 스크립트가 없으면 에러."""
        sdk_dir = tmp_path / "sdk"
        sdk_dir.mkdir()
        data = {
            "path": str(sdk_dir),
            "environmentSetup": "SECRET_SETUP_SHOULD_NOT_LEAK.sh",
        }
        errors = validate_sdk(data)
        assert errors == ["Environment setup script not found"]
        assert "SECRET_SETUP_SHOULD_NOT_LEAK" not in errors[0]

    def test_compiler_not_found(self, tmp_path):
        """컴파일러 바이너리가 없으면 에러."""
        sdk_dir = tmp_path / "sdk"
        sysroot = sdk_dir / "SECRET_SYSROOT_SHOULD_NOT_LEAK" / "usr" / "bin"
        sysroot.mkdir(parents=True)
        data = {
            "path": str(sdk_dir),
            "sysroot": "SECRET_SYSROOT_SHOULD_NOT_LEAK",
            "compilerPrefix": "SECRET_PREFIX_SHOULD_NOT_LEAK",
        }
        errors = validate_sdk(data)
        assert errors == ["Compiler not found"]
        assert "SECRET_SYSROOT_SHOULD_NOT_LEAK" not in errors[0]
        assert "SECRET_PREFIX_SHOULD_NOT_LEAK" not in errors[0]

    def test_no_optional_fields_no_errors(self, tmp_path):
        """path만 유효하고 선택 필드가 없으면 에러 없음."""
        sdk_dir = tmp_path / "sdk"
        sdk_dir.mkdir()
        data = {"path": str(sdk_dir)}
        errors = validate_sdk(data)
        assert errors == []


# ---------------------------------------------------------------------------
# register_sdk / unregister_sdk
# ---------------------------------------------------------------------------

class TestRegisterUnregister:
    def test_register_sdk(self, tmp_path):
        """SDK 등록 후 레지스트리에 추가되는지 확인."""
        _write_registry(tmp_path, {})

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            register_sdk("new-sdk", {
                "path": str(tmp_path / "new-sdk"),
                "description": "Test SDK",
                "sysroot": "sysroots/arm",
                "compilerPrefix": "arm-linux-gnueabihf",
                "gccVersion": "9.2.0",
                "environmentSetup": "env-setup.sh",
            })

            reg = _get_registry()
            assert "new-sdk" in reg
            assert reg["new-sdk"]["compiler_prefix"] == "arm-linux-gnueabihf"
            assert reg["new-sdk"]["gcc_version"] == "9.2.0"

    def test_register_sdk_log_uses_category_without_sdk_identity_or_path(
        self, tmp_path, caplog
    ):
        """SDK 등록 로그는 sdkId/설치 경로 대신 category만 남긴다."""
        _write_registry(tmp_path, {})
        secret_sdk_id = "SECRET_SDK_ID_SHOULD_NOT_LEAK"
        secret_path = str(tmp_path / "SECRET_SDK_PATH_SHOULD_NOT_LEAK")
        caplog.set_level(logging.INFO, logger="aegis-sast-runner")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            register_sdk(secret_sdk_id, {
                "path": secret_path,
                "description": "Test SDK",
            })

        assert "SDK registered" in caplog.text
        _assert_log_records_do_not_contain(caplog, secret_sdk_id, secret_path)

    def test_register_overwrites_existing(self, tmp_path):
        """동일 SDK ID로 재등록하면 덮어쓰기."""
        initial = {"old-sdk": {"description": "old", "path": "/old", "sysroot": "", "compiler_prefix": "", "gcc_version": "", "environment_setup": ""}}
        _write_registry(tmp_path, initial)

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            register_sdk("old-sdk", {
                "path": str(tmp_path / "updated"),
                "description": "Updated SDK",
            })

            reg = _get_registry()
            assert reg["old-sdk"]["description"] == "Updated SDK"

    def test_unregister_existing(self, tmp_path):
        """등록된 SDK 삭제 → True."""
        initial = {"to-remove": {"description": "x", "path": "/x", "sysroot": "", "compiler_prefix": "", "gcc_version": "", "environment_setup": ""}}
        _write_registry(tmp_path, initial)

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            result = unregister_sdk("to-remove")

        assert result is True

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            reg = _get_registry()
            assert "to-remove" not in reg

    def test_unregister_sdk_log_uses_category_without_sdk_identity(
        self, tmp_path, caplog
    ):
        """SDK 삭제 로그는 sdkId 대신 category만 남긴다."""
        secret_sdk_id = "SECRET_SDK_ID_SHOULD_NOT_LEAK"
        initial = {
            secret_sdk_id: {
                "description": "x",
                "path": "/x",
                "sysroot": "",
                "compiler_prefix": "",
                "gcc_version": "",
                "environment_setup": "",
            }
        }
        _write_registry(tmp_path, initial)
        caplog.set_level(logging.INFO, logger="aegis-sast-runner")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            result = unregister_sdk(secret_sdk_id)

        assert result is True
        assert "SDK unregistered" in caplog.text
        _assert_log_records_do_not_contain(caplog, secret_sdk_id)

    def test_unregister_nonexistent(self, tmp_path):
        """존재하지 않는 SDK 삭제 → False."""
        _write_registry(tmp_path, {})

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            result = unregister_sdk("nonexistent")

        assert result is False


# ---------------------------------------------------------------------------
# resolve_sdk_paths
# ---------------------------------------------------------------------------

class TestResolveSdkPaths:
    def test_resolves_include_paths_from_registry(self, tmp_path):
        """레지스트리에 등록된 SDK의 인클루드 경로를 자동 해석."""
        prefix = "arm-linux-gnueabihf"
        gcc_ver = "9.2.0"
        _make_sdk_structure(tmp_path, "ti-am335x", prefix, gcc_ver)

        registry = {
            "ti-am335x": {
                "sysroot": f"sysroots/{prefix}-linux-gnueabi",
                "compiler_prefix": prefix,
                "gcc_version": gcc_ver,
            }
        }
        _write_registry(tmp_path, registry)

        profile = BuildProfile(sdkId="ti-am335x")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            paths = resolve_sdk_paths(profile)

        assert len(paths) > 0
        # 모든 반환 경로가 실제 존재하는 디렉토리
        for p in paths:
            assert Path(p).exists()

    def test_resolved_include_paths_log_uses_count_without_sdk_identity(
        self, tmp_path, caplog
    ):
        """SDK include path 성공 로그는 sdkId/root path를 노출하지 않는다."""
        secret_root = tmp_path / "SECRET_SDK_ROOT_SHOULD_NOT_LEAK"
        secret_sdk_id = "SECRET_SDK_ID_SHOULD_NOT_LEAK"
        prefix = "arm-linux-gnueabihf"
        gcc_ver = "9.2.0"
        _make_sdk_structure(secret_root, secret_sdk_id, prefix, gcc_ver)

        registry = {
            secret_sdk_id: {
                "sysroot": f"sysroots/{prefix}-linux-gnueabi",
                "compiler_prefix": prefix,
                "gcc_version": gcc_ver,
            }
        }
        _write_registry(secret_root, registry)
        profile = BuildProfile(sdkId=secret_sdk_id)
        caplog.set_level(logging.INFO, logger="aegis-sast-runner")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=secret_root):
            paths = resolve_sdk_paths(profile)

        assert paths
        assert "Resolved" in caplog.text
        assert "include paths from SDK" in caplog.text
        assert secret_sdk_id not in caplog.text
        assert "SECRET_SDK_ROOT_SHOULD_NOT_LEAK" not in caplog.text

    def test_sdk_not_in_registry(self, tmp_path):
        """레지스트리에 없는 SDK → 빈 결과 (디렉토리도 없을 때)."""
        _write_registry(tmp_path, {})

        profile = BuildProfile(sdkId="unknown-sdk")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            paths = resolve_sdk_paths(profile)

        assert paths == []

    def test_missing_sdk_directory_log_uses_category_without_path(self, tmp_path, caplog):
        """누락된 SDK directory 로그는 sdkId/root path를 노출하지 않는다."""
        secret_root = tmp_path / "SECRET_SDK_ROOT_SHOULD_NOT_LEAK"
        secret_root.mkdir()
        _write_registry(secret_root, {})
        secret_sdk_id = "SECRET_SDK_ID_SHOULD_NOT_LEAK"
        profile = BuildProfile(sdkId=secret_sdk_id)
        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=secret_root):
            paths = resolve_sdk_paths(profile)

        assert paths == []
        assert "SDK directory not found" in caplog.text
        assert secret_sdk_id not in caplog.text
        assert "SECRET_SDK_ROOT_SHOULD_NOT_LEAK" not in caplog.text

    def test_missing_sdk_id_skips_resolution_and_preserves_include_paths(self, tmp_path):
        """sdkId가 없으면 SDK 해석을 건너뛰고 profile includePaths만 유지."""
        _write_registry(tmp_path, {})

        profile = BuildProfile(
            compiler="gcc",
            includePaths=["/usr/include", "/opt/project/include"],
        )

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            paths = resolve_sdk_paths(profile)

        assert paths == ["/usr/include", "/opt/project/include"]


class TestSdkReferenceExists:
    def test_missing_sdk_id_is_valid(self, tmp_path):
        _write_registry(tmp_path, {})
        profile = BuildProfile(compiler="gcc")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            assert sdk_reference_exists(profile) is True

    def test_registry_entry_counts_as_existing(self, tmp_path):
        _write_registry(tmp_path, {"ti-am335x": {"sysroot": "sysroots/arm"}})
        profile = BuildProfile(sdkId="ti-am335x")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            assert sdk_reference_exists(profile) is True

    def test_missing_directory_and_registry_is_invalid(self, tmp_path):
        _write_registry(tmp_path, {})
        profile = BuildProfile(sdkId="nonexistent")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            assert sdk_reference_exists(profile) is False

    def test_custom_sdk_id_is_not_treated_as_existing(self, tmp_path):
        _write_registry(tmp_path, {})
        profile = BuildProfile(sdkId="custom")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            assert sdk_reference_exists(profile) is False


class TestProfileSdkId:
    def test_none_profile(self):
        assert profile_sdk_id(None) is None

    def test_blank_sdk_id_normalizes_to_none(self):
        assert profile_sdk_id(BuildProfile(sdkId="   ", compiler="gcc")) is None

    def test_include_paths_from_profile(self, tmp_path):
        """BuildProfile.includePaths가 결과에 추가되는지."""
        _write_registry(tmp_path, {})

        profile = BuildProfile(
            sdkId="no-such-sdk",
            includePaths=["/usr/local/include", "/opt/custom/include"],
        )

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            paths = resolve_sdk_paths(profile)

        assert "/usr/local/include" in paths
        assert "/opt/custom/include" in paths

    def test_sdk_dir_exists_but_not_in_registry(self, tmp_path):
        """SDK 폴더가 있지만 레지스트리에 없으면 자동 해석 안 함."""
        sdk_dir = tmp_path / "orphan-sdk"
        sdk_dir.mkdir()
        _write_registry(tmp_path, {})

        profile = BuildProfile(sdkId="orphan-sdk")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            paths = resolve_sdk_paths(profile)

        assert paths == []

    def test_missing_sysroot_log_uses_category_without_path(self, tmp_path, caplog):
        """누락된 SDK sysroot 로그는 base/sysroot path를 노출하지 않는다."""
        secret_base = tmp_path / "SECRET_SDK_BASE_SHOULD_NOT_LEAK"
        sdk_info = {
            "sysroot": "SECRET_SYSROOT_SHOULD_NOT_LEAK",
            "compiler_prefix": "arm-none-eabi",
            "gcc_version": "12.0",
        }
        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        paths = sdk_resolver._resolve_from_registry(secret_base, sdk_info)

        assert paths == []
        assert "SDK sysroot not found" in caplog.text
        assert "SECRET_SDK_BASE_SHOULD_NOT_LEAK" not in caplog.text
        assert "SECRET_SYSROOT_SHOULD_NOT_LEAK" not in caplog.text


# ---------------------------------------------------------------------------
# get_sdk_compiler
# ---------------------------------------------------------------------------

class TestGetSdkCompiler:
    def test_compiler_found(self, tmp_path):
        """레지스트리에 등록된 SDK의 컴파일러 경로 반환."""
        prefix = "arm-linux-gnueabihf"
        gcc_ver = "9.2.0"
        _make_sdk_structure(tmp_path, "ti-am335x", prefix, gcc_ver)

        registry = {
            "ti-am335x": {
                "sysroot": f"sysroots/{prefix}-linux-gnueabi",
                "compiler_prefix": prefix,
                "gcc_version": gcc_ver,
            }
        }
        _write_registry(tmp_path, registry)

        profile = BuildProfile(sdkId="ti-am335x")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            compiler = get_sdk_compiler(profile)

        assert compiler is not None
        assert compiler.endswith(f"{prefix}-gcc")
        assert Path(compiler).exists()

    def test_compiler_not_in_registry(self, tmp_path):
        """레지스트리에 없는 SDK → None."""
        _write_registry(tmp_path, {})

        profile = BuildProfile(sdkId="nonexistent")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            compiler = get_sdk_compiler(profile)

        assert compiler is None

    def test_missing_sdk_id_returns_none(self, tmp_path):
        """sdkId가 없으면 SDK 컴파일러 해석을 시도하지 않는다."""
        _write_registry(tmp_path, {})

        profile = BuildProfile(compiler="gcc")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            compiler = get_sdk_compiler(profile)

        assert compiler is None

    def test_compiler_binary_missing(self, tmp_path):
        """레지스트리에는 있지만 컴파일러 바이너리가 없으면 None."""
        sdk_dir = tmp_path / "broken-sdk"
        sysroot = sdk_dir / "sysroots" / "arm" / "usr" / "bin"
        sysroot.mkdir(parents=True)
        # gcc binary NOT created

        registry = {
            "broken-sdk": {
                "sysroot": "sysroots/arm",
                "compiler_prefix": "arm-none-eabi",
                "gcc_version": "12.0",
            }
        }
        _write_registry(tmp_path, registry)

        profile = BuildProfile(sdkId="broken-sdk")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            compiler = get_sdk_compiler(profile)

        assert compiler is None

    def test_malformed_registry_entry(self, tmp_path):
        """레지스트리 항목에 sysroot/compiler_prefix 누락 시 KeyError 없이 None."""
        _write_registry(tmp_path, {"broken": {"description": "malformed entry"}})

        profile = BuildProfile(sdkId="broken")

        with patch.object(sdk_resolver, "_get_sdk_root", return_value=tmp_path):
            compiler = get_sdk_compiler(profile)

        assert compiler is None
