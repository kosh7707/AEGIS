"""SDK 설치 경로 자동 해석 — BuildProfile.sdkId로 헤더/컴파일러 경로를 찾는다.

SDK 폴더 규칙:
  SAST_SDK_ROOT=/opt/sdks         (.env 예시값 — 환경별로 교체)
    ├── sdk-registry.json          ← SDK 메타데이터 (코드 밖에서 관리)
    ├── ti-am335x/                 ← sdkId가 곧 폴더명
    └── nxp-s32k/                  ← 나중에 추가 시 json만 편집

  sdkId가 레지스트리에 있으면 → sysroot/compiler 자동 해석
  sdkId가 레지스트리에 없어도 폴더가 있으면 → includePaths로 활용 가능
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from app.schemas.request import BuildProfile

logger = logging.getLogger("aegis-sast-runner")


def _profile_sdk_id(profile: BuildProfile) -> str | None:
    """BuildProfile의 sdkId를 정규화한다."""
    sdk_id = profile.sdk_id
    if sdk_id is None:
        return None
    sdk_id = sdk_id.strip()
    return sdk_id or None


def _descriptor_dict(profile: BuildProfile | None) -> dict[str, Any]:
    if profile is None or profile.sdk_descriptor is None:
        return {}
    return profile.sdk_descriptor.model_dump(by_alias=True, exclude_none=True)


def _descriptor_base(profile: BuildProfile | None) -> Path | None:
    descriptor = _descriptor_dict(profile)
    root = descriptor.get("sdkRootPath")
    return Path(root) if root else None


def _descriptor_path(base: Path, raw: str | None) -> Path | None:
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = base / candidate
    return candidate


def _looks_like_readable_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _get_sdk_root() -> Path:
    """SDK 루트 디렉토리. .env의 SAST_SDK_ROOT → 폴백 ~/sdks."""
    from app.config import settings
    if settings.sdk_root:
        return Path(settings.sdk_root)
    return Path.home() / "sdks"


def _load_sdk_registry() -> dict[str, dict[str, Any]]:
    """$SAST_SDK_ROOT/sdk-registry.json에서 SDK 레지스트리를 로드.

    파일이 없으면 빈 dict 반환. 코드 수정 없이 SDK 추가/변경 가능.
    """
    registry_path = _get_sdk_root() / "sdk-registry.json"
    if not registry_path.exists():
        logger.warning("SDK registry not found")
        return {}
    try:
        return json.loads(registry_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.error("Failed to load SDK registry")
        return {}


# 레지스트리 캐시 (서버 수명 동안 1회 로드, thread-safe)
_SDK_REGISTRY: dict[str, dict[str, Any]] | None = None
_SDK_REGISTRY_LOCK = threading.Lock()


def _get_registry() -> dict[str, dict[str, Any]]:
    """SDK 레지스트리 캐시 반환. 최초 호출 시 파일에서 로드 (thread-safe)."""
    global _SDK_REGISTRY
    if _SDK_REGISTRY is not None:
        return _SDK_REGISTRY
    with _SDK_REGISTRY_LOCK:
        if _SDK_REGISTRY is None:
            _SDK_REGISTRY = _load_sdk_registry()
        return _SDK_REGISTRY


def _get_sdk_base(sdk_id: str) -> Path:
    """sdkId에 해당하는 SDK 설치 경로. 레지스트리에 path가 있으면 우선 사용."""
    sdk_info = _get_registry().get(sdk_id)
    if sdk_info and "path" in sdk_info:
        return Path(sdk_info["path"])
    return _get_sdk_root() / sdk_id


def profile_sdk_id(profile: BuildProfile | None) -> str | None:
    """외부 호출자가 사용할 수 있는 정규화된 sdkId."""
    if profile is None:
        return None
    return _profile_sdk_id(profile)


def sdk_reference_exists(profile: BuildProfile | None) -> bool:
    """profile에 sdkId가 주어진 경우 해당 SDK reference가 존재하는지 확인."""
    sdk_id = profile_sdk_id(profile)
    if sdk_id is None:
        return True
    if profile and profile.sdk_resolution_mode in {"none", "non-registered"}:
        return True
    if _get_registry().get(sdk_id):
        return True
    return _get_sdk_base(sdk_id).is_dir()


def _save_registry(registry: dict[str, dict[str, Any]]) -> None:
    """SDK 레지스트리를 파일에 저장."""
    registry_path = _get_sdk_root() / "sdk-registry.json"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps(registry, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _invalidate_cache() -> None:
    """레지스트리 캐시를 무효화 (thread-safe)."""
    global _SDK_REGISTRY
    with _SDK_REGISTRY_LOCK:
        _SDK_REGISTRY = None


def validate_sdk(data: dict[str, Any]) -> list[str]:
    """SDK 등록 데이터를 검증. 실패한 항목의 에러 메시지 리스트를 반환."""
    errors: list[str] = []

    sdk_path = Path(data.get("path", ""))
    if not sdk_path.is_dir():
        errors.append("SDK path not found")
        return errors  # 경로가 없으면 나머지 검증 불가

    sysroot = data.get("sysroot")
    if sysroot:
        sysroot_path = sdk_path / sysroot
        if not sysroot_path.is_dir():
            errors.append("Sysroot not found")

    env_setup = data.get("environmentSetup") or data.get("environment_setup")
    if env_setup:
        setup_path = sdk_path / env_setup
        if not setup_path.is_file():
            errors.append("Environment setup script not found")

    prefix = data.get("compilerPrefix") or data.get("compiler_prefix")
    if prefix and sysroot:
        sysroot_path = sdk_path / sysroot
        compiler = sysroot_path / "usr" / "bin" / f"{prefix}-gcc"
        if not compiler.exists():
            errors.append("Compiler not found")

    return errors


def register_sdk(sdk_id: str, data: dict[str, Any]) -> None:
    """SDK를 레지스트리에 등록."""
    registry = _get_registry().copy()
    registry[sdk_id] = {
        "description": data.get("description", ""),
        "path": data["path"],
        "sysroot": data.get("sysroot", ""),
        "compiler_prefix": data.get("compilerPrefix") or data.get("compiler_prefix", ""),
        "gcc_version": data.get("gccVersion") or data.get("gcc_version", ""),
        "environment_setup": data.get("environmentSetup") or data.get("environment_setup", ""),
    }
    _save_registry(registry)
    _invalidate_cache()
    logger.info("SDK registered")


def unregister_sdk(sdk_id: str) -> bool:
    """SDK를 레지스트리에서 삭제. 존재했으면 True."""
    registry = _get_registry().copy()
    if sdk_id not in registry:
        return False
    del registry[sdk_id]
    _save_registry(registry)
    _invalidate_cache()
    logger.info("SDK unregistered")
    return True


def resolve_sdk_paths(profile: BuildProfile) -> list[str]:
    """BuildProfile의 sdkId에서 헤더 인클루드 경로를 해석한다.

    반환하는 경로들은 도구의 -I 옵션에 직접 사용할 수 있다.
    profile.includePaths가 있으면 그것도 포함한다.
    """
    paths: list[str] = []
    sdk_id = _profile_sdk_id(profile)
    descriptor = _descriptor_dict(profile)

    if profile.sdk_resolution_mode == "none":
        if profile.include_paths:
            paths.extend(profile.include_paths)
        return paths

    if profile.sdk_resolution_mode == "non-registered":
        base = _descriptor_base(profile)
        if descriptor.get("includePaths"):
            paths.extend(descriptor["includePaths"])
        if base:
            paths.extend(_resolve_from_descriptor(base, descriptor))
        if profile.include_paths:
            paths.extend(profile.include_paths)
        return paths

    # 1. SDK 레지스트리에서 자동 해석
    if sdk_id is not None:
        sdk_info = _get_registry().get(sdk_id)
        base = _get_sdk_base(sdk_id)

        if sdk_info and base.is_dir():
            sdk_paths = _resolve_from_registry(base, sdk_info)
            paths.extend(sdk_paths)
            logger.info(
                "Resolved %d include paths from SDK",
                len(sdk_paths),
            )
        elif not base.is_dir():
            logger.warning("SDK directory not found")

    # 2. BuildProfile에 명시된 includePaths 추가
    if profile.include_paths:
        paths.extend(profile.include_paths)

    return paths


def get_sdk_compiler(profile: BuildProfile) -> str | None:
    """SDK의 크로스 컴파일러 경로를 반환."""
    if profile.sdk_resolution_mode == "none":
        return None

    if profile.sdk_resolution_mode == "non-registered":
        descriptor = _descriptor_dict(profile)
        compiler_path = descriptor.get("compilerPath")
        if compiler_path and Path(compiler_path).exists():
            return compiler_path
        base = _descriptor_base(profile)
        if base:
            inferred = _descriptor_compiler_path(base, descriptor)
            if inferred and inferred.exists():
                return str(inferred)
        return None

    sdk_id = _profile_sdk_id(profile)
    if sdk_id is None:
        return None

    sdk_info = _get_registry().get(sdk_id)
    if not sdk_info:
        return None

    base = _get_sdk_base(sdk_id)
    sysroot = sdk_info.get("sysroot", "")
    prefix = sdk_info.get("compiler_prefix", "")
    if not sysroot or not prefix:
        return None

    compiler_path = base / sysroot / "usr" / "bin" / f"{prefix}-gcc"
    if compiler_path.exists():
        return str(compiler_path)
    return None


def get_sdk_environment_setup(profile: BuildProfile) -> str | None:
    """SDK의 environment-setup 스크립트 경로를 반환."""
    if profile.sdk_resolution_mode == "none":
        return None

    if profile.sdk_resolution_mode == "non-registered":
        descriptor = _descriptor_dict(profile)
        base = _descriptor_base(profile)
        if not base:
            return None
        setup_path = _descriptor_path(base, descriptor.get("setupScript"))
        if setup_path and setup_path.exists():
            return str(setup_path)
        return None

    sdk_id = _profile_sdk_id(profile)
    if sdk_id is None:
        return None

    sdk_info = _get_registry().get(sdk_id)
    if not sdk_info or "environment_setup" not in sdk_info:
        return None

    base = _get_sdk_base(sdk_id)
    setup_path = base / sdk_info["environment_setup"]
    if setup_path.exists():
        return str(setup_path)
    return None


def get_sdk_registry() -> list[dict[str, Any]]:
    """등록된 SDK 목록을 반환. 빌드 Agent가 SDK 매칭에 사용."""
    result = []
    sdk_root = _get_sdk_root()

    for sdk_id, info in _get_registry().items():
        base = sdk_root / sdk_id
        compiler_path = get_sdk_compiler_path(base, info)
        prefix = info.get("compiler_prefix", "")
        sysroot_val = info.get("sysroot", "")
        setup_path = base / info.get("environment_setup", "")

        result.append({
            "sdkId": sdk_id,
            "compiler": f"{prefix}-gcc" if prefix else None,
            "compilerVersion": info.get("gcc_version"),
            "compilerPath": compiler_path,
            "targetArch": _infer_arch(prefix) if prefix else None,
            "sysroot": str(base / sysroot_val) if sysroot_val and base.is_dir() else None,
            "setupScript": str(setup_path) if setup_path.exists() else None,
            "installed": base.is_dir(),
        })

    return result


def get_sdk_compiler_path(base: Path, sdk_info: dict[str, Any]) -> str | None:
    """SDK 크로스 컴파일러의 절대 경로."""
    sysroot = sdk_info.get("sysroot", "")
    prefix = sdk_info.get("compiler_prefix", "")
    if not sysroot or not prefix:
        return None
    path = base / sysroot / "usr" / "bin" / f"{prefix}-gcc"
    return str(path) if path.exists() else None


def _infer_arch(compiler_prefix: str) -> str:
    """컴파일러 prefix에서 타겟 아키텍처를 추론."""
    if "arm" in compiler_prefix:
        return "arm"
    if "aarch64" in compiler_prefix:
        return "aarch64"
    if "x86_64" in compiler_prefix:
        return "x86_64"
    return compiler_prefix.split("-")[0]


def _resolve_from_registry(base: Path, sdk_info: dict[str, Any]) -> list[str]:
    """레지스트리 정보에서 인클루드 경로 목록을 생성."""
    sysroot = sdk_info.get("sysroot", "")
    prefix = sdk_info.get("compiler_prefix", "")
    gcc_ver = sdk_info.get("gcc_version", "")
    if not sysroot or not prefix or not gcc_ver:
        return []

    sysroot_dir = base / sysroot
    if not sysroot_dir.exists():
        logger.warning("SDK sysroot not found")
        return []

    gcc_base = sysroot_dir / "usr" / "lib" / "gcc" / prefix / gcc_ver
    cpp_include = sysroot_dir / "usr" / prefix / "include" / "c++" / gcc_ver
    libc_include = sysroot_dir / "usr" / prefix / "libc" / "usr" / "include"

    candidates = [
        # C++ 표준 라이브러리
        cpp_include,
        cpp_include / prefix,
        cpp_include / "backward",
        # GCC 내장 헤더
        gcc_base / "include",
        gcc_base / "include-fixed",
        # ARM 타겟 헤더
        sysroot_dir / "usr" / prefix / "include",
        # libc 헤더
        libc_include,
    ]

    return [str(p) for p in candidates if p.exists()]


def _descriptor_compiler_path(base: Path, descriptor: dict[str, Any]) -> Path | None:
    sysroot = descriptor.get("sysroot") or ""
    triplet = descriptor.get("toolchainTriplet") or ""
    if not sysroot or not triplet:
        return None
    sysroot_dir = _descriptor_path(base, sysroot)
    if not sysroot_dir:
        return None
    return sysroot_dir / "usr" / "bin" / f"{triplet}-gcc"


def _resolve_from_descriptor(base: Path, descriptor: dict[str, Any]) -> list[str]:
    """Build deterministic include candidates from a caller-resolved SDK descriptor."""
    sysroot = descriptor.get("sysroot") or ""
    triplet = descriptor.get("toolchainTriplet") or ""
    gcc_ver = descriptor.get("compilerVersion") or ""
    if not sysroot:
        return []

    sysroot_dir = _descriptor_path(base, sysroot)
    if not sysroot_dir or not _looks_like_readable_dir(sysroot_dir):
        return []

    candidates: list[Path] = [
        sysroot_dir / "usr" / "include",
    ]
    if triplet:
        candidates.extend([
            sysroot_dir / "usr" / triplet / "include",
            sysroot_dir / "usr" / triplet / "libc" / "usr" / "include",
        ])
    if triplet and gcc_ver:
        gcc_base = sysroot_dir / "usr" / "lib" / "gcc" / triplet / gcc_ver
        candidates.extend([
            gcc_base / "include",
            gcc_base / "include-fixed",
            sysroot_dir / "usr" / triplet / "include" / "c++" / gcc_ver,
            sysroot_dir / "usr" / triplet / "include" / "c++" / gcc_ver / triplet,
            sysroot_dir / "usr" / triplet / "include" / "c++" / gcc_ver / "backward",
        ])

    return [str(p) for p in candidates if p.exists()]
