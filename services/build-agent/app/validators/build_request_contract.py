from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass

from pydantic import ValidationError

from app.agent_runtime.path_util import resolve_scoped_path
from app.schemas.request import BuildMode, BuildResolveContract, ContractVersion, TaskRequest
from app.types import TaskType

_MAX_SCRIPT_HINT_BYTES = 20_000
_WINDOWS_DRIVE_OR_UNC = re.compile(r"^(?:[a-zA-Z]:[\\/]|\\\\|//)")


@dataclass(frozen=True)
class BuildScriptHintMaterial:
    """Validated uploaded-project script hint material for prompt reference."""

    path: str
    resolved_path: str
    content: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class SdkMaterialization:
    """Validated SDK descriptor material for strict SDK-mode builds."""

    sdk_root_path: str | None
    setup_script: str | None
    setup_script_raw: str | None
    sysroot: str | None
    sysroot_raw: str | None
    toolchain_triplet: str | None
    caller_environment: dict[str, str]
    derived_environment: dict[str, str]
    effective_environment: dict[str, str]
    legacy_transitional: bool = False


@dataclass(frozen=True)
class BuildRequestPreflight:
    contract: BuildResolveContract
    project_path: str
    target_path: str
    target_name: str
    script_hint: BuildScriptHintMaterial | None = None
    sdk_materialization: SdkMaterialization | None = None


class BuildRequestContractValidator:
    def validate(self, request: TaskRequest) -> tuple[BuildRequestPreflight | None, list[str]]:
        if request.taskType != TaskType.BUILD_RESOLVE:
            return None, []

        try:
            contract = request.build_resolve_contract()
        except ValidationError as exc:
            return None, self._format_validation_errors(exc)

        errors: list[str] = []
        project_path = contract.projectPath

        if not os.path.isabs(project_path):
            errors.append("context.trusted.projectPath must be an absolute path")

        strict_mode = contract.strictMode is True

        if strict_mode and not os.path.isdir(project_path):
            errors.append(
                "strict compile-first v1 requires context.trusted.projectPath to exist and be a directory",
            )

        target_path = self._normalize_target_path(contract.buildTargetPath or contract.targetPath)
        if contract.buildTargetPath is not None or contract.targetPath is not None:
            scoped_target = resolve_scoped_path(project_path, target_path or ".")
            if scoped_target is None:
                errors.append("context.trusted.buildTargetPath must stay within projectPath")

        if strict_mode:
            if contract.buildTargetPath is None:
                errors.append(
                    "strict compile-first v1 requires context.trusted.buildTargetPath "
                    "(use '.' when the project root itself is the declared target)",
                )
            if not contract.buildTargetName:
                errors.append("strict compile-first v1 requires context.trusted.buildTargetName")
            if contract.buildMode is None:
                errors.append("strict compile-first v1 requires context.trusted.build.mode")
            if not contract.expectedArtifacts:
                errors.append("strict compile-first v1 requires context.trusted.expectedArtifacts")

        if contract.buildMode == BuildMode.SDK and contract.sdkId is None:
            errors.append("context.trusted.build.sdkId is required when build.mode is 'sdk'")
        if strict_mode and contract.buildMode == BuildMode.SDK and not (
            contract.setupScript or contract.buildEnvironment or contract.scriptHintPath
        ):
            errors.append(
                "strict compile-first v1 sdk builds require at least one materialization source: "
                "context.trusted.build.setupScript, context.trusted.build.environment, "
                "or context.trusted.build.scriptHintPath",
            )

        sdk_materialization: SdkMaterialization | None = None
        if contract.buildMode == BuildMode.SDK:
            sdk_materialization, sdk_errors = self._validate_sdk_materialization(
                contract=contract,
                strict_mode=strict_mode,
            )
            errors.extend(sdk_errors)

        script_hint: BuildScriptHintMaterial | None = None
        if contract.scriptHintPath:
            script_hint, hint_errors = self._load_script_hint(
                project_path=project_path,
                target_path=target_path,
                script_hint_path=contract.scriptHintPath,
            )
            errors.extend(hint_errors)

        if errors:
            return None, errors

        target_name = contract.buildTargetName or contract.targetName or self._derive_target_name(project_path, target_path)
        return BuildRequestPreflight(
            contract=contract,
            project_path=project_path,
            target_path=target_path,
            target_name=target_name,
            script_hint=script_hint,
            sdk_materialization=sdk_materialization,
        ), []

    @staticmethod
    def _validate_sdk_materialization(
        *,
        contract: BuildResolveContract,
        strict_mode: bool,
    ) -> tuple[SdkMaterialization, list[str]]:
        errors: list[str] = []
        root_raw = contract.sdkRootPath
        root_resolved: str | None = None
        setup_resolved: str | None = None
        sysroot_resolved: str | None = None
        legacy_transitional = False

        if root_raw:
            if "\x00" in root_raw:
                errors.append("context.trusted.build.sdkRootPath must not contain NUL bytes")
            elif not os.path.isabs(root_raw):
                errors.append("context.trusted.build.sdkRootPath must be an absolute server-visible path")
            else:
                root_resolved = os.path.realpath(root_raw)
                if strict_mode and not os.path.isdir(root_resolved):
                    errors.append("context.trusted.build.sdkRootPath must exist and be a directory")
        elif strict_mode:
            # The only no-root strict-SDK compatibility path is a legacy
            # absolute setupScript. Relative setup paths, env-only requests, or
            # scriptHint-only requests do not provide an uploaded-SDK trust
            # boundary and must not satisfy the materialization contract.
            if not (contract.setupScript and os.path.isabs(contract.setupScript)):
                errors.append(
                    "strict compile-first v1 sdk builds require context.trusted.build.sdkRootPath "
                    "or a legacy absolute context.trusted.build.setupScript",
                )

        def _inside(candidate: str, parent: str) -> bool:
            try:
                return os.path.commonpath([candidate, parent]) == parent
            except ValueError:
                return False

        def _resolve_descriptor_path(raw: str | None, field: str, *, must_be_file: bool) -> str | None:
            nonlocal legacy_transitional
            if not raw:
                return None
            if "\x00" in raw:
                errors.append(f"context.trusted.build.{field} must not contain NUL bytes")
                return None
            if "\\" in raw:
                errors.append(f"context.trusted.build.{field} must use POSIX '/' separators")
                return None

            if root_resolved:
                if os.path.isabs(raw):
                    candidate = os.path.realpath(raw)
                else:
                    normalized = os.path.normpath(raw)
                    if normalized in ("", ".") or normalized.startswith("../") or normalized == "..":
                        errors.append(
                            f"context.trusted.build.{field} must resolve inside sdkRootPath",
                        )
                        return None
                    if ".." in normalized.split(os.sep):
                        errors.append(
                            f"context.trusted.build.{field} must not contain path traversal",
                        )
                        return None
                    candidate = os.path.realpath(os.path.join(root_resolved, normalized))
                if not _inside(candidate, root_resolved):
                    errors.append(f"context.trusted.build.{field} must resolve inside sdkRootPath")
                    return None
                if strict_mode:
                    if must_be_file and not os.path.isfile(candidate):
                        errors.append(f"context.trusted.build.{field} must resolve to a regular file")
                    if not must_be_file and not os.path.isdir(candidate):
                        errors.append(f"context.trusted.build.{field} must resolve to a directory")
                return candidate

            # Legacy transitional behavior: absolute setup/sysroot paths without
            # sdkRootPath remain accepted so existing callers do not break. They
            # are not proof of uploaded-SDK materialization and cannot provide a
            # scoped root boundary.
            if strict_mode and not os.path.isabs(raw):
                errors.append(
                    f"context.trusted.build.{field} requires sdkRootPath when using a relative path",
                )
                return None
            legacy_transitional = True
            return os.path.realpath(raw) if os.path.isabs(raw) else raw

        setup_resolved = _resolve_descriptor_path(
            contract.setupScript,
            "setupScript",
            must_be_file=True,
        )
        sysroot_resolved = _resolve_descriptor_path(
            contract.sysroot,
            "sysroot",
            must_be_file=False,
        )

        derived_environment: dict[str, str] = {}
        if root_resolved:
            derived_environment["AEGIS_SDK_ROOT"] = root_resolved
            derived_environment["SDK_DIR"] = root_resolved
        if setup_resolved:
            derived_environment["AEGIS_SDK_SETUP_SCRIPT"] = setup_resolved
        if sysroot_resolved:
            derived_environment["AEGIS_SDK_SYSROOT"] = sysroot_resolved
            derived_environment["SDKTARGETSYSROOT"] = sysroot_resolved
        if contract.toolchainTriplet:
            derived_environment["AEGIS_TOOLCHAIN_TRIPLET"] = contract.toolchainTriplet

        effective_environment = dict(contract.buildEnvironment)
        # The trusted descriptor is authoritative; caller env remains
        # supplemental and cannot override descriptor-derived paths.
        effective_environment.update(derived_environment)

        return SdkMaterialization(
            sdk_root_path=root_resolved,
            setup_script=setup_resolved,
            setup_script_raw=contract.setupScript,
            sysroot=sysroot_resolved,
            sysroot_raw=contract.sysroot,
            toolchain_triplet=contract.toolchainTriplet,
            caller_environment=dict(contract.buildEnvironment),
            derived_environment=derived_environment,
            effective_environment=effective_environment,
            legacy_transitional=legacy_transitional and root_resolved is None,
        ), errors

    @staticmethod
    def _load_script_hint(
        *,
        project_path: str,
        target_path: str,
        script_hint_path: str,
    ) -> tuple[BuildScriptHintMaterial | None, list[str]]:
        errors: list[str] = []
        if not script_hint_path:
            return None, ["context.trusted.build.scriptHintPath must not be empty"]
        if "\x00" in script_hint_path:
            return None, ["context.trusted.build.scriptHintPath must not contain NUL bytes"]
        if "\\" in script_hint_path:
            return None, ["context.trusted.build.scriptHintPath must use POSIX '/' separators"]
        if os.path.isabs(script_hint_path) or _WINDOWS_DRIVE_OR_UNC.match(script_hint_path):
            return None, ["context.trusted.build.scriptHintPath must be a relative uploaded-project path"]

        normalized = os.path.normpath(script_hint_path)
        if ".." in script_hint_path.split("/"):
            return None, ["context.trusted.build.scriptHintPath must not contain path traversal"]
        if normalized in ("", ".") or normalized.startswith("../") or normalized == "..":
            return None, ["context.trusted.build.scriptHintPath must not traverse outside the build target"]
        if ".." in normalized.split(os.sep):
            return None, ["context.trusted.build.scriptHintPath must not contain path traversal"]

        # Canonical interpretation after S2 review: scriptHintPath is relative
        # to the effective BuildTarget root, not the broader uploaded project
        # root.  This keeps Build Agent hints scoped to the declared target.
        allowed_root = os.path.join(project_path, target_path) if target_path else project_path
        resolved = resolve_scoped_path(allowed_root, normalized)
        if resolved is None:
            return None, ["context.trusted.build.scriptHintPath must resolve inside the build target scope"]
        if not os.path.isfile(resolved):
            return None, ["context.trusted.build.scriptHintPath must resolve to a regular file"]

        try:
            size_bytes = os.path.getsize(resolved)
        except OSError:
            return None, ["context.trusted.build.scriptHintPath could not be stat'ed"]
        if size_bytes > _MAX_SCRIPT_HINT_BYTES:
            return None, [
                "context.trusted.build.scriptHintPath exceeds "
                f"{_MAX_SCRIPT_HINT_BYTES} byte limit",
            ]

        try:
            with open(resolved, "rb") as fp:
                raw = fp.read()
        except OSError:
            return None, ["context.trusted.build.scriptHintPath could not be read"]
        if b"\x00" in raw:
            return None, ["context.trusted.build.scriptHintPath must be a text file without NUL bytes"]
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None, ["context.trusted.build.scriptHintPath must be UTF-8 text"]

        return BuildScriptHintMaterial(
            path=normalized,
            resolved_path=resolved,
            content=content,
            size_bytes=size_bytes,
            sha256=hashlib.sha256(raw).hexdigest(),
        ), []

    @staticmethod
    def _normalize_target_path(target_path: str | None) -> str:
        if target_path is None:
            return ""
        normalized = os.path.normpath(target_path)
        return "" if normalized == "." else normalized

    @staticmethod
    def _derive_target_name(project_path: str, target_path: str) -> str:
        if target_path:
            return os.path.basename(target_path.rstrip("/")) or target_path
        return os.path.basename(os.path.normpath(project_path)) or "project-root"

    @staticmethod
    def _format_validation_errors(exc: ValidationError) -> list[str]:
        errors: list[str] = []
        for error in exc.errors():
            loc = ".".join(str(part) for part in error.get("loc", ()))
            msg = error.get("msg", "invalid value")
            errors.append(f"{loc}: {msg}" if loc else msg)
        return errors


def normalize_contract_version(contract: BuildResolveContract) -> str:
    if contract.contractVersion == ContractVersion.BUILD_RESOLVE_V1:
        return ContractVersion.BUILD_RESOLVE_V1.value
    return ContractVersion.LEGACY.value
