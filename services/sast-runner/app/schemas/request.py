from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class SnapshotProvenance(BaseModel):
    build_snapshot_id: str | None = Field(default=None, alias="buildSnapshotId")
    build_unit_id: str | None = Field(default=None, alias="buildUnitId")
    snapshot_schema_version: str | None = Field(default=None, alias="snapshotSchemaVersion")

    model_config = {"populate_by_name": True}


class FileEntry(BaseModel):
    path: str
    content: str


class ScanOptions(BaseModel):
    timeout_seconds: int = Field(default=120, alias="timeoutSeconds")
    tools: list[str] | None = None

    model_config = {"populate_by_name": True}


# --- BuildProfile (S4 service-local extension of shared BuildProfile) ---


class SdkDescriptor(BaseModel):
    """Caller-resolved SDK descriptor for non-registered SDK analysis."""

    sdk_root_path: str | None = Field(default=None, alias="sdkRootPath")
    setup_script: str | None = Field(default=None, alias="setupScript")
    sysroot: str | None = None
    toolchain_triplet: str | None = Field(default=None, alias="toolchainTriplet")
    compiler_path: str | None = Field(default=None, alias="compilerPath")
    compiler_version: str | None = Field(default=None, alias="compilerVersion")
    target_arch: str | None = Field(default=None, alias="targetArch")
    language_standard: str | None = Field(default=None, alias="languageStandard")
    include_paths: list[str] | None = Field(default=None, alias="includePaths")
    defines: dict[str, str] | None = None
    environment: dict[str, str] | None = None

    model_config = {"populate_by_name": True}


class BuildProfile(BaseModel):
    sdk_id: str | None = Field(default=None, alias="sdkId")
    sdk_resolution_mode: Literal["none", "non-registered"] | None = Field(
        default=None,
        alias="sdkResolutionMode",
    )
    sdk_descriptor: SdkDescriptor | None = Field(default=None, alias="sdkDescriptor")
    compiler: str | None = None
    compiler_version: str | None = Field(default=None, alias="compilerVersion")
    target_arch: str | None = Field(default=None, alias="targetArch")
    language_standard: str | None = Field(default=None, alias="languageStandard")
    header_language: Literal["c", "cpp", "auto"] = Field(default="auto", alias="headerLanguage")
    include_paths: list[str] | None = Field(default=None, alias="includePaths")
    defines: dict[str, str] | None = None
    flags: list[str] | None = None

    model_config = {"populate_by_name": True}


class ScanRequest(BaseModel):
    scan_id: str = Field(alias="scanId")
    project_id: str = Field(alias="projectId")
    files: list[FileEntry] = []
    project_path: str | None = Field(default=None, alias="projectPath")
    compile_commands: str | None = Field(default=None, alias="compileCommands")
    build_profile: BuildProfile | None = Field(default=None, alias="buildProfile")
    provenance: SnapshotProvenance | None = None
    rulesets: list[str] | None = None
    third_party_paths: list[str] | None = Field(default=None, alias="thirdPartyPaths")
    options: ScanOptions = Field(default_factory=ScanOptions)

    model_config = {"populate_by_name": True}


class BuildRequest(BaseModel):
    project_path: str | None = Field(default=None, alias="projectPath")
    build_command: str | None = Field(default=None, alias="buildCommand")
    build_environment: dict[str, str] | None = Field(default=None, alias="buildEnvironment")
    provenance: SnapshotProvenance | None = None
    wrap_with_bear: bool = Field(default=True, alias="wrapWithBear")

    model_config = {"populate_by_name": True, "extra": "forbid"}


class BuildAndAnalyzeRequest(BaseModel):
    project_path: str | None = Field(default=None, alias="projectPath")
    build_command: str | None = Field(default=None, alias="buildCommand")
    project_id: str = Field(default="auto", alias="projectId")
    build_environment: dict[str, str] | None = Field(default=None, alias="buildEnvironment")
    scan_profile: BuildProfile | None = Field(default=None, alias="scanProfile")
    provenance: SnapshotProvenance | None = None
    rulesets: list[str] | None = None
    third_party_paths: list[str] | None = Field(default=None, alias="thirdPartyPaths")
    options: ScanOptions = Field(default_factory=ScanOptions)

    model_config = {"populate_by_name": True, "extra": "forbid"}


class DiscoverTargetsRequest(BaseModel):
    project_path: str | None = Field(default=None, alias="projectPath")

    model_config = {"populate_by_name": True}


class PaperCompileContext(BaseModel):
    type: Literal["compile_commands_json"]
    path: str
    ref: str

    model_config = {"populate_by_name": True, "extra": "forbid"}


class PaperStaticEvidenceProvenance(BaseModel):
    paper_run_id: str = Field(alias="paperRunId")
    build_snapshot_id: str = Field(alias="buildSnapshotId")
    build_unit_id: str = Field(alias="buildUnitId")
    dataset_root_ref: str | None = Field(default=None, alias="datasetRootRef")
    source_root_ref: str = Field(alias="sourceRootRef")
    compile_context_ref: str = Field(alias="compileContextRef")

    model_config = {"populate_by_name": True, "extra": "forbid"}


class PaperStaticEvidenceScope(BaseModel):
    include_paths: list[str] = Field(default_factory=list, alias="includePaths")
    exclude_paths: list[str] = Field(default_factory=list, alias="excludePaths")
    third_party_paths: list[str] = Field(default_factory=list, alias="thirdPartyPaths")

    model_config = {"populate_by_name": True, "extra": "forbid"}


class PaperStaticEvidenceRequest(BaseModel):
    case_id: str = Field(alias="caseId")
    build_target_id: str = Field(alias="buildTargetId")
    source_root: str = Field(alias="sourceRoot")
    compile_context: PaperCompileContext = Field(alias="compileContext")
    provenance: PaperStaticEvidenceProvenance
    scope: PaperStaticEvidenceScope = Field(default_factory=PaperStaticEvidenceScope)

    model_config = {"populate_by_name": True, "extra": "forbid"}
