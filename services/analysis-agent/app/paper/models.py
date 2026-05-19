from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

FORBIDDEN_LEAKAGE_CLASSES = [
    "cve_id",
    "fix_commit",
    "advisory",
    "exploit_writeup",
    "patch_text",
]


class CaseStage(str, Enum):
    CASE_REGISTERED = "CASE_REGISTERED"
    BUILD_CONTEXT_READY = "BUILD_CONTEXT_READY"
    SETUP_RUNNING = "SETUP_RUNNING"
    S4_STATIC_EVIDENCE_READY = "S4_STATIC_EVIDENCE_READY"
    S5_CODE_KB_READY = "S5_CODE_KB_READY"
    S5_FINDING_CONTEXT_READY = "S5_FINDING_CONTEXT_READY"
    S3_TRIAGE_COMPLETED = "S3_TRIAGE_COMPLETED"
    PAPER_EXPORT_READY = "PAPER_EXPORT_READY"


class StageProgress(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    DIAGNOSTIC = "diagnostic"


class Scope(BaseModel):
    includePaths: list[str] = Field(default_factory=list)
    excludePaths: list[str] = Field(default_factory=list)
    thirdPartyPaths: list[str] = Field(default_factory=list)


class ProducerArtifacts(BaseModel):
    s4StaticEvidencePath: str | None = None
    s5CodeKbPath: str | None = None
    s5FindingContextByFindingId: dict[str, str] = Field(default_factory=dict)
    s5GenericThreatContextByFindingId: dict[str, str] = Field(default_factory=dict)
    llmTriageByFindingId: dict[str, str] = Field(default_factory=dict)
    s5ContractSnapshotPath: str | None = None


class ServiceEndpoints(BaseModel):
    s4Endpoint: str | None = None
    s5Endpoint: str | None = None
    s7Endpoint: str | None = None


class PaperCaseCreateRequest(BaseModel):
    paperRunId: str
    paperRunRoot: str
    caseId: str
    buildTargetId: str
    targetManifestRef: str | None = None
    datasetRootRef: str | None = None
    sourceRootRef: str
    sourceRoot: str
    compileContextRef: str
    compileCommandsPath: str
    s5SourceKgIngestRequest: dict[str, Any] | None = None
    s5SourceKgSelectors: dict[str, Any] | None = None
    buildSnapshotId: str
    buildUnitId: str
    scope: Scope = Field(default_factory=Scope)
    producerArtifacts: ProducerArtifacts = Field(default_factory=ProducerArtifacts)
    serviceEndpoints: ServiceEndpoints = Field(default_factory=ServiceEndpoints)

    @field_validator("paperRunId", "caseId", "buildTargetId", "sourceRootRef", "compileContextRef", "buildSnapshotId", "buildUnitId")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must not be empty")
        return value

    @model_validator(mode="after")
    def validate_paths(self) -> "PaperCaseCreateRequest":
        source_root = Path(self.sourceRoot)
        compile_path = Path(self.compileCommandsPath)
        if not source_root.exists() or not source_root.is_dir():
            raise ValueError(f"sourceRoot is not a readable directory: {self.sourceRoot}")
        if not compile_path.exists() or not compile_path.is_file():
            raise ValueError(f"compileCommandsPath is not a readable file: {self.compileCommandsPath}")
        run_root = Path(self.paperRunRoot)
        run_root.mkdir(parents=True, exist_ok=True)
        probe = run_root / ".aegis-write-probe"
        probe.write_text("ok\n")
        probe.unlink(missing_ok=True)
        return self


class StageRecord(BaseModel):
    stage: CaseStage
    status: StageProgress
    artifactRef: str | None = None
    diagnostic: str | None = None


class StageResult(BaseModel):
    stage: CaseStage
    status: StageProgress
    artifactRef: str | None = None
    diagnostic: str | None = None


class CaseRecord(BaseModel):
    caseId: str
    buildTargetId: str
    paperRunId: str
    status: CaseStage
    stages: list[StageRecord]
    caseRoot: str
    summary: dict[str, Any] = Field(default_factory=dict)


class PaperCaseCreateResponse(BaseModel):
    caseId: str
    buildTargetId: str
    paperRunId: str
    status: CaseStage
    links: dict[str, str]


class PaperCaseStatusResponse(BaseModel):
    caseId: str
    buildTargetId: str
    paperRunId: str
    status: CaseStage
    stages: list[StageRecord]
    summary: dict[str, Any]


class PaperArtifactsResponse(BaseModel):
    caseId: str
    status: CaseStage
    caseRoot: str
    files: list[str]


class TriageVerdict(str, Enum):
    TP = "TP"
    FP = "FP"
    UNKNOWN = "UNKNOWN"


class ClaimEvidenceLink(BaseModel):
    claim: str
    stance: str
    evidenceRefs: list[str] = Field(default_factory=list)


class TriageEnvelopeRow(BaseModel):
    findingId: str
    verdict: TriageVerdict
    rationale: str
    citedEvidenceRefs: list[str] = Field(default_factory=list)
    claimEvidenceLinks: list[ClaimEvidenceLink] = Field(default_factory=list)
    unsupportedClaims: list[str] = Field(default_factory=list)
    unknownReason: str | None = None
    diagnosticRefsUsed: list[str] = Field(default_factory=list)
    boundaryNotes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def enforce_evidence_refs(self) -> "TriageEnvelopeRow":
        if self.verdict in {TriageVerdict.TP, TriageVerdict.FP} and not self.citedEvidenceRefs:
            raise ValueError("TP/FP triage rows require at least one citedEvidenceRef")
        return self


class EvidenceLedgerRow(BaseModel):
    evidenceRef: str
    caseId: str
    buildTargetId: str
    producer: Literal["s3", "s4", "s5", "s7"]
    producerRunId: str | None = None
    rawObjectRef: str | None = None
    sourceId: str | None = None
    relatedFindingId: str | None = None
    evidenceType: str
    text: str = ""
    surfaceStatus: str | None = None
    visibleLeakageClass: str | None = None
    producerTrace: dict[str, Any] = Field(default_factory=dict)
    diagnostic: bool = False
    claimLinks: list[dict[str, Any]] = Field(default_factory=list)
