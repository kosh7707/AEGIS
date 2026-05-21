from __future__ import annotations

from pydantic import BaseModel, Field

from app.types import FailureCode, TaskStatus, TaskType


class Claim(BaseModel):
    statement: str
    supportingEvidenceRefs: list[str] = []
    location: str | None = None


class ConfidenceBreakdown(BaseModel):
    grounding: float = 0.0
    deterministicSupport: float = 0.0
    ragCoverage: float = 0.0
    schemaCompliance: float = 0.0


class TestPlan(BaseModel):
    objective: str
    hypotheses: list[str] = []
    targetProtocol: str | None = None
    targetServiceClass: str | None = None
    preconditions: list[str] = []
    dataToCollect: list[str] = []
    stopConditions: list[str] = []
    safetyConstraints: list[str] = []
    suggestedExecutorTemplateIds: list[str] = []
    suggestedRiskLevel: str | None = None


class AssessmentResult(BaseModel):
    summary: str
    claims: list[Claim] = []
    caveats: list[str] = []
    usedEvidenceRefs: list[str] = []
    suggestedSeverity: str | None = None
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    confidenceBreakdown: ConfidenceBreakdown = Field(
        default_factory=ConfidenceBreakdown,
    )
    needsHumanReview: bool = True
    recommendedNextSteps: list[str] = []
    policyFlags: list[str] = []
    plan: TestPlan | None = None


class ValidationInfo(BaseModel):
    valid: bool
    errors: list[str] = []


class TokenUsage(BaseModel):
    prompt: int = 0
    completion: int = 0


class AuditInfo(BaseModel):
    inputHash: str
    latencyMs: int = 0
    tokenUsage: TokenUsage = Field(default_factory=TokenUsage)
    retryCount: int = 0
    ragHits: int = 0
    createdAt: str


class TaskSuccessResponse(BaseModel):
    taskId: str
    taskType: TaskType
    status: TaskStatus = TaskStatus.COMPLETED
    modelProfile: str
    promptVersion: str
    schemaVersion: str
    validation: ValidationInfo
    result: AssessmentResult
    audit: AuditInfo


class TaskFailureResponse(BaseModel):
    taskId: str
    taskType: TaskType
    status: TaskStatus
    failureCode: FailureCode
    failureDetail: str
    retryable: bool = False
    audit: AuditInfo


class AsyncChatAcceptedResponse(BaseModel):
    requestId: str
    traceRequestId: str
    status: str
    statusUrl: str
    resultUrl: str
    cancelUrl: str
    acceptedAt: str
    expiresAt: str


class AsyncChatStatusResponse(BaseModel):
    requestId: str
    traceRequestId: str
    state: str
    localAckState: str | None = None
    phase: str | None = None
    degraded: bool = False
    degradeReasons: list[str] = []
    lastAckAt: int | None = None
    lastAckSource: str | None = None
    blockedReason: str | None = None
    error: str | None = None
    errorDetail: str | None = None
    retryable: bool = False
    resultReady: bool = False
    acceptedAt: str
    startedAt: str | None = None
    endedAt: str | None = None
    expiresAt: str
    statusUrl: str
    resultUrl: str
    cancelUrl: str
    backendActivity: dict | None = None


class AsyncChatResultResponse(BaseModel):
    requestId: str
    traceRequestId: str
    state: str
    completedAt: str | None = None
    expiresAt: str
    response: dict
