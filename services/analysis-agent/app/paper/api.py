from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from .artifacts import CaseArtifacts, write_initial_case
from .errors import PaperConflictError, PaperError, PaperNotFoundError
from .models import (
    CaseRecord,
    CaseStage,
    PaperArtifactsResponse,
    PaperCaseCreateRequest,
    PaperCaseCreateResponse,
    PaperCaseStatusResponse,
    StageProgress,
    StageRecord,
)
from .observability import PaperObservedRoute, log_event, paper_error_response
from .runner import PaperCaseRunner

router = APIRouter(prefix="/v1/paper", tags=["paper"], route_class=PaperObservedRoute)

_CASES: dict[str, PaperCaseCreateRequest] = {}
_RECORDS: dict[str, CaseRecord] = {}


def _error_response(exc: PaperError) -> JSONResponse:
    return paper_error_response(exc)


@router.post("/analysis-cases")
async def create_analysis_case(request: PaperCaseCreateRequest) -> JSONResponse:
    try:
        if request.caseId in _CASES:
            existing = _CASES[request.caseId]
            if existing.model_dump(mode="json") != request.model_dump(mode="json"):
                raise PaperConflictError(f"caseId already registered with different input: {request.caseId}")
        artifacts = CaseArtifacts.from_request(request)
        write_initial_case(artifacts, request)
        stages = [
            StageRecord(stage=CaseStage.CASE_REGISTERED, status=StageProgress.DONE, artifactRef="case-manifest.json"),
            StageRecord(stage=CaseStage.BUILD_CONTEXT_READY, status=StageProgress.PENDING),
            StageRecord(stage=CaseStage.SETUP_RUNNING, status=StageProgress.PENDING),
            StageRecord(stage=CaseStage.S4_STATIC_EVIDENCE_READY, status=StageProgress.PENDING),
            StageRecord(stage=CaseStage.S5_CODE_KB_READY, status=StageProgress.PENDING),
            StageRecord(stage=CaseStage.S5_FINDING_CONTEXT_READY, status=StageProgress.PENDING),
            StageRecord(stage=CaseStage.S3_TRIAGE_COMPLETED, status=StageProgress.PENDING),
            StageRecord(stage=CaseStage.PAPER_EXPORT_READY, status=StageProgress.PENDING),
        ]
        record = CaseRecord(
            caseId=request.caseId,
            buildTargetId=request.buildTargetId,
            paperRunId=request.paperRunId,
            status=CaseStage.CASE_REGISTERED,
            stages=stages,
            caseRoot=str(artifacts.root),
            summary={"canStart": True, "findingCount": 0, "triagedFindingCount": 0},
        )
        _CASES[request.caseId] = request
        _RECORDS[request.caseId] = record
        log_event(
            "paper case registered",
            event="paper_case_registered",
            caseId=request.caseId,
            buildTargetId=request.buildTargetId,
            paperRunId=request.paperRunId,
        )
        response = PaperCaseCreateResponse(
            caseId=request.caseId,
            buildTargetId=request.buildTargetId,
            paperRunId=request.paperRunId,
            status=CaseStage.CASE_REGISTERED,
            links={
                "status": f"/v1/paper/analysis-cases/{request.caseId}",
                "start": f"/v1/paper/analysis-cases/{request.caseId}/start",
                "artifacts": f"/v1/paper/analysis-cases/{request.caseId}/artifacts",
            },
        )
        return JSONResponse(status_code=201, content=response.model_dump(mode="json"))
    except PaperError as exc:
        return _error_response(exc)


@router.get("/analysis-cases")
async def list_analysis_cases(paperRunId: str | None = Query(default=None)) -> dict[str, Any]:
    records = [record for record in _RECORDS.values() if paperRunId is None or record.paperRunId == paperRunId]
    log_event(
        "paper cases listed",
        event="paper_cases_listed",
        paperRunId=paperRunId,
        caseCount=len(records),
    )
    return {"cases": [PaperCaseStatusResponse(**record.model_dump()).model_dump(mode="json") for record in records]}


@router.get("/analysis-cases/{case_id}")
async def get_analysis_case(case_id: str) -> JSONResponse:
    try:
        record = _get_record(case_id)
        log_event(
            "paper case status fetched",
            event="paper_case_status_fetched",
            caseId=record.caseId,
            buildTargetId=record.buildTargetId,
            paperRunId=record.paperRunId,
            status=record.status.value,
        )
        return JSONResponse(content=PaperCaseStatusResponse(**record.model_dump()).model_dump(mode="json"))
    except PaperError as exc:
        return _error_response(exc)


@router.post("/analysis-cases/{case_id}/start")
async def start_analysis_case(case_id: str) -> JSONResponse:
    try:
        request = _get_case(case_id)
        log_event(
            "paper case start requested",
            event="paper_case_start_requested",
            caseId=request.caseId,
            buildTargetId=request.buildTargetId,
            paperRunId=request.paperRunId,
        )
        runner = PaperCaseRunner()
        summary = await runner.run(request)
        record = _get_record(case_id)
        record.status = CaseStage.PAPER_EXPORT_READY
        _apply_stage_results(record, summary)
        record.summary = summary
        _RECORDS[case_id] = record
        log_event(
            "paper case completed",
            event="paper_case_completed",
            caseId=request.caseId,
            buildTargetId=request.buildTargetId,
            paperRunId=request.paperRunId,
            findingCount=summary.get("findingCount"),
            triageCounts=summary.get("triageCounts"),
        )
        return JSONResponse(content=PaperCaseStatusResponse(**record.model_dump()).model_dump(mode="json"))
    except PaperError as exc:
        return _error_response(exc)
    except Exception as exc:  # defensive: /start normal 200 is only PAPER_EXPORT_READY
        return _error_response(PaperError(f"Paper case failed before PAPER_EXPORT_READY: {exc}"))


@router.get("/analysis-cases/{case_id}/artifacts")
async def get_artifacts(case_id: str) -> JSONResponse:
    try:
        record = _get_record(case_id)
        artifacts = CaseArtifacts.from_request(_get_case(case_id))
        response = PaperArtifactsResponse(
            caseId=case_id,
            status=record.status,
            caseRoot=str(artifacts.root),
            files=artifacts.list_files(),
        )
        log_event(
            "paper artifacts listed",
            event="paper_artifacts_listed",
            caseId=record.caseId,
            buildTargetId=record.buildTargetId,
            paperRunId=record.paperRunId,
            fileCount=len(response.files),
        )
        return JSONResponse(content=response.model_dump(mode="json"))
    except PaperError as exc:
        return _error_response(exc)


def _get_case(case_id: str) -> PaperCaseCreateRequest:
    if case_id not in _CASES:
        raise PaperNotFoundError(f"unknown paper case: {case_id}")
    return _CASES[case_id]


def _get_record(case_id: str) -> CaseRecord:
    if case_id not in _RECORDS:
        raise PaperNotFoundError(f"unknown paper case: {case_id}")
    return _RECORDS[case_id]


def _apply_stage_results(record: CaseRecord, summary: dict[str, Any]) -> None:
    results = {item.get("stage"): item for item in summary.get("stageResults", []) if isinstance(item, dict)}
    for stage in record.stages:
        result = results.get(stage.stage.value)
        if result:
            stage.status = StageProgress(result.get("status", stage.status.value))
            stage.artifactRef = result.get("artifactRef")
            stage.diagnostic = result.get("diagnostic")
    if record.status == CaseStage.PAPER_EXPORT_READY:
        export_stage = next((stage for stage in record.stages if stage.stage == CaseStage.PAPER_EXPORT_READY), None)
        if export_stage and export_stage.status != StageProgress.DONE:
            raise PaperError("runner reported PAPER_EXPORT_READY without a completed export stage")
