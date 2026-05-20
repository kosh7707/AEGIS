from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from app.clients.s4_ownership import (
    S4OwnershipError,
    S4OwnershipUnsupported,
    make_s4_operation_request_id,
    post_and_wait_s4_ownership,
)
from app.config import settings

from .artifacts import read_json
from .errors import PaperOperationalError
from .models import PaperCaseCreateRequest
from .observability import current_request_id_or, log_event, log_http_end, log_http_error, log_http_start
from .timeout_policy import wait_while_alive_http_timeout
from .validation import validate_s4_bundle


def build_s4_request(case: PaperCaseCreateRequest) -> dict[str, Any]:
    return {
        "caseId": case.caseId,
        "buildTargetId": case.buildTargetId,
        "sourceRoot": case.sourceRoot,
        "compileContext": {
            "type": "compile_commands_json",
            "path": case.compileCommandsPath,
            "ref": case.compileContextRef,
        },
        "provenance": {
            "paperRunId": case.paperRunId,
            "buildSnapshotId": case.buildSnapshotId,
            "buildUnitId": case.buildUnitId,
            "datasetRootRef": case.datasetRootRef,
            "sourceRootRef": case.sourceRootRef,
            "compileContextRef": case.compileContextRef,
        },
        "scope": case.scope.model_dump(mode="json"),
    }


class S4PaperClient:
    def __init__(self, endpoint: str | None = None):
        self.endpoint = endpoint or settings.sast_endpoint
        self.transport_timeout = wait_while_alive_http_timeout()

    async def produce_static_evidence(self, case: PaperCaseCreateRequest) -> tuple[dict[str, Any], dict[str, Any]]:
        request = build_s4_request(case)
        if case.producerArtifacts.s4StaticEvidencePath:
            data = read_json(case.producerArtifacts.s4StaticEvidencePath)
            log_event(
                "S4 static evidence loaded from file-backed artifact",
                event="paper_producer_file_backed",
                target="s4-sast",
                method="POST",
                path="/v1/paper/static-evidence",
                mode="file_backed",
                caseId=case.caseId,
                buildTargetId=case.buildTargetId,
                paperRunId=case.paperRunId,
            )
        else:
            path = "/v1/paper/static-evidence"
            root_request_id = current_request_id_or()
            child_request_id = make_s4_operation_request_id(
                root_request_id,
                endpoint=path,
                operation="paper-static-evidence",
                payload=request,
            )
            started_at = log_http_start(
                target="s4-sast",
                method="POST",
                path=path,
                case_id=case.caseId,
                build_target_id=case.buildTargetId,
                paper_run_id=case.paperRunId,
                operation_request_id=child_request_id,
                child_request_id=child_request_id,
            )
            try:
                async with httpx.AsyncClient(timeout=self.transport_timeout) as client:
                    owned = await post_and_wait_s4_ownership(
                        client,
                        base_url=self.endpoint,
                        endpoint_path=path,
                        payload=request,
                        root_request_id=root_request_id,
                        operation="paper-static-evidence",
                    )
                    data = owned.payload
                    child_request_id = owned.request_id
            except S4OwnershipUnsupported as exc:
                log_http_error(
                    started_at=started_at,
                    target="s4-sast",
                    method="POST",
                    path=path,
                    error_code="S4_OWNERSHIP_UNSUPPORTED",
                    case_id=case.caseId,
                    build_target_id=case.buildTargetId,
                    paper_run_id=case.paperRunId,
                    operation_request_id=child_request_id,
                    child_request_id=child_request_id,
                )
                raise PaperOperationalError("S4 paper static-evidence durable ownership is required") from exc
            except S4OwnershipError as exc:
                log_http_error(
                    started_at=started_at,
                    target="s4-sast",
                    method="POST",
                    path=path,
                    error_code="S4_OWNERSHIP_ERROR",
                    case_id=case.caseId,
                    build_target_id=case.buildTargetId,
                    paper_run_id=case.paperRunId,
                    operation_request_id=child_request_id,
                    child_request_id=child_request_id,
                )
                raise PaperOperationalError(
                    f"S4 static-evidence ownership failure: {exc}",
                    detail={"statusCode": exc.status_code, "payload": exc.payload},
                ) from exc
            except httpx.HTTPError as exc:
                log_http_error(
                    started_at=started_at,
                    target="s4-sast",
                    method="POST",
                    path=path,
                    error_code=type(exc).__name__,
                    case_id=case.caseId,
                    build_target_id=case.buildTargetId,
                    paper_run_id=case.paperRunId,
                    operation_request_id=child_request_id,
                    child_request_id=child_request_id,
                )
                raise PaperOperationalError(f"S4 static-evidence transport failure: {exc}") from exc
            log_http_end(
                started_at=started_at,
                target="s4-sast",
                method="POST",
                path=path,
                status=200,
                case_id=case.caseId,
                build_target_id=case.buildTargetId,
                paper_run_id=case.paperRunId,
                operation_request_id=child_request_id,
                child_request_id=child_request_id,
            )
        validate_s4_bundle(data, case_id=case.caseId, build_target_id=case.buildTargetId)
        return data, request
