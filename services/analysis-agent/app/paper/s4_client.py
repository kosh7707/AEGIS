from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from app.config import settings

from .artifacts import read_json
from .errors import PaperOperationalError
from .models import PaperCaseCreateRequest
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
    def __init__(self, endpoint: str | None = None, timeout_seconds: float = 60.0):
        self.endpoint = endpoint or settings.sast_endpoint
        self.timeout_seconds = timeout_seconds

    async def produce_static_evidence(self, case: PaperCaseCreateRequest) -> tuple[dict[str, Any], dict[str, Any]]:
        request = build_s4_request(case)
        if case.producerArtifacts.s4StaticEvidencePath:
            data = read_json(case.producerArtifacts.s4StaticEvidencePath)
        else:
            url = f"{self.endpoint.rstrip('/')}/v1/paper/static-evidence"
            try:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.post(url, json=request)
            except httpx.HTTPError as exc:
                raise PaperOperationalError(f"S4 static-evidence transport failure: {exc}") from exc
            if response.status_code >= 400:
                raise PaperOperationalError(
                    f"S4 static-evidence HTTP {response.status_code}",
                    detail={"statusCode": response.status_code, "body": response.text[:1000]},
                )
            data = response.json()
        validate_s4_bundle(data, case_id=case.caseId, build_target_id=case.buildTargetId)
        return data, request
