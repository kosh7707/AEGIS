from __future__ import annotations

from typing import Any

import httpx

from app.config import settings

from .artifacts import read_json
from .errors import PaperContractError, PaperOperationalError
from .models import FORBIDDEN_LEAKAGE_CLASSES, PaperCaseCreateRequest
from .validation import validate_s5_contract_snapshot, validate_s5_response


DEFAULT_TIMEOUT_MS = 120_000


def _common(case: PaperCaseCreateRequest, *, schema_version: str, request_id: str, idempotency_key: str) -> dict[str, Any]:
    return {
        "schemaVersion": schema_version,
        "caseId": case.caseId,
        "buildTargetId": case.buildTargetId,
        "paperRunId": case.paperRunId,
        "requestId": request_id,
        "idempotencyKey": idempotency_key,
        "visibilityMode": "generic",
        "forbiddenLeakageClasses": FORBIDDEN_LEAKAGE_CLASSES,
        "producerInputRefs": {
            "sourceRootRef": case.sourceRootRef,
            "compileContextRef": case.compileContextRef,
            "buildSnapshotId": case.buildSnapshotId,
            "buildUnitId": case.buildUnitId,
        },
    }


def build_prepare_code_kb_request(case: PaperCaseCreateRequest) -> dict[str, Any]:
    body = _common(
        case,
        schema_version="s5-prepare-code-kb-request-v1",
        request_id=f"{case.caseId}:s5:prepare-code-kb:attempt-1",
        idempotency_key=f"{case.caseId}:{case.buildTargetId}:s5:prepare-code-kb:v1",
    )
    body.update(
        {
            "sourceRootRef": case.sourceRootRef,
            "compileContextRef": case.compileContextRef,
            "sourceContext": {
                "sourceRoot": case.sourceRoot,
                "compileCommandsPath": case.compileCommandsPath,
                "language": "c/cpp",
                "scope": case.scope.model_dump(mode="json"),
            },
        }
    )
    return body


def build_finding_context_request(
    case: PaperCaseCreateRequest,
    *,
    finding: dict[str, Any],
    code_kb_ref: str,
    source_kg_ref: str,
) -> dict[str, Any]:
    finding_id = finding["findingId"]
    body = _common(
        case,
        schema_version="s5-retrieve-finding-context-request-v1",
        request_id=f"{case.caseId}:{finding_id}:s5:finding-context:attempt-1",
        idempotency_key=f"{case.caseId}:{finding_id}:s5:finding-context:v1",
    )
    body.update(
        {
            "findingId": finding_id,
            "codeKbRef": code_kb_ref,
            "sourceKgRef": source_kg_ref,
            "finding": {
                "findingId": finding_id,
                "s3EvidenceRefs": [f"s3-evidence:s4:finding:{finding_id}"],
                "sourceAnchors": [
                    {
                        "displayPath": (finding.get("location") or {}).get("path"),
                        "lineStart": (finding.get("location") or {}).get("startLine"),
                        "lineEnd": (finding.get("location") or {}).get("endLine"),
                        "functionRef": finding.get("functionId"),
                    }
                ],
                "ruleId": finding.get("ruleId"),
                "cweCandidates": finding.get("cweCandidates", []),
                "toolMessage": finding.get("message"),
                "libraryIdentity": finding.get("libraryIdentity"),
            },
            "queryIntent": "finding_local_context",
            "retrievalProfile": "paper-code-context-default-v1",
            "topK": 5,
        }
    )
    return body


def build_generic_threat_request(case: PaperCaseCreateRequest, *, finding: dict[str, Any]) -> dict[str, Any]:
    finding_id = finding["findingId"]
    body = _common(
        case,
        schema_version="s5-retrieve-generic-threat-context-request-v1",
        request_id=f"{case.caseId}:{finding_id}:s5:generic-threat:attempt-1",
        idempotency_key=f"{case.caseId}:{finding_id}:s5:generic-threat:v1",
    )
    body.update(
        {
            "findingId": finding_id,
            "s3EvidenceRefs": [f"s3-evidence:s4:finding:{finding_id}"],
            "cweCandidates": finding.get("cweCandidates", []),
            "capecCandidates": [],
            "apiNames": [],
            "libraryIdentity": finding.get("libraryIdentity"),
            "queryIntent": "generic_threat_context",
            "retrievalProfile": "paper-generic-threat-default-v1",
            "topK": 5,
        }
    )
    if not body["cweCandidates"] and not body["apiNames"] and not body.get("libraryIdentity"):
        body["apiNames"] = [str(finding.get("ruleId") or "generic-sast-finding")]
    return body


def validate_prepare_alias_consistency(body: dict[str, Any]) -> None:
    refs = body.get("producerInputRefs") or {}
    for top, nested in [("sourceRootRef", "sourceRootRef"), ("compileContextRef", "compileContextRef")]:
        if top in body and nested in refs and body[top] != refs[nested]:
            raise PaperContractError(f"S5 prepare request alias mismatch for {top}")


class S5PaperClient:
    def __init__(self, endpoint: str | None = None, timeout_ms: int = DEFAULT_TIMEOUT_MS):
        self.endpoint = endpoint or settings.kb_endpoint
        self.timeout_ms = timeout_ms

    async def contract_snapshot(self, case: PaperCaseCreateRequest) -> dict[str, Any] | None:
        if case.producerArtifacts.s5ContractSnapshotPath:
            data = read_json(case.producerArtifacts.s5ContractSnapshotPath)
            validate_s5_contract_snapshot(data)
            return data
        # Contract snapshot is useful but live S5 may not implement it yet in first tests.
        return None

    async def prepare_code_kb(self, case: PaperCaseCreateRequest) -> tuple[dict[str, Any], dict[str, Any]]:
        body = build_prepare_code_kb_request(case)
        validate_prepare_alias_consistency(body)
        if case.producerArtifacts.s5CodeKbPath:
            data = read_json(case.producerArtifacts.s5CodeKbPath)
        else:
            data = await self._post("/v1/paper/code-kb/prepare", body)
        self._validate_common(data, case)
        if not _prepare_response_is_context_selectable(data):
            raise PaperOperationalError(
                "S5 code KB is not ready for finding-context retrieval",
                detail={
                    "surfaceStatus": data.get("surfaceStatus"),
                    "stageReadiness": data.get("stageReadiness"),
                },
            )
        return data, body

    async def retrieve_finding_context(self, case: PaperCaseCreateRequest, *, finding: dict[str, Any], code_kb_ref: str, source_kg_ref: str) -> tuple[dict[str, Any], dict[str, Any]]:
        body = build_finding_context_request(case, finding=finding, code_kb_ref=code_kb_ref, source_kg_ref=source_kg_ref)
        path = case.producerArtifacts.s5FindingContextByFindingId.get(finding["findingId"])
        if path:
            data = read_json(path)
        else:
            data = await self._post("/v1/paper/finding-context/retrieve", body)
        validate_s5_response(data, expected_case_id=case.caseId, expected_build_target_id=case.buildTargetId)
        return data, body

    async def retrieve_generic_threat_context(self, case: PaperCaseCreateRequest, *, finding: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        body = build_generic_threat_request(case, finding=finding)
        path = case.producerArtifacts.s5GenericThreatContextByFindingId.get(finding["findingId"])
        if path:
            data = read_json(path)
        else:
            data = await self._post("/v1/paper/threat-context/generic", body)
        validate_s5_response(data, expected_case_id=case.caseId, expected_build_target_id=case.buildTargetId)
        return data, body

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        if body.get("visibilityMode") != "generic":
            raise PaperContractError("S5 paper requests must use visibilityMode=generic")
        headers = {"X-Timeout-Ms": str(self.timeout_ms), "X-Request-Id": body["requestId"]}
        url = f"{self.endpoint.rstrip('/')}{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_ms / 1000) as client:
                response = await client.post(url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise PaperOperationalError(f"S5 transport failure: {exc}") from exc
        if response.status_code >= 400:
            raise PaperOperationalError(
                f"S5 HTTP {response.status_code}",
                detail={"statusCode": response.status_code, "body": response.text[:1000]},
            )
        return response.json()

    def _validate_common(self, data: dict[str, Any], case: PaperCaseCreateRequest) -> None:
        if data.get("caseId") != case.caseId or data.get("buildTargetId") != case.buildTargetId:
            raise PaperContractError("S5 response case/buildTarget identity mismatch")
        status = data.get("surfaceStatus")
        if status not in {"produced", "partial", "not_available", "error"}:
            raise PaperContractError("S5 prepare response surfaceStatus is unknown")
        readiness = data.get("stageReadiness")
        if readiness not in {"ready", "ready_with_diagnostics", "not_ready"}:
            raise PaperContractError("S5 prepare response stageReadiness is unknown")
        for diag in data.get("diagnostics", []) or []:
            if diag.get("negativeEvidenceAllowed") is not False:
                raise PaperContractError("S5 diagnostics must set negativeEvidenceAllowed=false")


def _prepare_response_is_context_selectable(data: dict[str, Any]) -> bool:
    status = data.get("surfaceStatus")
    readiness = data.get("stageReadiness")
    context_selectable = bool((data.get("readiness") or {}).get("contextSelectable"))
    if status == "produced" and readiness == "ready" and context_selectable:
        return True
    if status == "partial" and readiness == "ready_with_diagnostics" and context_selectable:
        return True
    return False
