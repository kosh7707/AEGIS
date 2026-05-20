"""Paper-facing projection service over real S5 Source KG and Threat KB internals."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Callable, Iterable
from typing import Any

from fastapi import HTTPException

from app.ledger.repository import SQLiteLedgerRepository
from app.paper_context.models import (
    BasePaperRequest,
    PrepareCodeKbRequest,
    RetrieveFindingContextRequest,
    RetrieveGenericThreatContextRequest,
    SourceAnchor,
    SourceKgSelectors,
)
from app.source_kg.service import ingest_source_kg
from app.threat_retrieval.evidence import build_threat_retrieval_evidence

FORBIDDEN_LEAKAGE_CLASSES = {"cve_id", "fix_commit", "advisory", "exploit_writeup", "patch_text"}
PAPER_CONTEXT_CONTRACT_VERSION = "s5-paper-context-api-v1"
SOURCE_KG_CONTRACT_VERSION = "source-code-kg-ingest-v1"
SOURCE_KG_CONTEXT_VERSION = "source-code-kg-context-v1"
THREAT_RETRIEVAL_VERSION = "s5-threat-retrieval-evidence-v1"
RETRIEVAL_POLICY_VERSION = "s5-paper-retrieval-policy-v1"
GENERIC_THREAT_POLICY_VERSION = "s5-paper-generic-threat-policy-v1"

_LEAKAGE_PATTERNS = [
    re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
    re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE),
    re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE),
    re.compile(r"advisory", re.IGNORECASE),
    re.compile(r"exploit\s+writeup", re.IGNORECASE),
    re.compile(r"patch\s+text", re.IGNORECASE),
]
_AUTHORITY_TEXT_PATTERNS = [
    re.compile(r"\b(TP|FP|UNKNOWN)\b"),
    re.compile(r"\btrue\s+positive\b", re.IGNORECASE),
    re.compile(r"\bfalse\s+positive\b", re.IGNORECASE),
    re.compile(r"\bvulnerable\b", re.IGNORECASE),
    re.compile(r"\bsafe\b", re.IGNORECASE),
    re.compile(r"\bclean\b", re.IGNORECASE),
    re.compile(r"\bnot\s+affected\b", re.IGNORECASE),
    re.compile(r"\baffected\b", re.IGNORECASE),
    re.compile(r"\bexploitability\s+proven\b", re.IGNORECASE),
    re.compile(r"\babsence\s+evidence\b", re.IGNORECASE),
]

_idempotency_cache: dict[tuple[str, str], dict[str, Any]] = {}
IDEMPOTENCY_PROVIDER = "s5-paper-context-idempotency"
IDEMPOTENCY_RECORD_SCHEMA_VERSION = "s5-paper-idempotency-record-v1"


def reset_paper_context_state() -> None:
    _idempotency_cache.clear()


def paper_http_error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code, {"message": message, "code": code, "reason": code})


def _stable_id(prefix: str, *parts: Any, length: int = 16) -> str:
    payload = json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return f"{prefix}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:length]}"


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _fingerprint(req: BasePaperRequest) -> str:
    data = req.model_dump(by_alias=True, exclude_none=True)
    data.pop("requestId", None)
    data.pop("attemptMetadata", None)
    return hashlib.sha256(_canonical_json(data).encode("utf-8")).hexdigest()


def _idempotency_subject(endpoint: str, idempotency_key: str) -> str:
    return f"{endpoint}:{idempotency_key}"


def _load_ledger_idempotency(repo: SQLiteLedgerRepository, endpoint: str, idempotency_key: str) -> dict[str, Any] | None:
    subject = _idempotency_subject(endpoint, idempotency_key)
    observations = [
        obs
        for obs in repo.list_provider_observations(provider=IDEMPOTENCY_PROVIDER)
        if obs.get("subjectKey") == subject and isinstance(obs.get("payload"), dict)
    ]
    if not observations:
        return None
    payload = observations[-1].get("payload") or {}
    if payload.get("schemaVersion") != IDEMPOTENCY_RECORD_SCHEMA_VERSION:
        return None
    return payload


def _record_ledger_idempotency(
    repo: SQLiteLedgerRepository,
    *,
    endpoint: str,
    req: BasePaperRequest,
    fingerprint: str,
    response: dict[str, Any],
    replayed_request_id: str | None = None,
) -> None:
    subject = _idempotency_subject(endpoint, req.idempotency_key)
    payload = {
        "schemaVersion": IDEMPOTENCY_RECORD_SCHEMA_VERSION,
        "endpoint": endpoint,
        "idempotencyKey": req.idempotency_key,
        "fingerprint": fingerprint,
        "response": response,
        "createdByRequestId": response.get("requestId"),
        "lastReplayedRequestId": replayed_request_id,
        "transportRequestIdMutable": True,
        "replayPolicy": "preserve_stable_s5_ids_and_echo_current_request_id",
    }
    repo.record_provider_observation(
        provider=IDEMPOTENCY_PROVIDER,
        subject_key=subject,
        status="replayable",
        payload=payload,
        observation_id=_stable_id("s5-paper-idempotency", endpoint, req.idempotency_key, length=24),
    )


def _replayed_response(stored_response: dict[str, Any], request_id: str) -> dict[str, Any]:
    response = copy.deepcopy(stored_response)
    response["requestId"] = request_id
    return response


def _with_idempotency(
    repo: SQLiteLedgerRepository,
    endpoint: str,
    req: BasePaperRequest,
    compute: Callable[[str], dict[str, Any]],
) -> dict[str, Any]:
    fingerprint = _fingerprint(req)
    key = (endpoint, req.idempotency_key)
    cached = _idempotency_cache.get(key)
    if cached:
        if cached["fingerprint"] != fingerprint:
            raise paper_http_error(
                409,
                "S5_PAPER_IDEMPOTENCY_CONFLICT",
                "Idempotency key was reused with a different normalized paper request.",
            )
        response = _replayed_response(cached["response"], req.request_id)
        _record_ledger_idempotency(repo, endpoint=endpoint, req=req, fingerprint=fingerprint, response=cached["response"], replayed_request_id=req.request_id)
        return response
    repo.initialize()
    ledger_record = _load_ledger_idempotency(repo, endpoint, req.idempotency_key)
    if ledger_record is not None:
        if ledger_record.get("fingerprint") != fingerprint:
            raise paper_http_error(
                409,
                "S5_PAPER_IDEMPOTENCY_CONFLICT",
                "Idempotency key was reused with a different normalized paper request.",
            )
        stored_response = ledger_record.get("response") or {}
        if not isinstance(stored_response, dict):
            raise paper_http_error(500, "S5_PAPER_SCHEMA_INVALID", "Stored idempotency response is malformed.")
        _idempotency_cache[key] = {"fingerprint": fingerprint, "response": copy.deepcopy(stored_response)}
        response = _replayed_response(stored_response, req.request_id)
        _record_ledger_idempotency(repo, endpoint=endpoint, req=req, fingerprint=fingerprint, response=stored_response, replayed_request_id=req.request_id)
        return response
    response = compute(fingerprint)
    _idempotency_cache[key] = {"fingerprint": fingerprint, "response": copy.deepcopy(response)}
    _record_ledger_idempotency(repo, endpoint=endpoint, req=req, fingerprint=fingerprint, response=response)
    return response


def _diagnostic(
    code: str,
    message: str,
    *,
    severity: str = "info",
    surface_status: str = "not_available",
    s3_evidence_refs: list[str] | None = None,
    related_item_ids: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "severity": severity,
        "surfaceStatus": surface_status,
        "consumerPolicy": "diagnostic_only_not_security_evidence",
        "negativeEvidenceAllowed": False,
        "visibleLeakageClass": "generic",
        "relatedItemIds": related_item_ids or [],
        "s3EvidenceRefs": s3_evidence_refs or [],
        "metadata": metadata or {},
    }


def _enforce_common(req: BasePaperRequest, x_request_id: str | None) -> None:
    if x_request_id and x_request_id != req.request_id:
        raise paper_http_error(400, "S5_PAPER_SCHEMA_INVALID", "X-Request-Id must match body requestId.")
    if req.visibility_mode != "generic":
        raise paper_http_error(
            422,
            "S5_PAPER_VISIBILITY_MODE_UNSUPPORTED",
            "S5 paper-context v1 supports only generic visibility mode.",
        )
    if len(req.forbidden_leakage_classes) != len(FORBIDDEN_LEAKAGE_CLASSES) or set(req.forbidden_leakage_classes) != FORBIDDEN_LEAKAGE_CLASSES:
        raise paper_http_error(
            422,
            "S5_PAPER_FORBIDDEN_LEAKAGE_CLASSES_REQUIRED",
            "Mainline paper requests must provide the required forbidden leakage class set.",
        )


def _enforce_prepare_aliases(req: PrepareCodeKbRequest) -> None:
    aliases = {
        "sourceRootRef": (req.source_root_ref, req.producer_input_refs.source_root_ref),
        "compileContextRef": (req.compile_context_ref, req.producer_input_refs.compile_context_ref),
        "buildSnapshotId": (req.build_snapshot_id, req.producer_input_refs.build_snapshot_id),
        "buildUnitId": (req.build_unit_id, req.producer_input_refs.build_unit_id),
    }
    for field, (alias_value, canonical_value) in aliases.items():
        if alias_value is not None and canonical_value is not None and alias_value != canonical_value:
            raise paper_http_error(400, "S5_PAPER_SCHEMA_INVALID", f"{field} alias must match producerInputRefs.{field}.")


def _code_kb_ref(req: BasePaperRequest) -> str:
    return f"s5-code-kb:{req.case_id}:{req.build_target_id}"


def _source_kg_ref(req: BasePaperRequest) -> str:
    return f"s5-source-kg:{req.case_id}:{req.build_target_id}"


def _source_kg_index_ref(req: BasePaperRequest) -> str:
    return f"s5-source-kg-index:{req.paper_run_id}"


def _producer_provenance(
    req: BasePaperRequest,
    *,
    code_kb_ref: str | None = None,
    source_kg_ref: str | None = None,
    source_kg_versions: bool = False,
    threat_versions: bool = False,
) -> dict[str, Any]:
    return {
        "component": "s5-knowledge-base",
        "serviceVersion": "s5-dev",
        "paperContextContractVersion": PAPER_CONTEXT_CONTRACT_VERSION,
        "sourceCodeKgContractVersion": SOURCE_KG_CONTRACT_VERSION if source_kg_versions else None,
        "sourceCodeKgContextVersion": SOURCE_KG_CONTEXT_VERSION if source_kg_versions else None,
        "threatRetrievalContractVersion": THREAT_RETRIEVAL_VERSION if threat_versions else None,
        "retrievalPolicyVersion": RETRIEVAL_POLICY_VERSION if source_kg_versions or threat_versions else None,
        "genericThreatPolicyVersion": GENERIC_THREAT_POLICY_VERSION if threat_versions else None,
        "codeKbRef": code_kb_ref,
        "sourceKgRef": source_kg_ref,
        "sourceKgIndexVersionRef": _source_kg_index_ref(req) if source_kg_versions else None,
        "threatKbCorpusVersion": "s5-threat-kb-corpus-v1" if threat_versions else None,
        "threatKbIndexVersion": "s5-threat-kb-index-v1" if threat_versions else None,
        "visibilityMode": "generic",
    }


def _context_counts(context: dict[str, Any]) -> dict[str, int]:
    return {
        "sourceArtifacts": len(context.get("sourceArtifacts") or []),
        "graphNodes": len(context.get("graphNodes") or []),
        "graphEdges": len(context.get("graphEdges") or []),
        "evidenceSnippets": len(context.get("evidenceSnippets") or []),
        "richIrArtifacts": len(context.get("richIrArtifacts") or []),
    }


def _selectors_from_ingest_result(result: dict[str, Any]) -> SourceKgSelectors:
    ids = result.get("ids") or {}
    return SourceKgSelectors.model_validate(
        {
            "repositorySnapshotId": result.get("repositorySnapshotId"),
            "buildContextId": result.get("buildContextId"),
            "analysisArtifactSetId": result.get("analysisArtifactSetId"),
            "graphNodeIds": ids.get("sourceGraphNodeIds") or [],
            "evidenceSnippetIds": ids.get("evidenceSnippetIds") or [],
            "richIrArtifactIds": ids.get("richIrArtifactIds") or [],
        }
    )


def _resolve_context(repo: SQLiteLedgerRepository, selectors: SourceKgSelectors | None) -> dict[str, Any]:
    if selectors is None or not selectors.has_any():
        return {"resolved": False, "sourceArtifacts": [], "graphNodes": [], "graphEdges": [], "evidenceSnippets": [], "richIrArtifacts": [], "contextResolution": {"diagnostics": []}}
    return repo.get_source_kg_context(**selectors.as_context_kwargs())


def _record_mapping(
    repo: SQLiteLedgerRepository,
    *,
    req: BasePaperRequest,
    code_kb_ref: str,
    source_kg_ref: str,
    selectors: SourceKgSelectors,
    counts: dict[str, int],
    status: str,
) -> None:
    repo.record_provider_observation(
        provider="s5-paper-context",
        subject_key=source_kg_ref,
        status=status,
        payload={
            "schemaVersion": "s5-paper-source-kg-ref-mapping-v1",
            "caseId": req.case_id,
            "buildTargetId": req.build_target_id,
            "paperRunId": req.paper_run_id,
            "codeKbRef": code_kb_ref,
            "sourceKgRef": source_kg_ref,
            "selectors": selectors.as_paper_dict(),
            "counts": counts,
        },
    )


def _mapping_selectors(repo: SQLiteLedgerRepository, source_kg_ref: str) -> SourceKgSelectors | None:
    observations = [
        obs
        for obs in repo.list_provider_observations(provider="s5-paper-context")
        if obs.get("subjectKey") == source_kg_ref and isinstance(obs.get("payload"), dict)
    ]
    if not observations:
        return None
    payload = observations[-1].get("payload") or {}
    selectors = payload.get("selectors")
    if not isinstance(selectors, dict):
        return None
    parsed = SourceKgSelectors.model_validate(selectors)
    return parsed if parsed.has_any() else None


def _sanitize_string(value: str) -> tuple[str, bool]:
    redacted = False
    sanitized = value
    for pattern in _LEAKAGE_PATTERNS:
        new_value = pattern.sub("[redacted]", sanitized)
        redacted = redacted or new_value != sanitized
        sanitized = new_value
    for pattern in _AUTHORITY_TEXT_PATTERNS:
        new_value = pattern.sub("[bounded-context]", sanitized)
        redacted = redacted or new_value != sanitized
        sanitized = new_value
    return sanitized, redacted


def _sanitize_visible(value: Any) -> tuple[Any, int]:
    if isinstance(value, dict):
        redactions = 0
        sanitized: dict[str, Any] = {}
        for key, nested in value.items():
            sanitized_key, key_redacted = _sanitize_string(str(key))
            sanitized_nested, nested_redactions = _sanitize_visible(nested)
            sanitized[sanitized_key] = sanitized_nested
            redactions += (1 if key_redacted else 0) + nested_redactions
        return sanitized, redactions
    if isinstance(value, list):
        redactions = 0
        sanitized_list = []
        for item in value:
            sanitized_item, item_redactions = _sanitize_visible(item)
            sanitized_list.append(sanitized_item)
            redactions += item_redactions
        return sanitized_list, redactions
    if isinstance(value, str):
        sanitized, redacted = _sanitize_string(value)
        return sanitized, 1 if redacted else 0
    return value, 0


def _sanitize_response(response: dict[str, Any]) -> dict[str, Any]:
    sanitized, redaction_count = _sanitize_visible(response)
    assert isinstance(sanitized, dict)
    if redaction_count:
        diagnostics = sanitized.setdefault("diagnostics", [])
        diagnostics.append(
            _diagnostic(
                "S5_PAPER_FORBIDDEN_LEAKAGE_REDACTED",
                "One or more visible fields were redacted by the generic visibility policy.",
                severity="warning",
                surface_status=sanitized.get("surfaceStatus", "partial"),
                metadata={"redactedFieldCount": redaction_count, "redactionReason": "forbidden_leakage_class"},
            )
        )
        if sanitized.get("surfaceStatus") == "produced":
            sanitized["surfaceStatus"] = "partial"
            if "retrievalTrace" in sanitized:
                sanitized["retrievalTrace"]["surfaceStatus"] = "partial"
    return sanitized


def prepare_code_kb(repo: SQLiteLedgerRepository, req: PrepareCodeKbRequest, x_request_id: str | None) -> dict[str, Any]:
    _enforce_common(req, x_request_id)
    _enforce_prepare_aliases(req)

    def compute(fingerprint: str) -> dict[str, Any]:
        repo.initialize()
        code_ref = _code_kb_ref(req)
        source_ref = _source_kg_ref(req)
        diagnostics: list[dict[str, Any]] = []
        selectors: SourceKgSelectors | None = None
        context: dict[str, Any]
        ingest_result: dict[str, Any] | None = None

        if req.source_context.source_kg_ingest_request is not None:
            try:
                ingest_result = ingest_source_kg(repo, req.source_context.source_kg_ingest_request).model_dump(by_alias=True)
            except ValueError as exc:
                raise paper_http_error(422, "S5_PAPER_SCHEMA_INVALID", str(exc)) from exc
            selectors = _selectors_from_ingest_result(ingest_result)
            context = _resolve_context(repo, selectors)
        elif req.source_context.source_kg_selectors is not None:
            selectors = req.source_context.source_kg_selectors
            context = _resolve_context(repo, selectors)
        else:
            context = _resolve_context(repo, None)

        counts = _context_counts(context)
        if ingest_result is not None:
            for key, value in (ingest_result.get("counts") or {}).items():
                if key in counts:
                    counts[key] = int(value)
        context_selectable = bool(context.get("resolved")) and (counts["graphNodes"] > 0 or counts["evidenceSnippets"] > 0)
        if context_selectable and selectors is not None:
            status = "produced"
            stage = "ready"
            readiness = {"codeKbReady": True, "sourceKgReady": True, "contextSelectable": True}
            _record_mapping(repo, req=req, code_kb_ref=code_ref, source_kg_ref=source_ref, selectors=selectors, counts=counts, status="ready")
        else:
            status = "not_available"
            stage = "not_ready"
            readiness = {"codeKbReady": False, "sourceKgReady": False, "contextSelectable": False}
            diagnostics.append(
                _diagnostic(
                    "S5_PAPER_SOURCE_KG_NOT_AVAILABLE",
                    "No Source KG rows were available for the requested paper target.",
                    surface_status="not_available",
                )
            )

        response = {
            "schemaVersion": "s5-prepare-code-kb-response-v1",
            "caseId": req.case_id,
            "buildTargetId": req.build_target_id,
            "paperRunId": req.paper_run_id,
            "requestId": req.request_id,
            "idempotencyKey": req.idempotency_key,
            "codeKbRunId": _stable_id("s5-code-kb-run", req.case_id, req.build_target_id, req.idempotency_key, fingerprint),
            "s5ProducerRunId": _stable_id("s5-producer-run-code-kb", req.case_id, req.build_target_id, req.idempotency_key, fingerprint),
            "surfaceStatus": status,
            "stageReadiness": stage,
            "codeKbRef": code_ref,
            "sourceKgRef": source_ref,
            "readiness": {
                **readiness,
                "acceptedSourceRootRef": req.producer_input_refs.source_root_ref,
                "acceptedCompileContextRef": req.producer_input_refs.compile_context_ref,
                "rowCounts": counts,
            },
            "producerProvenance": _producer_provenance(req, code_kb_ref=code_ref, source_kg_ref=source_ref, source_kg_versions=context_selectable),
            "diagnostics": diagnostics,
        }
        if ingest_result is not None:
            response["sourceKgSelectors"] = selectors.as_paper_dict() if selectors else None
        return _sanitize_response(response)

    return _with_idempotency(repo, "prepare_code_kb", req, compute)


def _line_overlap(anchor: SourceAnchor, start: int | None, end: int | None) -> bool:
    if anchor.line_start is None or anchor.line_end is None or start is None or end is None:
        return True
    return max(anchor.line_start, start) <= min(anchor.line_end, end)


def _anchor_score_node(node: dict[str, Any], anchors: list[SourceAnchor]) -> int:
    if not anchors:
        return 1
    best = 0
    for anchor in anchors:
        score = 0
        if anchor.display_path and node.get("filePath") == anchor.display_path:
            score += 5
        if _line_overlap(anchor, node.get("lineStart"), node.get("lineEnd")):
            score += 3
        display = str(node.get("displayName") or "")
        stable = str(node.get("stableId") or "")
        node_id = str(node.get("sourceGraphNodeId") or "")
        if anchor.symbol_name and anchor.symbol_name in {display, stable, node_id}:
            score += 5
        if anchor.function_ref and anchor.function_ref in {display, stable, node_id}:
            score += 2
        best = max(best, score)
    return best


def _anchor_score_snippet(snippet: dict[str, Any], anchors: list[SourceAnchor]) -> int:
    if not anchors:
        return 1
    best = 0
    for anchor in anchors:
        score = 0
        if anchor.display_path and snippet.get("filePath") == anchor.display_path:
            score += 5
        if _line_overlap(anchor, snippet.get("lineStart"), snippet.get("lineEnd")):
            score += 3
        best = max(best, score)
    return best


def _display_ref(record: dict[str, Any]) -> str:
    path = str(record.get("filePath") or "source")
    start = record.get("lineStart")
    end = record.get("lineEnd")
    if start is not None and end is not None:
        return f"{path}:{start}-{end}"
    return path


def _stable_rows_for_finding(
    req: RetrieveFindingContextRequest,
    context: dict[str, Any],
    *,
    retrieval_run_id: str,
    row_set_id: str,
    s5_producer_run_id: str,
) -> tuple[list[dict[str, Any]], int]:
    anchors = req.finding.source_anchors
    scored: list[tuple[int, str, str, dict[str, Any], str]] = []
    for node in context.get("graphNodes") or []:
        score = _anchor_score_node(node, anchors)
        if score > 0:
            scored.append((score, str(node.get("filePath") or ""), str(node.get("sourceGraphNodeId") or ""), node, "node"))
    for snippet in context.get("evidenceSnippets") or []:
        score = _anchor_score_snippet(snippet, anchors)
        if score > 0:
            scored.append((score, str(snippet.get("filePath") or ""), str(snippet.get("evidenceSnippetId") or ""), snippet, "snippet"))
    scored.sort(key=lambda item: (-item[0], item[1], item[2], item[4]))
    selected = scored[: req.top_k]
    rows: list[dict[str, Any]] = []
    for rank, (_score, _path, entity_id, record, kind) in enumerate(selected, start=1):
        item_id = _stable_id("s5-item", row_set_id, kind, entity_id, rank)
        ordering_key = f"{rank:06d}:{item_id}"
        display_ref = _display_ref(record)
        if kind == "node":
            text = f"Source context near {display_ref} references symbol {record.get('displayName') or record.get('stableId') or 'source symbol'}."
            source_type = "symbol"
            source_evidence = {
                "kind": "source_kg_node",
                "ref": f"source-kg-node:{entity_id}",
                "displayRef": display_ref,
                "s3EvidenceRefs": req.finding.s3_evidence_refs,
                "sourceCodeKgRefs": {
                    "codeKbRef": req.code_kb_ref,
                    "sourceKgRef": req.source_kg_ref,
                    "graphNodeIds": [entity_id],
                    "evidenceSnippetIds": [record.get("evidenceSnippetId")] if record.get("evidenceSnippetId") else [],
                },
                "threatKbRefs": None,
            }
        else:
            text = f"Source snippet context is available near {display_ref} for the S3-provided finding anchors."
            source_type = "code"
            source_evidence = {
                "kind": "source_kg_snippet",
                "ref": f"source-kg-snippet:{entity_id}",
                "displayRef": display_ref,
                "s3EvidenceRefs": req.finding.s3_evidence_refs,
                "sourceCodeKgRefs": {
                    "codeKbRef": req.code_kb_ref,
                    "sourceKgRef": req.source_kg_ref,
                    "graphNodeIds": [],
                    "evidenceSnippetIds": [entity_id],
                },
                "threatKbRefs": None,
            }
        rows.append(
            {
                "schemaVersion": "s5-paper-evidence-row-v1",
                "retrievalRunId": retrieval_run_id,
                "itemId": item_id,
                "sourceType": source_type,
                "queryIntent": req.query_intent,
                "sourceEvidence": source_evidence,
                "surfaceStatus": "produced",
                "visibleLeakageClass": "generic",
                "text": text,
                "rank": rank,
                "score": round(min(1.0, _score / 13.0), 4),
                "orderingKey": ordering_key,
                "producerTrace": {
                    "s5ProducerRunId": s5_producer_run_id,
                    "codeKbRef": req.code_kb_ref,
                    "sourceKgRef": req.source_kg_ref,
                    "sourceCodeKgContextVersion": SOURCE_KG_CONTEXT_VERSION,
                    "retrievalPolicyVersion": RETRIEVAL_POLICY_VERSION,
                },
                "diagnostics": [],
            }
        )
    return rows, len(scored)


def retrieve_finding_context(repo: SQLiteLedgerRepository, req: RetrieveFindingContextRequest, x_request_id: str | None) -> dict[str, Any]:
    _enforce_common(req, x_request_id)

    def compute(fingerprint: str) -> dict[str, Any]:
        selectors = req.source_kg_selectors if req.source_kg_selectors and req.source_kg_selectors.has_any() else _mapping_selectors(repo, req.source_kg_ref)
        source_kg_prepared = selectors is not None and selectors.has_any()
        context = _resolve_context(repo, selectors)
        s5_producer_run_id = _stable_id("s5-producer-run-finding", req.case_id, req.finding_id, req.idempotency_key, fingerprint)
        retrieval_run_id = _stable_id("s5-retrieval-run-finding", req.case_id, req.finding_id, req.idempotency_key, fingerprint)
        row_set_id = _stable_id("s5-row-set", req.case_id, req.finding_id, req.idempotency_key, fingerprint)
        rows, candidate_pool_size = (
            _stable_rows_for_finding(
                req,
                context,
                retrieval_run_id=retrieval_run_id,
                row_set_id=row_set_id,
                s5_producer_run_id=s5_producer_run_id,
            )
            if source_kg_prepared and context.get("resolved")
            else ([], 0)
        )
        diagnostics: list[dict[str, Any]] = []
        if not source_kg_prepared:
            status = "not_available"
            diagnostics.append(
                _diagnostic(
                    "S5_PAPER_SOURCE_KG_NOT_PREPARED",
                    "No prepared Source KG mapping or explicit selectors were available for this paper target.",
                    surface_status="not_available",
                    s3_evidence_refs=req.finding.s3_evidence_refs,
                )
            )
        elif not context.get("resolved"):
            status = "not_available"
            diagnostics.append(
                _diagnostic(
                    "S5_PAPER_SOURCE_KG_NOT_AVAILABLE",
                    "Prepared Source KG selectors did not resolve to a selectable Source KG context.",
                    surface_status="not_available",
                    s3_evidence_refs=req.finding.s3_evidence_refs,
                )
            )
        elif rows:
            status = "produced"
        else:
            status = "no_hit"
            diagnostics.append(
                _diagnostic(
                    "S5_PAPER_CONTEXT_NO_HIT",
                    "No source context row matched the S3-provided anchors under the requested profile.",
                    surface_status="no_hit",
                    s3_evidence_refs=req.finding.s3_evidence_refs,
                )
            )
        response = {
            "schemaVersion": "s5-retrieve-finding-context-response-v1",
            "caseId": req.case_id,
            "buildTargetId": req.build_target_id,
            "paperRunId": req.paper_run_id,
            "findingId": req.finding_id,
            "requestId": req.request_id,
            "idempotencyKey": req.idempotency_key,
            "s5ProducerRunId": s5_producer_run_id,
            "retrievalRunId": retrieval_run_id,
            "rowSetId": row_set_id,
            "surfaceStatus": status,
            "rows": rows,
            "retrievalTrace": {
                "queryIntent": req.query_intent,
                "normalizedQuery": "S3-provided source anchors and generic source context request",
                "topK": req.top_k,
                "returnedCount": len(rows),
                "candidatePoolSize": candidate_pool_size,
                "orderingPolicy": "s5-paper-stable-row-order-v1",
                "b2b4StableRows": True,
                "discardedHitReasons": [],
                "methodsAttempted": ["source_anchor", "symbol_neighbor", "cwe_hint"],
                "methodsUsed": ["source_anchor"] if rows else [],
                "sourceKgPrepared": source_kg_prepared,
            },
            "producerProvenance": _producer_provenance(req, code_kb_ref=req.code_kb_ref, source_kg_ref=req.source_kg_ref, source_kg_versions=True),
            "diagnostics": diagnostics,
        }
        return _sanitize_response(response)

    return _with_idempotency(repo, "retrieve_finding_context", req, compute)


def _loads(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        value = json.loads(str(raw))
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _taxonomy_lookup(repo: SQLiteLedgerRepository, table: str, external_ids: Iterable[str]) -> list[dict[str, Any]]:
    wanted = {str(item) for item in external_ids if item}
    if not wanted:
        return []
    rows = []
    for row in repo.fetch_all(table):
        if str(row.get("external_id")) in wanted:
            payload = _loads(row.get("payload_json"))
            rows.append({**row, "payload": payload})
    return rows


def _generic_threat_rows(
    req: RetrieveGenericThreatContextRequest,
    repo: SQLiteLedgerRepository,
    threat: dict[str, Any],
    *,
    retrieval_run_id: str,
    row_set_id: str,
    s5_producer_run_id: str,
) -> tuple[list[dict[str, Any]], int, int]:
    row_specs: list[tuple[str, str, str, str, float]] = []
    for item in threat.get("weaknessSemantics") or []:
        external_id = str(item.get("externalId") or item.get("external_id") or "")
        if external_id:
            text = str(item.get("summary") or item.get("name") or f"{external_id} describes a generic software weakness relevant to the requested context.")
            row_specs.append(("cwe", external_id, f"cwe:{external_id}", text, 0.91))
    for item in threat.get("attackSemantics") or []:
        external_id = str(item.get("externalId") or item.get("external_id") or "")
        if external_id:
            text = str(item.get("summary") or item.get("name") or f"{external_id} describes a generic attack pattern relevant to the requested context.")
            row_specs.append(("capec", external_id, f"capec:{external_id}", text, 0.84))

    known_refs = {spec[2] for spec in row_specs}
    for row in _taxonomy_lookup(repo, "weakness", req.cwe_candidates):
        external_id = str(row.get("external_id"))
        ref = f"cwe:{external_id}"
        if ref not in known_refs:
            payload = row.get("payload") or {}
            name = payload.get("name") or payload.get("title") or "generic software weakness"
            row_specs.append(("cwe", external_id, ref, f"{external_id} describes {name} as generic weakness taxonomy context.", 0.88))
            known_refs.add(ref)
    for row in _taxonomy_lookup(repo, "attack_pattern", req.capec_candidates):
        external_id = str(row.get("external_id"))
        ref = f"capec:{external_id}"
        if ref not in known_refs:
            payload = row.get("payload") or {}
            name = payload.get("name") or payload.get("title") or "generic attack pattern"
            row_specs.append(("capec", external_id, ref, f"{external_id} describes {name} as generic attack-pattern context.", 0.78))
            known_refs.add(ref)
    for api_name in req.api_names:
        row_specs.append(
            (
                "generic_security_note",
                api_name,
                f"api:{api_name}",
                f"API {api_name} is commonly reviewed with source-level bounds, size, and data-flow context.",
                0.65,
            )
        )

    rows: list[dict[str, Any]] = []
    for rank, (source_type, external_id, node_ref, text, score) in enumerate(row_specs[: req.top_k], start=1):
        item_id = _stable_id("s5-threat-item", row_set_id, node_ref, rank)
        rows.append(
            {
                "schemaVersion": "s5-paper-evidence-row-v1",
                "retrievalRunId": retrieval_run_id,
                "itemId": item_id,
                "sourceType": source_type,
                "queryIntent": req.query_intent,
                "sourceEvidence": {
                    "kind": "threat_kb_node" if source_type != "generic_security_note" else "generic_api_note",
                    "ref": node_ref,
                    "displayRef": f"{external_id} generic context",
                    "s3EvidenceRefs": req.s3_evidence_refs,
                    "sourceCodeKgRefs": None,
                    "threatKbRefs": {
                        "corpusVersion": "s5-threat-kb-corpus-v1",
                        "indexVersion": "s5-threat-kb-index-v1",
                        "nodeRef": node_ref,
                    },
                },
                "surfaceStatus": "produced",
                "visibleLeakageClass": "generic",
                "text": text,
                "rank": rank,
                "score": score,
                "orderingKey": f"{rank:06d}:{item_id}",
                "producerTrace": {
                    "s5ProducerRunId": s5_producer_run_id,
                    "threatKbCorpusVersion": "s5-threat-kb-corpus-v1",
                    "threatKbIndexVersion": "s5-threat-kb-index-v1",
                    "genericThreatPolicyVersion": GENERIC_THREAT_POLICY_VERSION,
                    "retrievalPolicyVersion": RETRIEVAL_POLICY_VERSION,
                },
                "diagnostics": [],
            }
        )
    hidden_count = len(threat.get("candidateEvidence") or []) + len(threat.get("suppressedCandidateEvidence") or []) + len(threat.get("riskSignals") or [])
    candidate_pool_size = int((threat.get("retrievalTrace") or {}).get("candidatePoolSize") or len(row_specs))
    return rows, candidate_pool_size, hidden_count


def retrieve_generic_threat_context(
    repo: SQLiteLedgerRepository,
    req: RetrieveGenericThreatContextRequest,
    x_request_id: str | None,
) -> dict[str, Any]:
    _enforce_common(req, x_request_id)
    if not (req.cwe_candidates or req.capec_candidates or req.api_names or req.library_identity):
        raise paper_http_error(422, "S5_PAPER_SCHEMA_INVALID", "Generic threat context requires at least one query input.")

    def compute(fingerprint: str) -> dict[str, Any]:
        component = req.library_identity.model_dump(by_alias=True, exclude_none=True) if req.library_identity else {}
        threat = build_threat_retrieval_evidence(
            repo,
            component=component,
            affectedness={"evidence": []},
            identity_resolution=None,
            controls={"requested": {"topK": req.top_k}, "accepted": {"topK": req.top_k}},
            query_terms_extra=[*req.cwe_candidates, *req.capec_candidates, *req.api_names],
        )
        s5_producer_run_id = _stable_id("s5-producer-run-threat", req.case_id, req.finding_id, req.idempotency_key, fingerprint)
        retrieval_run_id = _stable_id("s5-retrieval-run-threat", req.case_id, req.finding_id, req.idempotency_key, fingerprint)
        row_set_id = _stable_id("s5-row-set-threat", req.case_id, req.finding_id, req.idempotency_key, fingerprint)
        rows, candidate_pool_size, hidden_count = _generic_threat_rows(
            req,
            repo,
            threat,
            retrieval_run_id=retrieval_run_id,
            row_set_id=row_set_id,
            s5_producer_run_id=s5_producer_run_id,
        )
        diagnostics: list[dict[str, Any]] = []
        status = "produced" if rows else "no_hit"
        if hidden_count:
            diagnostics.append(
                _diagnostic(
                    "S5_PAPER_FORBIDDEN_LEAKAGE_REDACTED",
                    "One or more internal candidates were omitted because they were outside generic Threat KB visibility.",
                    severity="warning",
                    surface_status="partial" if rows else "no_hit",
                    s3_evidence_refs=req.s3_evidence_refs,
                    metadata={"redactedCandidateCount": hidden_count, "redactionReason": "forbidden_leakage_class"},
                )
            )
            if rows:
                status = "partial"
        if not rows:
            diagnostics.append(
                _diagnostic(
                    "S5_PAPER_CONTEXT_NO_HIT",
                    "No generic threat context row was found for the requested CWE, CAPEC, API, or library inputs.",
                    surface_status="no_hit",
                    s3_evidence_refs=req.s3_evidence_refs,
                )
            )
        response = {
            "schemaVersion": "s5-retrieve-generic-threat-context-response-v1",
            "caseId": req.case_id,
            "buildTargetId": req.build_target_id,
            "paperRunId": req.paper_run_id,
            "findingId": req.finding_id,
            "requestId": req.request_id,
            "idempotencyKey": req.idempotency_key,
            "s5ProducerRunId": s5_producer_run_id,
            "retrievalRunId": retrieval_run_id,
            "rowSetId": row_set_id,
            "surfaceStatus": status,
            "rows": rows,
            "retrievalTrace": {
                "queryIntent": req.query_intent,
                "normalizedQuery": "generic CWE CAPEC API library context",
                "topK": req.top_k,
                "returnedCount": len(rows),
                "candidatePoolSize": candidate_pool_size,
                "orderingPolicy": "s5-paper-stable-row-order-v1",
                "b2b4StableRows": True,
                "leakagePolicy": "generic_only_no_hidden_identifiers_or_patch_material",
                "redactedCandidateCount": hidden_count,
                "discardedHitReasons": ["outside_generic_visibility"] if hidden_count else [],
            },
            "producerProvenance": _producer_provenance(req, threat_versions=True),
            "diagnostics": diagnostics,
        }
        return _sanitize_response(response)

    return _with_idempotency(repo, "retrieve_generic_threat_context", req, compute)
