"""Target context API — S3 target-aware acquisition v1 surfaces."""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, Body, Header, HTTPException

from app.context import set_request_id
from app.contracts.acquisition import (
    ACQUISITION_READINESS_CONTRACT_VERSION,
    KNOWLEDGE_COVERAGE_CONTRACT_VERSION,
    apply_no_hit_safety,
    runtime_semantics_metadata,
)
from app.cve.acquisition_split import (
    CANDIDATE_RANGE_OUT_FORBIDDEN_INFERENCES,
    candidate_methods,
    cve_ids,
    cve_method_plan,
    normalize_cve_id,
    provider_methods_succeeded,
)
from app.graphrag.retrieval_planner import unsafe_no_hit_basis_from_trace
from app.projections.ledger_projection import (
    NEO4J_THREAT_PROJECTION,
    QDRANT_THREAT_PROJECTION,
    SCOPE_KEY as THREAT_PROJECTION_SCOPE,
)
from app.target_context_service import TargetContextStoreError
from app.timeout import check_deadline, parse_timeout, run_async_with_deadline, run_sync_with_deadline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/target-contexts", tags=["target-contexts"])

_target_context_service = None
_code_graph_service = None
_code_vector_search = None
_code_assembler = None
_knowledge_assembler = None
_nvd_client = None
_ledger_repository = None

_CODE_GRAPH_PROJECTION = "neo4j-code-graph"
_CODE_VECTOR_PROJECTION = "qdrant-code-functions"
_UNSAFE_PROJECTION_STATES = {"timeout", "error", "failed", "stale", "debt", "projection_debt", "partial"}


def set_target_context_service(service) -> None:
    global _target_context_service
    _target_context_service = service


def set_code_graph_service(service) -> None:
    global _code_graph_service
    _code_graph_service = service


def set_code_vector_search(service) -> None:
    global _code_vector_search
    _code_vector_search = service


def set_code_assembler(assembler) -> None:
    global _code_assembler
    _code_assembler = assembler


def set_knowledge_assembler(assembler) -> None:
    global _knowledge_assembler
    _knowledge_assembler = assembler


def set_nvd_client(client) -> None:
    global _nvd_client
    _nvd_client = client


def set_ledger_repository(repo) -> None:
    global _ledger_repository
    _ledger_repository = repo


def _require_target_context_service():
    if _target_context_service is None:
        raise HTTPException(503, "Target context service not initialized")


def _elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _camel(source: dict[str, Any] | None, *keys: str) -> Any:
    if not isinstance(source, dict):
        return None
    for key in keys:
        if key in source and source[key] not in (None, ""):
            return source[key]
    return None


def _provenance_from_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    prov = bundle.get("provenance") if isinstance(bundle.get("provenance"), dict) else {}
    out = {
        "projectId": _camel(bundle, "projectId", "project_id"),
        "buildSnapshotId": _camel(prov, "buildSnapshotId", "build_snapshot_id"),
        "buildUnitId": _camel(prov, "buildUnitId", "build_unit_id"),
        "sourceBuildAttemptId": _camel(prov, "sourceBuildAttemptId", "source_build_attempt_id"),
    }
    return {k: v for k, v in out.items() if v is not None}


def _base_envelope(
    *,
    surface: str,
    acquisition_status: str,
    quality_gate: str,
    consumer_policy: str,
    target_knowledge_id: str | None = None,
    target_context_version: int | None = None,
    acquisition_id: str | None = None,
    primary_method: str | None = None,
    methods_attempted: list[str] | None = None,
    methods_succeeded: list[str] | None = None,
    fallback_trace: list[dict[str, Any]] | None = None,
    diagnostics: list[dict[str, Any]] | None = None,
    scope: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
    results: dict[str, Any] | None = None,
    item_acquisitions: list[dict[str, Any]] | None = None,
    source_evidence_refs: list[str] | None = None,
    derived_from_evidence_refs: list[str] | None = None,
    provider_state: dict[str, Any] | None = None,
    projection_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    provider_state = provider_state or {"state": "not_applicable"}
    projection_state = projection_state or {"state": "not_applicable"}
    readiness = {
        "scope": scope or {},
        "requiredInputs": [],
        "missingInputs": [],
        "providerState": provider_state,
        "projectionState": projection_state,
        "methodsRequiredForNoHit": (scope or {}).get("methodsRequiredForNoHit", []),
        "methodsAttempted": methods_attempted or [],
        "methodsSucceeded": methods_succeeded or [],
        "fallbackPolicy": "fallback_must_be_explicit_and_traced",
        "retryGuidance": "retry_after_missing_inputs_or_provider_projection_state_changes",
        "diagnostics": diagnostics or [],
    }
    envelope = {
        "schemaVersion": "acquisition-envelope-v1",
        "coverageContractVersion": KNOWLEDGE_COVERAGE_CONTRACT_VERSION,
        "readinessContractVersion": ACQUISITION_READINESS_CONTRACT_VERSION,
        "runtimeSemantics": runtime_semantics_metadata(),
        "targetKnowledgeId": target_knowledge_id,
        "targetContextVersion": target_context_version,
        "acquisitionId": acquisition_id,
        "surface": surface,
        "acquisitionStatus": acquisition_status,
        "acquisitionQualityGate": quality_gate,
        "consumerPolicy": consumer_policy,
        "primaryMethod": primary_method,
        "methodsAttempted": methods_attempted or [],
        "methodsSucceeded": methods_succeeded or [],
        "fallbackTrace": fallback_trace or [],
        "diagnostics": diagnostics or [],
        "providerState": provider_state,
        "projectionState": projection_state,
        "readiness": readiness,
        "scope": scope or {},
        "provenance": provenance or {},
        "sourceEvidenceRefs": source_evidence_refs or [],
        "derivedFromEvidenceRefs": derived_from_evidence_refs or [],
        "results": results or {},
        "itemAcquisitions": item_acquisitions or [],
    }
    return apply_no_hit_safety(envelope)


def _diagnostic(code: str, message: str, **extra: Any) -> dict[str, Any]:
    item = {"code": code, "message": message}
    item.update({k: v for k, v in extra.items() if v is not None})
    return item


def _context_lookup(target_knowledge_id: str) -> dict[str, Any]:
    _require_target_context_service()
    context = _target_context_service.get(target_knowledge_id)
    if context is None:
        raise HTTPException(404, f"Target context '{target_knowledge_id}' not found")
    return context


def _code_graph_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    cg = bundle.get("codeGraph") if isinstance(bundle.get("codeGraph"), dict) else {}
    return cg


def _list_param(source: dict[str, Any], *keys: str) -> list[str] | None:
    value = _camel(source, *keys)
    if value is None:
        return None
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _bool_param(source: dict[str, Any], *keys: str) -> bool | None:
    value = _camel(source, *keys)
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _trace_list(trace: dict[str, Any], key: str, default: list[str]) -> list[str]:
    if key in trace and isinstance(trace.get(key), list):
        return list(trace.get(key) or [])
    return list(default)


def _retrieval_trace_diagnostics(
    trace: dict[str, Any],
    *,
    status: str,
    methods_succeeded: list[str],
) -> list[dict[str, Any]]:
    if status != "completed_no_hit":
        return []
    if not trace:
        return [_diagnostic(
            "NO_HIT_TRACE_MISSING",
            "completed_no_hit requires a retrievalTrace with explicit method success observations",
        )]
    if "methodsSucceeded" not in trace or not isinstance(trace.get("methodsSucceeded"), list):
        return [_diagnostic(
            "NO_HIT_TRACE_METHOD_SUCCESS_MISSING",
            "completed_no_hit requires retrievalTrace.methodsSucceeded as an explicit list",
        )]
    if not methods_succeeded:
        return [_diagnostic(
            "NO_HIT_METHOD_SUCCESS_EMPTY",
            "completed_no_hit requires at least one completed non-weak required method",
        )]
    return []


def _projection_ledger():
    if _ledger_repository is not None:
        return _ledger_repository
    return getattr(_target_context_service, "_ledger", None)


def _compact_projection_state(row: dict[str, Any] | None, *, projection_name: str, scope_key: str) -> dict[str, Any]:
    if row is None:
        return {
            "projectionName": projection_name,
            "scopeKey": scope_key,
            "state": "not_recorded",
        }
    return {
        "projectionName": row.get("projectionName"),
        "scopeKey": row.get("scopeKey"),
        "state": row.get("state"),
        "sourceHash": row.get("sourceHash"),
        "projectionVersion": row.get("projectionVersion"),
        "debt": row.get("debt", {}),
        "freshness": row.get("freshness", {}),
        "updatedAt": row.get("updatedAt"),
    }


def _ledger_projection_state(
    *,
    surface: str,
    dependencies: list[tuple[str, str]],
    default_ready_reason: str,
) -> dict[str, Any]:
    ledger = _projection_ledger()
    if ledger is None:
        return {"state": "ready", "surface": surface, "source": "runtime_default", "reason": default_ready_reason}

    states = []
    for projection_name, scope_key in dependencies:
        states.append(_compact_projection_state(
            ledger.get_projection_state(projection_name, scope_key),
            projection_name=projection_name,
            scope_key=scope_key,
        ))

    recorded = [state for state in states if state["state"] != "not_recorded"]
    if not recorded:
        return {
            "state": "ready",
            "surface": surface,
            "source": "runtime_default",
            "reason": default_ready_reason,
            "dependencies": states,
        }

    for unsafe in ("failed", "debt", "projection_debt", "stale", "partial", "timeout", "error"):
        if any(state.get("state") == unsafe for state in recorded):
            return {
                "state": unsafe,
                "surface": surface,
                "source": "ledger",
                "dependencies": states,
            }
    if all(state.get("state") in {"ready", "synced"} for state in recorded):
        return {
            "state": "ready",
            "surface": surface,
            "source": "ledger",
            "dependencies": states,
        }
    return {
        "state": "partial",
        "surface": surface,
        "source": "ledger",
        "dependencies": states,
    }


def _threat_projection_state() -> dict[str, Any]:
    return _ledger_projection_state(
        surface="semanticThreatRetrieval",
        dependencies=[
            (NEO4J_THREAT_PROJECTION, THREAT_PROJECTION_SCOPE),
            (QDRANT_THREAT_PROJECTION, THREAT_PROJECTION_SCOPE),
        ],
        default_ready_reason="knowledge assembler is initialized but no ledger projection state is recorded",
    )


def _code_search_projection_state(project_id: str) -> dict[str, Any]:
    return _ledger_projection_state(
        surface="semanticCodeRetrieval",
        dependencies=[
            (_CODE_GRAPH_PROJECTION, project_id),
            (_CODE_VECTOR_PROJECTION, project_id),
        ],
        default_ready_reason="code assembler is initialized but no ledger projection state is recorded",
    )


def _dangerous_callers_projection_state(project_id: str) -> dict[str, Any]:
    return _ledger_projection_state(
        surface="dangerousCallerTraversal",
        dependencies=[(_CODE_GRAPH_PROJECTION, project_id)],
        default_ready_reason="code graph service is initialized but no ledger projection state is recorded",
    )


def _is_timeout_exception(exc: Exception) -> bool:
    return isinstance(exc, HTTPException) and exc.status_code == 408


async def _persist_code_graph_if_present(
    ingest_result: dict[str, Any],
    deadline: float,
) -> dict[str, Any] | None:
    bundle = ingest_result.get("normalizedBundle") or {}
    code_graph = _code_graph_bundle(bundle)
    functions = code_graph.get("functions") if isinstance(code_graph.get("functions"), list) else []
    if not functions:
        return None

    item_key = code_graph.get("projectId") or ingest_result.get("targetKnowledgeId") or "codeGraph"
    if _code_graph_service is None:
        return {
            "itemKey": item_key,
            "itemType": "codeGraph",
            "acquisitionStatus": "not_ready",
            "acquisitionQualityGate": "rejected",
            "consumerPolicy": "do_not_use_as_negative_evidence",
            "scope": {"functionCount": len(functions)},
            "diagnostics": [_diagnostic("CODE_GRAPH_NOT_READY", "Code graph service is not initialized")],
            "fallbackTrace": [],
            "sourceEvidenceRefs": [],
            "derivedFromEvidenceRefs": [],
            "results": {},
        }

    provenance = bundle.get("provenance") if isinstance(bundle.get("provenance"), dict) else None
    project_id = str(item_key)
    try:
        check_deadline(deadline, "target-context-code-graph-projection")
        graph_result = await run_sync_with_deadline(
            deadline,
            "target-context-code-graph-projection",
            _code_graph_service.ingest,
            project_id,
            functions,
            provenance=provenance,
        )
        check_deadline(deadline, "target-context-code-vector-projection")
        vector_count = 0
        if _code_vector_search is not None:
            vector_count = await run_sync_with_deadline(
                deadline,
                "target-context-code-vector-projection",
                _code_vector_search.ingest,
                project_id,
                functions,
                provenance=provenance,
            )
        node_count = int(graph_result.get("nodeCount", 0))
        status = "completed_hit" if node_count > 0 else "completed_no_hit"
        gate = (
            "accepted"
            if node_count > 0 and _code_vector_search is not None and vector_count >= len(functions)
            else "accepted_with_caveats"
        )
        diagnostics = []
        if _code_vector_search is None:
            diagnostics.append(_diagnostic("CODE_VECTOR_UNAVAILABLE", "Code vector index is not initialized"))
        elif vector_count < len(functions):
            diagnostics.append(_diagnostic("CODE_VECTOR_INCOMPLETE", "Not all functions were vector-indexed", vectorCount=vector_count, expected=len(functions)))
        return {
            "itemKey": project_id,
            "itemType": "codeGraph",
            "acquisitionStatus": status,
            "acquisitionQualityGate": gate,
            "consumerPolicy": "s3_may_derive_local_support_if_refs_validate",
            "scope": {"functionCount": len(functions), "projectId": project_id},
            "diagnostics": diagnostics,
            "fallbackTrace": [],
            "sourceEvidenceRefs": [],
            "derivedFromEvidenceRefs": [
                f.get("evidenceRefId") for f in functions if isinstance(f, dict) and f.get("evidenceRefId")
            ],
            "results": {**graph_result, "vectorCount": vector_count},
        }
    except HTTPException as exc:
        if not _is_timeout_exception(exc):
            raise
        logger.warning("target context code graph projection exceeded deadline")
        return {
            "itemKey": project_id,
            "itemType": "codeGraph",
            "acquisitionStatus": "timeout",
            "acquisitionQualityGate": "inconclusive",
            "consumerPolicy": "do_not_use_as_negative_evidence",
            "scope": {
                "functionCount": len(functions),
                "projectId": project_id,
                "graphProjectionReady": False,
            },
            "diagnostics": [
                _diagnostic(
                    "TARGET_CONTEXT_GRAPH_PROJECTION_TIMEOUT",
                    "Target-context code graph projection exceeded caller deadline",
                )
            ],
            "fallbackTrace": [],
            "sourceEvidenceRefs": [],
            "derivedFromEvidenceRefs": [
                f.get("evidenceRefId") for f in functions if isinstance(f, dict) and f.get("evidenceRefId")
            ],
            "results": {"projectionState": "timeout", "vectorCount": 0},
        }
    except Exception as exc:  # defensive: envelope must explain acquisition failure
        logger.exception("target context code graph persistence failed")
        return {
            "itemKey": project_id,
            "itemType": "codeGraph",
            "acquisitionStatus": "incomplete_acquisition",
            "acquisitionQualityGate": "inconclusive",
            "consumerPolicy": "diagnostic_only",
            "scope": {"functionCount": len(functions), "projectId": project_id, "graphProjectionReady": False},
            "diagnostics": [_diagnostic("CODE_GRAPH_PERSIST_FAILED", str(exc))],
            "fallbackTrace": [],
            "sourceEvidenceRefs": [],
            "derivedFromEvidenceRefs": [],
            "results": {"projectionState": "incomplete"},
        }


@router.post("")
async def ingest_target_context(
    bundle: dict[str, Any] = Body(...),
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict[str, Any]:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    start = time.monotonic()
    _require_target_context_service()

    try:
        ingest_result = await run_sync_with_deadline(
            deadline,
            "target-context-ingest",
            _target_context_service.ingest,
            bundle,
        )
    except TargetContextStoreError as exc:
        raise HTTPException(503, f"Target context ledger storage failed: {exc}") from exc

    if not ingest_result.get("ok"):
        envelope = _base_envelope(
            surface="target-context-ingest",
            acquisition_status="input_insufficient",
            quality_gate="rejected",
            consumer_policy="do_not_use",
            acquisition_id=ingest_result.get("targetContextIngestId"),
            primary_method="target_context_validate",
            methods_attempted=["target_context_validate"],
            methods_succeeded=[],
            diagnostics=[
                _diagnostic(
                    "TARGET_IDENTITY_INSUFFICIENT",
                    "Target context identity is insufficient; S5 will not use global defaults",
                    missingFields=ingest_result.get("missingFields", []),
                )
            ],
            scope={"inputHash": ingest_result.get("targetContextInputHash")},
            provenance={},
            results={
                "targetContextInputHash": ingest_result.get("targetContextInputHash"),
                "missingFields": ingest_result.get("missingFields", []),
            },
        )
        return {**envelope, "latency_ms": _elapsed_ms(start)}

    item_acquisitions = []
    code_graph_item = await _persist_code_graph_if_present(ingest_result, deadline)
    if code_graph_item is not None:
        item_acquisitions.append(code_graph_item)

    status = "completed_hit"
    gate = "accepted"
    policy = "contextual_only"
    if any(item["acquisitionStatus"] == "timeout" for item in item_acquisitions):
        status = "timeout"
        gate = "inconclusive"
        policy = "do_not_use_as_negative_evidence"
    elif any(item["acquisitionStatus"] in {"not_ready", "error", "incomplete_acquisition"} for item in item_acquisitions):
        status = "incomplete_acquisition"
        gate = "inconclusive"
        policy = "diagnostic_only"
    elif any(item.get("acquisitionQualityGate") != "accepted" for item in item_acquisitions):
        gate = "accepted_with_caveats"

    diagnostics = list(ingest_result.get("diagnostics", [])) + [
        diag
        for item in item_acquisitions
        for diag in item.get("diagnostics", [])
        if item.get("acquisitionStatus") not in {"completed_hit", "completed_no_hit"}
    ]
    envelope = _base_envelope(
        surface="target-context-ingest",
        acquisition_status=status,
        quality_gate=gate,
        consumer_policy=policy,
        target_knowledge_id=ingest_result.get("targetKnowledgeId"),
        target_context_version=ingest_result.get("targetContextVersion"),
        acquisition_id=ingest_result.get("targetContextIngestId"),
        primary_method="target_context_store",
        methods_attempted=["target_context_validate", "target_context_store"],
        methods_succeeded=["target_context_validate", "target_context_store"],
        diagnostics=diagnostics,
        scope={
            "inputHash": ingest_result.get("targetContextInputHash"),
            "targetId": (ingest_result.get("identity") or {}).get("targetId"),
        },
        provenance=_provenance_from_bundle(ingest_result.get("normalizedBundle") or {}),
        results={
            "targetKnowledgeId": ingest_result.get("targetKnowledgeId"),
            "targetContextVersion": ingest_result.get("targetContextVersion"),
            "targetContextIngestId": ingest_result.get("targetContextIngestId"),
            "targetContextInputHash": ingest_result.get("targetContextInputHash"),
            "reused": bool(ingest_result.get("reused")),
            "storage": ingest_result.get("storage", {}),
            "projectionReady": all(
                item.get("acquisitionQualityGate") == "accepted"
                for item in item_acquisitions
            ),
        },
        item_acquisitions=item_acquisitions,
    )
    logger.info(
        "Target context ingest",
        extra={"_extra": {
            "targetKnowledgeId": envelope["targetKnowledgeId"],
            "targetContextVersion": envelope["targetContextVersion"],
            "status": envelope["acquisitionStatus"],
            "latencyMs": _elapsed_ms(start),
        }},
    )
    return {**envelope, "latency_ms": _elapsed_ms(start)}


def _libraries_from_context(context: dict[str, Any], request_body: dict[str, Any] | None) -> list[dict[str, Any]]:
    if isinstance(request_body, dict) and isinstance(request_body.get("libraries"), list):
        return [lib for lib in request_body["libraries"] if isinstance(lib, dict)]
    bundle = context.get("bundle") or {}
    libs = bundle.get("libraries") if isinstance(bundle.get("libraries"), list) else []
    return [lib for lib in libs if isinstance(lib, dict)]


def _method_plan(lib: dict[str, Any]) -> tuple[str, list[str], list[dict[str, Any]]]:
    plan = cve_method_plan(lib)
    return plan["primaryMethod"], plan["methodsAttempted"], plan["fallbackTrace"]


def _method_requirements(lib: dict[str, Any]) -> dict[str, Any]:
    return cve_method_plan(lib)


def _library_key(lib: dict[str, Any]) -> str:
    name = _camel(lib, "name") or "<unknown>"
    version = _camel(lib, "version") or "<unknown>"
    return f"{name}@{version}"


def _annotate_cve_reasons(cves: list[dict[str, Any]], primary_method: str) -> list[dict[str, Any]]:
    annotated = []
    for cve in cves:
        item = dict(cve)
        if "versionMatchReason" not in item:
            version_match = item.get("version_match")
            source = item.get("source")
            if source == "osv" and version_match is True:
                reason = "osv_commit_match"
            elif version_match is True:
                reason = "matched_nvd_cpe_range"
            elif version_match is False:
                reason = "outside_nvd_cpe_range"
            elif primary_method == "nvd_keyword":
                reason = "keyword_only_unverifiable"
            else:
                reason = "no_cpe_version_range"
            item["versionMatchReason"] = reason
        annotated.append(item)
    return annotated


def _item_from_cve_result(lib: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    plan = _method_requirements(lib)
    primary = plan["primaryMethod"]
    attempted = list(plan["methodsAttempted"])
    required_for_no_hit = list(plan["methodsRequiredForNoHit"])
    fallback_trace = list(plan["fallbackTrace"])
    cves = _annotate_cve_reasons(result.get("cves", []) or [], primary)
    library_key = _library_key(lib)
    cache_info = result.get("cacheInfo") if isinstance(result.get("cacheInfo"), dict) else {}

    if cache_info.get("stale") or result.get("stale_cache_only"):
        status = "stale_cache_only"
        gate = "accepted_with_caveats"
        policy = "do_not_use_as_negative_evidence"
    elif result.get("error"):
        status = "incomplete_acquisition"
        gate = "inconclusive"
        policy = "do_not_use_as_negative_evidence"
    elif cves:
        status = "completed_hit"
        gate = "accepted" if primary != "nvd_keyword" else "accepted_with_caveats"
        policy = "contextual_only"
    else:
        if not plan["noHitEligible"]:
            status = "incomplete_acquisition"
            gate = "inconclusive"
            policy = "do_not_use_as_negative_evidence"
        else:
            status = "completed_no_hit"
            gate = "accepted"
            policy = "scoped_no_hit_record_only"

    result_methods_attempted = list(attempted)
    if status == "stale_cache_only":
        result_methods_attempted.append("cache")
        methods_succeeded = ["cache"]
    elif result.get("error"):
        methods_succeeded = []
    else:
        methods_succeeded = provider_methods_succeeded(plan, result, status=status)
    diagnostics = []
    if result.get("error"):
        diagnostics.append(_diagnostic("CVE_ACQUISITION_ERROR", str(result.get("error"))))
    if primary == "nvd_keyword":
        diagnostics.append(_diagnostic("KEYWORD_ONLY_FALLBACK", "CVE lookup used broad keyword fallback"))
    if status == "stale_cache_only":
        diagnostics.append(_diagnostic("STALE_CACHE_ONLY", "Only stale CVE cache data was available"))
        fallback_trace.append({
            "from": "fresh_provider_lookup",
            "to": "cache",
            "reason": "fresh_provider_result_unavailable",
            "confidenceImpact": ["stale_context", "not_negative_evidence"],
        })

    return {
        "itemKey": library_key,
        "itemType": "library",
        "acquisitionStatus": status,
        "acquisitionQualityGate": gate,
        "consumerPolicy": policy,
        "scope": {
            "libraryKey": library_key,
            "methodsRequiredForNoHit": required_for_no_hit,
            "cachePolicy": "stale" if status == "stale_cache_only" else ("fresh" if result.get("cached") else "none"),
            "noHitBasis": plan["noHitBasis"],
            "providerState": {"state": "ready" if status in {"completed_hit", "completed_no_hit"} else status},
        },
        "methodsAttempted": result_methods_attempted,
        "methodsSucceeded": methods_succeeded,
        "providerState": {"state": "ready" if status in {"completed_hit", "completed_no_hit"} else status},
        "projectionState": {"state": "not_applicable"},
        "diagnostics": diagnostics,
        "fallbackTrace": fallback_trace,
        "sourceEvidenceRefs": [str(_camel(lib, "evidenceRefId", "evidenceRefID"))] if _camel(lib, "evidenceRefId", "evidenceRefID") else [],
        "derivedFromEvidenceRefs": [],
        "results": {
            **result,
            "cves": cves,
            "lookupMethodsAttempted": result_methods_attempted,
            "lookupMethodsSucceeded": methods_succeeded,
        },
    }


def _has_conflicting_version_evidence(lib: dict[str, Any]) -> bool:
    version_status = str(_camel(lib, "versionStatus", "version_status") or "").lower()
    if version_status in {"conflict", "conflicting", "ambiguous_conflict"}:
        return True
    version_evidence = lib.get("versionEvidence") or lib.get("version_evidence")
    if isinstance(version_evidence, dict):
        evidence_status = str(_camel(version_evidence, "status", "quality") or "").lower()
        if evidence_status in {"conflict", "conflicting", "ambiguous_conflict"}:
            return True
    diagnostics = lib.get("diagnostics")
    if isinstance(diagnostics, list):
        for diag in diagnostics:
            if not isinstance(diag, dict):
                continue
            code = str(_camel(diag, "code") or "").upper()
            if code in {"CONFLICTING_VERSION_EVIDENCE", "VERSION_CONFLICT"}:
                return True
    return False


def _conflicting_library_item(lib: dict[str, Any]) -> dict[str, Any]:
    _, attempted, fallback_trace = _method_plan(lib)
    return {
        "itemKey": _library_key(lib),
        "itemType": "library",
        "acquisitionStatus": "conflicting_evidence",
        "acquisitionQualityGate": "inconclusive",
        "consumerPolicy": "do_not_use_as_negative_evidence",
        "scope": {"libraryKey": _library_key(lib), "methodsRequiredForNoHit": attempted},
        "diagnostics": [
            _diagnostic(
                "CONFLICTING_VERSION_EVIDENCE",
                "Library version evidence is conflicting; CVE no-hit cannot be established",
            )
        ],
        "fallbackTrace": fallback_trace,
        "sourceEvidenceRefs": [
            str(_camel(lib, "evidenceRefId", "evidenceRefID"))
        ] if _camel(lib, "evidenceRefId", "evidenceRefID") else [],
        "derivedFromEvidenceRefs": [],
        "results": {},
    }


def _invalid_library_item(lib: dict[str, Any], reason: str) -> dict[str, Any]:
    primary, attempted, fallback_trace = _method_plan(lib)
    return {
        "itemKey": _library_key(lib),
        "itemType": "library",
        "acquisitionStatus": "input_insufficient",
        "acquisitionQualityGate": "rejected",
        "consumerPolicy": "do_not_use_as_negative_evidence",
        "scope": {"libraryKey": _library_key(lib), "methodsRequiredForNoHit": attempted},
        "diagnostics": [_diagnostic("LIBRARY_INPUT_INSUFFICIENT", reason)],
        "fallbackTrace": fallback_trace,
        "sourceEvidenceRefs": [],
        "derivedFromEvidenceRefs": [],
        "results": {},
    }


def _provider_failure_item(
    lib: dict[str, Any],
    *,
    status: str,
    code: str,
    message: str,
) -> dict[str, Any]:
    _, attempted, fallback_trace = _method_plan(lib)
    gate = "inconclusive" if status == "timeout" else "rejected"
    return {
        "itemKey": _library_key(lib),
        "itemType": "library",
        "acquisitionStatus": status,
        "acquisitionQualityGate": gate,
        "consumerPolicy": "do_not_use_as_negative_evidence",
        "scope": {"libraryKey": _library_key(lib), "methodsRequiredForNoHit": attempted},
        "diagnostics": [_diagnostic(code, message)],
        "fallbackTrace": fallback_trace,
        "sourceEvidenceRefs": [
            str(_camel(lib, "evidenceRefId", "evidenceRefID"))
        ] if _camel(lib, "evidenceRefId", "evidenceRefID") else [],
        "derivedFromEvidenceRefs": [],
        "results": {"lookupMethodsAttempted": attempted, "lookupMethodsSucceeded": []},
    }


def _nvd_not_ready_item(lib: dict[str, Any]) -> dict[str, Any]:
    plan = _method_requirements(lib)
    return {
        "itemKey": _library_key(lib),
        "itemType": "library",
        "acquisitionStatus": "not_ready",
        "acquisitionQualityGate": "rejected",
        "consumerPolicy": "do_not_use_as_negative_evidence",
        "scope": {
            "libraryKey": _library_key(lib),
            "methodsRequiredForNoHit": plan["methodsRequiredForNoHit"],
            "noHitBasis": plan["noHitBasis"],
        },
        "methodsAttempted": plan["methodsAttempted"],
        "methodsSucceeded": [],
        "providerState": {"state": "not_ready"},
        "projectionState": {"state": "not_applicable"},
        "diagnostics": [_diagnostic("NVD_CLIENT_NOT_READY", "NVD client is not initialized")],
        "fallbackTrace": plan["fallbackTrace"],
        "sourceEvidenceRefs": [],
        "derivedFromEvidenceRefs": [],
        "results": {"lookupMethodsAttempted": plan["methodsAttempted"], "lookupMethodsSucceeded": []},
    }


def _candidateize_item(
    item: dict[str, Any],
    lib: dict[str, Any],
    candidate_cve_id: str | None,
) -> dict[str, Any]:
    plan = _method_requirements(lib)
    cmethod = candidate_methods(plan)
    out = dict(item)
    out["itemType"] = "candidateCve"
    out["itemKey"] = f"{_library_key(lib)}|{candidate_cve_id or '<missing-candidate>'}"
    scope = {
        **(out.get("scope") if isinstance(out.get("scope"), dict) else {}),
        "libraryKey": _library_key(lib),
        "candidateCveId": candidate_cve_id,
        "methodsRequiredForNoHit": cmethod["methodsRequiredForNoHit"],
        "noHitBasis": (out.get("scope") if isinstance(out.get("scope"), dict) else {}).get("noHitBasis") or plan["noHitBasis"],
    }
    out["scope"] = scope
    out["methodsAttempted"] = cmethod["methodsAttempted"]
    out["methodsSucceeded"] = out.get("methodsSucceeded") or []
    out["providerState"] = out.get("providerState") or {"state": out.get("acquisitionStatus", "unknown")}
    out["projectionState"] = out.get("projectionState") or {"state": "not_applicable"}
    results = dict(out.get("results") if isinstance(out.get("results"), dict) else {})
    results["lookupMethodsAttempted"] = out["methodsAttempted"]
    results["lookupMethodsSucceeded"] = out["methodsSucceeded"]
    results.setdefault("candidateEvaluation", {
        "candidateCveId": candidate_cve_id,
        "candidateReturned": False,
        "versionMatch": None,
        "versionMatchReason": None,
        "forbiddenInferences": [],
    })
    out["results"] = results
    return out


def _diagnostic_acquisition_item(
    *,
    item_key: str,
    item_type: str,
    status: str,
    gate: str,
    policy: str,
    scope: dict[str, Any],
    diagnostics: list[dict[str, Any]],
    methods_attempted: list[str] | None = None,
    methods_succeeded: list[str] | None = None,
    provider_state: dict[str, Any] | None = None,
    fallback_trace: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    methods_attempted = methods_attempted or []
    methods_succeeded = methods_succeeded or []
    return {
        "itemKey": item_key,
        "itemType": item_type,
        "acquisitionStatus": status,
        "acquisitionQualityGate": gate,
        "consumerPolicy": policy,
        "scope": scope,
        "methodsAttempted": methods_attempted,
        "methodsSucceeded": methods_succeeded,
        "providerState": provider_state or {"state": status},
        "projectionState": {"state": "not_applicable"},
        "diagnostics": diagnostics,
        "fallbackTrace": fallback_trace or [],
        "sourceEvidenceRefs": [],
        "derivedFromEvidenceRefs": [],
        "results": {
            "lookupMethodsAttempted": methods_attempted,
            "lookupMethodsSucceeded": methods_succeeded,
        },
    }


def _candidate_cve_id(request_body: dict[str, Any] | None) -> str:
    if not isinstance(request_body, dict):
        return ""
    return normalize_cve_id(_camel(request_body, "candidateCveId", "candidateCve", "candidate_cve_id", "candidate_cve", "cveId", "cve_id"))


def _candidate_library(context: dict[str, Any], request_body: dict[str, Any] | None) -> dict[str, Any] | None:
    if isinstance(request_body, dict):
        explicit = request_body.get("library")
        if isinstance(explicit, dict):
            return explicit
        libs = request_body.get("libraries")
        if isinstance(libs, list) and len([lib for lib in libs if isinstance(lib, dict)]) == 1:
            return [lib for lib in libs if isinstance(lib, dict)][0]
        library_key = _camel(request_body, "libraryKey", "library_key")
        if library_key:
            for lib in _libraries_from_context(context, None):
                if _library_key(lib) == library_key:
                    return lib
    context_libs = _libraries_from_context(context, None)
    return context_libs[0] if len(context_libs) == 1 else None


def _candidate_item_from_cve_result(
    lib: dict[str, Any],
    candidate_cve_id: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    plan = _method_requirements(lib)
    cmethod = candidate_methods(plan)
    primary = plan["primaryMethod"]
    cves = _annotate_cve_reasons(result.get("cves", []) or [], primary)
    candidate = next((cve for cve in cves if normalize_cve_id(cve.get("id")) == candidate_cve_id), None)
    other_cves = [cve for cve in cves if normalize_cve_id(cve.get("id")) != candidate_cve_id]
    cache_info = result.get("cacheInfo") if isinstance(result.get("cacheInfo"), dict) else {}
    library_key = _library_key(lib)
    diagnostics: list[dict[str, Any]] = []
    fallback_trace = list(plan["fallbackTrace"])
    forbidden_inferences: list[str] = []
    version_match = candidate.get("version_match") if candidate else None
    version_match_reason = candidate.get("versionMatchReason") if candidate else None

    if cache_info.get("stale") or result.get("stale_cache_only"):
        status = "stale_cache_only"
        gate = "accepted_with_caveats"
        policy = "do_not_use_as_negative_evidence"
        methods_succeeded = ["cache"]
        diagnostics.append(_diagnostic("STALE_CACHE_ONLY", "Only stale CVE cache data was available"))
        fallback_trace.append({
            "from": "fresh_provider_lookup",
            "to": "cache",
            "reason": "fresh_provider_result_unavailable",
            "confidenceImpact": ["stale_context", "not_negative_evidence"],
        })
    elif result.get("error"):
        status = "incomplete_acquisition"
        gate = "inconclusive"
        policy = "do_not_use_as_negative_evidence"
        methods_succeeded = []
        diagnostics.append(_diagnostic("CVE_ACQUISITION_ERROR", str(result.get("error"))))
    elif candidate is None:
        status = "incomplete_acquisition"
        gate = "inconclusive"
        policy = "do_not_use_as_negative_evidence"
        methods_succeeded = provider_methods_succeeded(plan, result, status=status)
        diagnostics.append(_diagnostic(
            "CANDIDATE_NOT_RETURNED_KEYWORD_ONLY" if not plan["noHitEligible"] else "CANDIDATE_NOT_RETURNED_NO_EXPLICIT_RANGE_EVAL",
            "Candidate CVE was not explicitly returned with range-evaluation evidence; absence is not scoped no-hit",
        ))
    elif version_match is False:
        if not plan["noHitEligible"]:
            status = "incomplete_acquisition"
            gate = "inconclusive"
            policy = "do_not_use_as_negative_evidence"
            methods_succeeded = provider_methods_succeeded(plan, result, status=status)
            diagnostics.append(_diagnostic(
                "KEYWORD_ONLY_CANDIDATE_RANGE_OUT_UNSAFE",
                "Keyword-only candidate range-out cannot become completed_no_hit",
            ))
        else:
            status = "completed_no_hit"
            gate = "accepted"
            policy = "scoped_no_hit_record_only"
            methods_succeeded = list(cmethod["methodsRequiredForNoHit"])
            forbidden_inferences = list(CANDIDATE_RANGE_OUT_FORBIDDEN_INFERENCES)
    elif version_match is True:
        status = "completed_hit"
        gate = "accepted" if plan["noHitEligible"] else "accepted_with_caveats"
        policy = "contextual_only"
        methods_succeeded = [
            "exact_id_match",
            "provider_range_eval",
            *provider_methods_succeeded(plan, result, status=status),
        ]
    else:
        status = "input_insufficient"
        gate = "rejected"
        policy = "do_not_use_as_negative_evidence"
        methods_succeeded = [
            "exact_id_match",
            *provider_methods_succeeded(plan, result, status=status),
        ]
        diagnostics.append(_diagnostic(
            "CVE_VERSION_MATCH_UNKNOWN",
            "Candidate CVE was returned but provider could not evaluate this library version range",
        ))

    if primary == "nvd_keyword":
        diagnostics.append(_diagnostic("KEYWORD_ONLY_FALLBACK", "CVE lookup used broad keyword fallback"))

    item = {
        "itemKey": f"{library_key}|{candidate_cve_id}",
        "itemType": "candidateCve",
        "acquisitionStatus": status,
        "acquisitionQualityGate": gate,
        "consumerPolicy": policy,
        "scope": {
            "libraryKey": library_key,
            "candidateCveId": candidate_cve_id,
            "methodsRequiredForNoHit": cmethod["methodsRequiredForNoHit"],
            "noHitBasis": "candidate_version_range_evaluated" if status == "completed_no_hit" else plan["noHitBasis"],
            "cachePolicy": "stale" if status == "stale_cache_only" else ("fresh" if result.get("cached") else "none"),
            "providerState": {"state": "ready" if status in {"completed_hit", "completed_no_hit"} else status},
            "forbiddenInferences": forbidden_inferences,
        },
        "methodsAttempted": cmethod["methodsAttempted"] + (["cache"] if status == "stale_cache_only" else []),
        "methodsSucceeded": methods_succeeded,
        "providerState": {"state": "ready" if status in {"completed_hit", "completed_no_hit"} else status},
        "projectionState": {"state": "not_applicable"},
        "diagnostics": diagnostics,
        "fallbackTrace": fallback_trace,
        "sourceEvidenceRefs": [
            str(_camel(lib, "evidenceRefId", "evidenceRefID"))
        ] if _camel(lib, "evidenceRefId", "evidenceRefID") else [],
        "derivedFromEvidenceRefs": [],
        "results": {
            **result,
            "cves": cves,
            "candidateEvaluation": {
                "candidateCveId": candidate_cve_id,
                "candidateReturned": candidate is not None,
                "versionMatch": version_match,
                "versionMatchReason": version_match_reason,
                "forbiddenInferences": forbidden_inferences,
            },
            "discoveryCompanion": {
                "otherCveCandidates": other_cves,
                "candidateCount": len(other_cves),
                "consumerPolicy": "contextual_only" if other_cves else "diagnostic_only",
            },
            "lookupMethodsAttempted": cmethod["methodsAttempted"] + (["cache"] if status == "stale_cache_only" else []),
            "lookupMethodsSucceeded": methods_succeeded,
        },
    }
    return apply_no_hit_safety(item)


def _item_cache_payload(item: dict[str, Any]) -> dict[str, Any]:
    results = item.get("results") if isinstance(item.get("results"), dict) else {}
    cache_info = results.get("cacheInfo") if isinstance(results.get("cacheInfo"), dict) else {}
    stale = bool(cache_info.get("stale") or results.get("stale_cache_only"))
    return {
        "cached": bool(results.get("cached")),
        "stale": stale,
        "cacheInfo": cache_info,
    }


def _item_freshness_payload(item: dict[str, Any]) -> dict[str, Any]:
    status = item.get("acquisitionStatus")
    cache = _item_cache_payload(item)
    if status in {"timeout", "error", "not_ready", "incomplete_acquisition"}:
        freshness_status = status
    elif cache["stale"] or status == "stale_cache_only":
        freshness_status = "stale_cache_only"
    else:
        freshness_status = "current"
    return {"status": freshness_status}


def _provider_observation_payload(item: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    results = item.get("results") if isinstance(item.get("results"), dict) else {}
    cves = results.get("cves") if isinstance(results.get("cves"), list) else []
    candidate_eval = results.get("candidateEvaluation") if isinstance(results.get("candidateEvaluation"), dict) else {}
    cache_payload = _item_cache_payload(item)
    freshness_payload = _item_freshness_payload(item)
    item_provider_state = (
        item.get("providerState")
        or item.get("scope", {}).get("providerState")
        or {"state": item.get("acquisitionStatus", "unknown")}
    )
    return {
        "surface": envelope.get("surface"),
        "targetKnowledgeId": envelope.get("targetKnowledgeId"),
        "candidateCveId": candidate_eval.get("candidateCveId") or item.get("scope", {}).get("candidateCveId"),
        "scope": item.get("scope", {}),
        "providerState": item_provider_state,
        "cacheFreshness": {
            **freshness_payload,
            **cache_payload,
        },
        "fallbackTrace": item.get("fallbackTrace", []),
        "cveIds": cve_ids(cves),
        "versionMatches": {
            str(cve.get("id")): cve.get("version_match")
            for cve in cves
            if isinstance(cve, dict) and cve.get("id")
        },
        "versionMatchReasons": {
            str(cve.get("id")): cve.get("versionMatchReason")
            for cve in cves
            if isinstance(cve, dict) and cve.get("id")
        },
        "methodsAttempted": item.get("methodsAttempted") or results.get("lookupMethodsAttempted", []),
        "methodsSucceeded": item.get("methodsSucceeded") or results.get("lookupMethodsSucceeded", []),
        "diagnostics": item.get("diagnostics", []),
        "forbiddenInferences": candidate_eval.get("forbiddenInferences") or item.get("scope", {}).get("forbiddenInferences", []),
    }


def _persist_acquisition_envelope(envelope: dict[str, Any], *, provider: str) -> None:
    ledger = _projection_ledger()
    if ledger is None or not envelope.get("acquisitionId"):
        return
    try:
        ledger.record_acquisition_run(
            acquisition_id=envelope["acquisitionId"],
            target_knowledge_id=envelope.get("targetKnowledgeId"),
            target_context_version=envelope.get("targetContextVersion"),
            surface=envelope.get("surface") or "unknown",
            acquisition_status=envelope.get("acquisitionStatus") or "error",
            acquisition_quality_gate=envelope.get("acquisitionQualityGate") or "rejected",
            consumer_policy=envelope.get("consumerPolicy") or "do_not_use",
            scope=envelope.get("scope", {}),
            provenance=envelope.get("provenance", {}),
            results=envelope.get("results", {}),
        )
        for item in envelope.get("itemAcquisitions", []) or []:
            ledger.record_acquisition_item(
                acquisition_id=envelope["acquisitionId"],
                item_key=item.get("itemKey") or "<unknown>",
                item_type=item.get("itemType") or "unknown",
                acquisition_status=item.get("acquisitionStatus") or "error",
                acquisition_quality_gate=item.get("acquisitionQualityGate") or "rejected",
                consumer_policy=item.get("consumerPolicy") or "do_not_use",
                scope=item.get("scope", {}),
                diagnostics=item.get("diagnostics", []),
                results=item.get("results", {}),
            )
            subject_key = item.get("itemKey") or item.get("scope", {}).get("libraryKey") or "<unknown>"
            ledger.record_provider_observation(
                acquisition_id=envelope["acquisitionId"],
                provider=provider,
                subject_key=str(subject_key),
                status=item.get("acquisitionStatus") or "unknown",
                freshness=_item_freshness_payload(item),
                cache=_item_cache_payload(item),
                payload=_provider_observation_payload(item, envelope),
            )
    except Exception as exc:  # pragma: no cover - exercised via service error boundary
        logger.exception("target context CVE acquisition ledger persistence failed")
        raise HTTPException(503, f"CVE acquisition ledger persistence failed: {exc}") from exc


def _aggregate_status(items: list[dict[str, Any]]) -> tuple[str, str, str]:
    if not items:
        return "input_insufficient", "rejected", "do_not_use"
    statuses = {item["acquisitionStatus"] for item in items}
    has_real_hit = "completed_hit" in statuses
    has_no_hit = "completed_no_hit" in statuses
    failure_statuses = {
        "incomplete_acquisition",
        "timeout",
        "not_ready",
        "error",
        "input_insufficient",
        "conflicting_evidence",
        "stale_cache_only",
    }
    has_failure = bool(statuses & failure_statuses)

    if statuses == {"completed_hit"}:
        return "completed_hit", "accepted", "contextual_only"
    if statuses == {"completed_no_hit"}:
        return "completed_no_hit", "accepted", "scoped_no_hit_record_only"
    if statuses == {"input_insufficient"}:
        return "input_insufficient", "rejected", "do_not_use_as_negative_evidence"
    if statuses == {"timeout"}:
        return "timeout", "inconclusive", "do_not_use_as_negative_evidence"
    if statuses == {"not_ready"}:
        return "not_ready", "rejected", "do_not_use_as_negative_evidence"
    if statuses == {"error"}:
        return "error", "rejected", "do_not_use_as_negative_evidence"
    if statuses == {"conflicting_evidence"}:
        return "conflicting_evidence", "inconclusive", "do_not_use_as_negative_evidence"
    if statuses == {"stale_cache_only"}:
        return "stale_cache_only", "accepted_with_caveats", "do_not_use_as_negative_evidence"
    if has_real_hit and has_failure:
        return "partial_hit", "inconclusive", "do_not_use_as_negative_evidence"
    if has_real_hit and has_no_hit:
        return "partial_hit", "accepted_with_caveats", "contextual_only"
    if has_real_hit:
        return "partial_hit", "accepted_with_caveats", "contextual_only"
    if has_no_hit and has_failure:
        return "incomplete_acquisition", "inconclusive", "do_not_use_as_negative_evidence"
    if has_failure:
        return "incomplete_acquisition", "inconclusive", "do_not_use_as_negative_evidence"
    return "incomplete_acquisition", "inconclusive", "do_not_use_as_negative_evidence"



async def _run_cve_discovery(
    *,
    target_knowledge_id: str,
    request_body: dict[str, Any] | None,
    deadline: float,
    start: float,
    surface: str,
    acquisition_prefix: str,
    primary_method: str,
    provider_name: str,
) -> dict[str, Any]:
    context = _context_lookup(target_knowledge_id)
    bundle = context.get("bundle") or {}
    provenance = _provenance_from_bundle(bundle)
    libraries = _libraries_from_context(context, request_body)
    acquisition_id = f"{acquisition_prefix}-{int(time.time() * 1000)}"

    if not libraries:
        diagnostic = _diagnostic("NO_LIBRARIES", "No libraries supplied in request or target context")
        item_acquisitions = [_diagnostic_acquisition_item(
            item_key=f"{surface}:no-libraries",
            item_type="librarySet",
            status="input_insufficient",
            gate="rejected",
            policy="do_not_use",
            scope={
                "targetKnowledgeId": target_knowledge_id,
                "methodsRequiredForNoHit": [],
                "noHitBasis": "input_insufficient",
            },
            diagnostics=[diagnostic],
            provider_state={"state": "input_insufficient"},
        )]
        envelope = _base_envelope(
            surface=surface,
            acquisition_status="input_insufficient",
            quality_gate="rejected",
            consumer_policy="do_not_use",
            target_knowledge_id=target_knowledge_id,
            target_context_version=context.get("targetContextVersion"),
            acquisition_id=acquisition_id,
            primary_method=primary_method,
            diagnostics=[diagnostic],
            provenance=provenance,
            provider_state={"state": "input_insufficient"},
            projection_state={"state": "not_applicable"},
            scope={
                "targetKnowledgeId": target_knowledge_id,
                "itemCount": 1,
                "methodsRequiredForNoHit": [],
                "noHitBasis": "input_insufficient",
                "providerState": {"state": "input_insufficient"},
            },
            results={"itemCount": 1},
            item_acquisitions=item_acquisitions,
        )
        _persist_acquisition_envelope(envelope, provider=provider_name)
        return {**envelope, "latency_ms": _elapsed_ms(start)}

    valid_libs = []
    item_acquisitions = []
    for lib in libraries:
        name = _camel(lib, "name")
        version = _camel(lib, "version")
        eligible = _camel(lib, "cveLookupEligible", "cve_lookup_eligible")
        if _has_conflicting_version_evidence(lib):
            item_acquisitions.append(_conflicting_library_item(lib))
        elif eligible is False:
            item_acquisitions.append(_invalid_library_item(lib, "cveLookupEligible=false"))
        elif not name or not version:
            item_acquisitions.append(_invalid_library_item(lib, "library name and version are required"))
        else:
            valid_libs.append(lib)

    if _nvd_client is None:
        for lib in valid_libs:
            item_acquisitions.append(_nvd_not_ready_item(lib))
    elif valid_libs:
        lookup_payload = [
            {
                "name": str(_camel(lib, "name")),
                "version": str(_camel(lib, "version")),
                "repo_url": _camel(lib, "repoUrl", "repo_url"),
                "commit": _camel(lib, "commit"),
            }
            for lib in valid_libs
        ]
        try:
            results = await run_async_with_deadline(
                deadline,
                primary_method,
                _nvd_client.batch_lookup(lookup_payload),
            )
        except HTTPException as exc:
            if not _is_timeout_exception(exc):
                raise
            for lib in valid_libs:
                item_acquisitions.append(_provider_failure_item(
                    lib,
                    status="timeout",
                    code="CVE_PROVIDER_TIMEOUT",
                    message="CVE provider lookup exceeded caller deadline",
                ))
        except Exception as exc:
            logger.exception("target context CVE provider lookup failed")
            for lib in valid_libs:
                item_acquisitions.append(_provider_failure_item(
                    lib,
                    status="error",
                    code="CVE_PROVIDER_ERROR",
                    message=str(exc),
                ))
        else:
            by_key = {f"{r.get('library')}@{r.get('version')}": r for r in results if isinstance(r, dict)}
            for lib in valid_libs:
                result = by_key.get(_library_key(lib)) or {
                    "library": _camel(lib, "name"),
                    "version": _camel(lib, "version"),
                    "cves": [],
                    "total": 0,
                    "error": "missing_result",
                }
                item_acquisitions.append(_item_from_cve_result(lib, result))

    status, gate, policy = _aggregate_status(item_acquisitions)
    methods_attempted = sorted({
        m
        for item in item_acquisitions
        for m in (item.get("methodsAttempted") or item.get("scope", {}).get("methodsRequiredForNoHit", []))
    })
    methods_succeeded = sorted({
        m
        for item in item_acquisitions
        for m in (item.get("methodsSucceeded") or item.get("results", {}).get("lookupMethodsSucceeded", []))
    })
    provider_state = {"state": "ready" if status in {"completed_hit", "completed_no_hit", "partial_hit"} else status}
    required_methods = sorted({m for item in item_acquisitions for m in item.get("scope", {}).get("methodsRequiredForNoHit", [])})
    envelope = _base_envelope(
        surface=surface,
        acquisition_status=status,
        quality_gate=gate,
        consumer_policy=policy,
        target_knowledge_id=target_knowledge_id,
        target_context_version=context.get("targetContextVersion"),
        acquisition_id=acquisition_id,
        primary_method=primary_method,
        methods_attempted=methods_attempted,
        methods_succeeded=methods_succeeded,
        fallback_trace=[trace for item in item_acquisitions for trace in item.get("fallbackTrace", [])],
        diagnostics=[diag for item in item_acquisitions for diag in item.get("diagnostics", []) if item.get("acquisitionStatus") not in {"completed_hit", "completed_no_hit"}],
        scope={
            "targetKnowledgeId": target_knowledge_id,
            "itemCount": len(item_acquisitions),
            "methodsRequiredForNoHit": required_methods,
            "noHitBasis": "completed_required_methods",
            "providerState": provider_state,
        },
        provenance=provenance,
        provider_state=provider_state,
        projection_state={"state": "not_applicable"},
        results={"itemCount": len(item_acquisitions)},
        item_acquisitions=item_acquisitions,
    )
    _persist_acquisition_envelope(envelope, provider=provider_name)
    return {**envelope, "latency_ms": _elapsed_ms(start)}


@router.post("/{target_knowledge_id}/acquire/cve")
async def acquire_cve(
    target_knowledge_id: str,
    request_body: dict[str, Any] | None = Body(default=None),
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict[str, Any]:
    """Compatibility CVE discovery surface; response surface remains `cve`."""

    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    start = time.monotonic()
    return await _run_cve_discovery(
        target_knowledge_id=target_knowledge_id,
        request_body=request_body,
        deadline=deadline,
        start=start,
        surface="cve",
        acquisition_prefix="acq-cve",
        primary_method="target_context_cve_batch",
        provider_name="target_context_cve_compat",
    )


@router.post("/{target_knowledge_id}/acquire/cve-discovery")
async def acquire_cve_discovery(
    target_knowledge_id: str,
    request_body: dict[str, Any] | None = Body(default=None),
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict[str, Any]:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    start = time.monotonic()
    return await _run_cve_discovery(
        target_knowledge_id=target_knowledge_id,
        request_body=request_body,
        deadline=deadline,
        start=start,
        surface="cveDiscovery",
        acquisition_prefix="acq-cve-discovery",
        primary_method="target_context_cve_discovery",
        provider_name="target_context_cve_discovery",
    )


@router.post("/{target_knowledge_id}/acquire/cve-candidate-evaluation")
async def acquire_cve_candidate_evaluation(
    target_knowledge_id: str,
    request_body: dict[str, Any] | None = Body(default=None),
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict[str, Any]:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    start = time.monotonic()
    context = _context_lookup(target_knowledge_id)
    bundle = context.get("bundle") or {}
    provenance = _provenance_from_bundle(bundle)
    candidate_cve_id = _candidate_cve_id(request_body)
    lib = _candidate_library(context, request_body)
    acquisition_id = f"acq-cve-candidate-{int(time.time() * 1000)}"

    item_acquisitions: list[dict[str, Any]] = []
    if not candidate_cve_id or lib is None:
        synthetic_lib = lib or {"name": "candidate-cve", "version": "<unknown>"}
        item_acquisitions.append(_candidateize_item(
            _invalid_library_item(
                synthetic_lib,
                "candidate CVE id and exactly one library identity/version are required",
            ),
            synthetic_lib,
            candidate_cve_id or None,
        ))
    elif _has_conflicting_version_evidence(lib):
        item_acquisitions.append(_candidateize_item(_conflicting_library_item(lib), lib, candidate_cve_id))
    elif _camel(lib, "cveLookupEligible", "cve_lookup_eligible") is False:
        item_acquisitions.append(_candidateize_item(_invalid_library_item(lib, "cveLookupEligible=false"), lib, candidate_cve_id))
    elif not _camel(lib, "name") or not _camel(lib, "version"):
        item_acquisitions.append(_candidateize_item(_invalid_library_item(lib, "library name and version are required"), lib, candidate_cve_id))
    elif _nvd_client is None:
        item_acquisitions.append(_candidateize_item(_nvd_not_ready_item(lib), lib, candidate_cve_id))
    else:
        lookup_payload = [{
            "name": str(_camel(lib, "name")),
            "version": str(_camel(lib, "version")),
            "repo_url": _camel(lib, "repoUrl", "repo_url"),
            "commit": _camel(lib, "commit"),
        }]
        try:
            results = await run_async_with_deadline(
                deadline,
                "target-context-cve-candidate-evaluation",
                _nvd_client.batch_lookup(lookup_payload),
            )
        except HTTPException as exc:
            if not _is_timeout_exception(exc):
                raise
            item_acquisitions.append(_candidateize_item(
                _provider_failure_item(
                    lib,
                    status="timeout",
                    code="CVE_PROVIDER_TIMEOUT",
                    message="CVE provider lookup exceeded caller deadline",
                ),
                lib,
                candidate_cve_id,
            ))
        except Exception as exc:
            logger.exception("target context CVE candidate provider lookup failed")
            item_acquisitions.append(_candidateize_item(
                _provider_failure_item(
                    lib,
                    status="error",
                    code="CVE_PROVIDER_ERROR",
                    message=str(exc),
                ),
                lib,
                candidate_cve_id,
            ))
        else:
            result = next((r for r in results if isinstance(r, dict)), None) or {
                "library": _camel(lib, "name"),
                "version": _camel(lib, "version"),
                "cves": [],
                "total": 0,
                "error": "missing_result",
            }
            item_acquisitions.append(_candidate_item_from_cve_result(lib, candidate_cve_id, result))

    status, gate, policy = _aggregate_status(item_acquisitions)
    item = item_acquisitions[0] if item_acquisitions else {}
    methods_attempted = sorted({m for item in item_acquisitions for m in (item.get("methodsAttempted") or item.get("scope", {}).get("methodsRequiredForNoHit", []))})
    methods_succeeded = sorted({m for item in item_acquisitions for m in (item.get("methodsSucceeded") or item.get("results", {}).get("lookupMethodsSucceeded", []))})
    provider_state = {"state": "ready" if status in {"completed_hit", "completed_no_hit"} else status}
    required_methods = sorted({m for item in item_acquisitions for m in item.get("scope", {}).get("methodsRequiredForNoHit", [])})
    envelope = _base_envelope(
        surface="cveCandidateEvaluation",
        acquisition_status=status,
        quality_gate=gate,
        consumer_policy=policy,
        target_knowledge_id=target_knowledge_id,
        target_context_version=context.get("targetContextVersion"),
        acquisition_id=acquisition_id,
        primary_method="target_context_cve_candidate_evaluation",
        methods_attempted=methods_attempted,
        methods_succeeded=methods_succeeded,
        fallback_trace=[trace for item in item_acquisitions for trace in item.get("fallbackTrace", [])],
        diagnostics=[diag for item in item_acquisitions for diag in item.get("diagnostics", []) if item.get("acquisitionStatus") not in {"completed_hit", "completed_no_hit"}],
        scope={
            "targetKnowledgeId": target_knowledge_id,
            "libraryKey": item.get("scope", {}).get("libraryKey"),
            "candidateCveId": candidate_cve_id or None,
            "itemCount": len(item_acquisitions),
            "methodsRequiredForNoHit": required_methods,
            "noHitBasis": item.get("scope", {}).get("noHitBasis") or "candidate_version_range_evaluated",
            "providerState": provider_state,
            "forbiddenInferences": item.get("scope", {}).get("forbiddenInferences", []),
        },
        provenance=provenance,
        provider_state=provider_state,
        projection_state={"state": "not_applicable"},
        results={
            "itemCount": len(item_acquisitions),
            "candidateEvaluation": item.get("results", {}).get("candidateEvaluation", {}),
            "discoveryCompanion": item.get("results", {}).get("discoveryCompanion", {}),
        },
        item_acquisitions=item_acquisitions,
    )
    _persist_acquisition_envelope(envelope, provider="target_context_cve_candidate")
    return {**envelope, "latency_ms": _elapsed_ms(start)}


@router.post("/{target_knowledge_id}/acquire/code-search")
async def acquire_code_search(
    target_knowledge_id: str,
    request_body: dict[str, Any] = Body(...),
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict[str, Any]:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    start = time.monotonic()
    context = _context_lookup(target_knowledge_id)
    bundle = context.get("bundle") or {}
    code_graph = _code_graph_bundle(bundle)
    query = request_body.get("query") if isinstance(request_body, dict) else None
    if not query:
        item = _invalid_library_item({"name": "code-search", "version": "query"}, "query is required")
        item["itemType"] = "query"
        envelope = _base_envelope(
            surface="code-search",
            acquisition_status="input_insufficient",
            quality_gate="rejected",
            consumer_policy="do_not_use",
            target_knowledge_id=target_knowledge_id,
            target_context_version=context.get("targetContextVersion"),
            diagnostics=item["diagnostics"],
            provenance=_provenance_from_bundle(bundle),
            item_acquisitions=[item],
        )
        return {**envelope, "latency_ms": _elapsed_ms(start)}
    if _code_assembler is None:
        envelope = _base_envelope(
            surface="code-search",
            acquisition_status="not_ready",
            quality_gate="rejected",
            consumer_policy="do_not_use_as_negative_evidence",
            target_knowledge_id=target_knowledge_id,
            target_context_version=context.get("targetContextVersion"),
            diagnostics=[_diagnostic("CODE_SEARCH_NOT_READY", "Code graph search is not initialized")],
            provenance=_provenance_from_bundle(bundle),
        )
        return {**envelope, "latency_ms": _elapsed_ms(start)}
    project_id = code_graph.get("projectId") or target_knowledge_id
    result = await run_sync_with_deadline(
        deadline,
        "target-context-code-search",
        _code_assembler.search,
        project_id,
        query,
        top_k=int(request_body.get("top_k", request_body.get("topK", 10))),
        min_score=float(request_body.get("min_score", request_body.get("minScore", 0.3))),
        graph_depth=int(request_body.get("graph_depth", request_body.get("graphDepth", 2))),
        include_call_chain=bool(request_body.get("include_call_chain", request_body.get("includeCallChain", True))),
        build_snapshot_id=(bundle.get("provenance") or {}).get("buildSnapshotId"),
        query_intent=_camel(request_body, "queryIntent", "query_intent"),
        corpus_partitions=_list_param(request_body, "corpusPartitions", "corpus_partitions"),
        profiles=_list_param(request_body, "profiles"),
        allow_global_embedding=_bool_param(request_body, "allowGlobalEmbedding", "allow_global_embedding"),
    )
    status = "completed_hit" if result.get("total", 0) > 0 else "completed_no_hit"
    projection_state = _code_search_projection_state(project_id)
    retrieval_trace = result.get("retrievalTrace") if isinstance(result.get("retrievalTrace"), dict) else {}
    default_methods = ["exact_id_match", "constrained_embedding_rerank", "graph_expansion"]
    methods_attempted = _trace_list(retrieval_trace, "methodsAttempted", default_methods)
    methods_succeeded = _trace_list(
        retrieval_trace,
        "methodsSucceeded",
        methods_attempted if status == "completed_hit" else [],
    )
    no_hit_basis = "completed_required_methods" if status == "completed_hit" else unsafe_no_hit_basis_from_trace(retrieval_trace)
    trace_diagnostics = _retrieval_trace_diagnostics(
        retrieval_trace,
        status=status,
        methods_succeeded=methods_succeeded,
    )
    envelope = _base_envelope(
        surface="code-search",
        acquisition_status=status,
        quality_gate="accepted",
        consumer_policy="s3_may_derive_local_support_if_refs_validate" if status == "completed_hit" else "scoped_no_hit_record_only",
        target_knowledge_id=target_knowledge_id,
        target_context_version=context.get("targetContextVersion"),
        acquisition_id=f"acq-code-search-{int(time.time() * 1000)}",
        primary_method="code_graph_hybrid_search",
        methods_attempted=methods_attempted,
        methods_succeeded=methods_succeeded,
        diagnostics=trace_diagnostics,
        scope={
            "query": query,
            "projectId": project_id,
            "methodsRequiredForNoHit": methods_attempted,
            "noHitBasis": no_hit_basis,
            "projectionState": projection_state,
            "retrievalTrace": retrieval_trace,
        },
        provenance=_provenance_from_bundle(bundle),
        provider_state={"state": "not_applicable"},
        projection_state=projection_state,
        results=result,
    )
    return {**envelope, "latency_ms": _elapsed_ms(start)}


@router.post("/{target_knowledge_id}/acquire/threat-search")
async def acquire_threat_search(
    target_knowledge_id: str,
    request_body: dict[str, Any] = Body(...),
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict[str, Any]:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    start = time.monotonic()
    context = _context_lookup(target_knowledge_id)
    bundle = context.get("bundle") or {}
    query = request_body.get("query") if isinstance(request_body, dict) else None
    if not query:
        envelope = _base_envelope(
            surface="threat-search",
            acquisition_status="input_insufficient",
            quality_gate="rejected",
            consumer_policy="do_not_use",
            target_knowledge_id=target_knowledge_id,
            target_context_version=context.get("targetContextVersion"),
            diagnostics=[_diagnostic("QUERY_REQUIRED", "query is required")],
            provenance=_provenance_from_bundle(bundle),
        )
        return {**envelope, "latency_ms": _elapsed_ms(start)}
    if _knowledge_assembler is None:
        envelope = _base_envelope(
            surface="threat-search",
            acquisition_status="not_ready",
            quality_gate="rejected",
            consumer_policy="do_not_use_as_negative_evidence",
            target_knowledge_id=target_knowledge_id,
            target_context_version=context.get("targetContextVersion"),
            diagnostics=[_diagnostic("THREAT_SEARCH_NOT_READY", "Threat search is not initialized")],
            provenance=_provenance_from_bundle(bundle),
        )
        return {**envelope, "latency_ms": _elapsed_ms(start)}
    result = await run_sync_with_deadline(
        deadline,
        "target-context-threat-search",
        _knowledge_assembler.assemble,
        query,
        top_k=int(request_body.get("top_k", request_body.get("topK", 5))),
        min_score=float(request_body.get("min_score", request_body.get("minScore", 0.35))),
        graph_depth=int(request_body.get("graph_depth", request_body.get("graphDepth", 2))),
        query_intent=_camel(request_body, "queryIntent", "query_intent"),
        corpus_partitions=_list_param(request_body, "corpusPartitions", "corpus_partitions"),
        profiles=_list_param(request_body, "profiles"),
        allow_global_embedding=_bool_param(request_body, "allowGlobalEmbedding", "allow_global_embedding"),
    )
    status = "completed_hit" if result.get("total", 0) > 0 else "completed_no_hit"
    projection_state = _threat_projection_state()
    retrieval_trace = result.get("retrievalTrace") if isinstance(result.get("retrievalTrace"), dict) else {}
    default_methods = ["exact_id_match", "graph_expansion", "constrained_embedding_rerank"]
    methods_attempted = _trace_list(retrieval_trace, "methodsAttempted", default_methods)
    methods_succeeded = _trace_list(
        retrieval_trace,
        "methodsSucceeded",
        methods_attempted if status == "completed_hit" else [],
    )
    no_hit_basis = "completed_required_methods" if status == "completed_hit" else unsafe_no_hit_basis_from_trace(retrieval_trace)
    trace_diagnostics = _retrieval_trace_diagnostics(
        retrieval_trace,
        status=status,
        methods_succeeded=methods_succeeded,
    )
    envelope = _base_envelope(
        surface="threat-search",
        acquisition_status=status,
        quality_gate="accepted",
        consumer_policy="contextual_only" if status == "completed_hit" else "scoped_no_hit_record_only",
        target_knowledge_id=target_knowledge_id,
        target_context_version=context.get("targetContextVersion"),
        acquisition_id=f"acq-threat-search-{int(time.time() * 1000)}",
        primary_method="threat_graphrag_search",
        methods_attempted=methods_attempted,
        methods_succeeded=methods_succeeded,
        diagnostics=trace_diagnostics,
        scope={
            "query": query,
            "methodsRequiredForNoHit": methods_attempted,
            "noHitBasis": no_hit_basis,
            "projectionState": projection_state,
            "retrievalTrace": retrieval_trace,
        },
        provenance=_provenance_from_bundle(bundle),
        provider_state={"state": "not_applicable"},
        projection_state=projection_state,
        results=result,
    )
    return {**envelope, "latency_ms": _elapsed_ms(start)}


@router.post("/{target_knowledge_id}/acquire/dangerous-callers")
async def acquire_dangerous_callers(
    target_knowledge_id: str,
    request_body: dict[str, Any] = Body(...),
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict[str, Any]:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    start = time.monotonic()
    context = _context_lookup(target_knowledge_id)
    bundle = context.get("bundle") or {}
    code_graph = _code_graph_bundle(bundle)
    dangerous = request_body.get("dangerous_functions") or request_body.get("dangerousFunctions")
    if not isinstance(dangerous, list) or not dangerous:
        envelope = _base_envelope(
            surface="dangerous-callers",
            acquisition_status="input_insufficient",
            quality_gate="rejected",
            consumer_policy="do_not_use",
            target_knowledge_id=target_knowledge_id,
            target_context_version=context.get("targetContextVersion"),
            diagnostics=[_diagnostic("DANGEROUS_FUNCTIONS_REQUIRED", "dangerous_functions is required")],
            provenance=_provenance_from_bundle(bundle),
        )
        return {**envelope, "latency_ms": _elapsed_ms(start)}
    if _code_graph_service is None:
        envelope = _base_envelope(
            surface="dangerous-callers",
            acquisition_status="not_ready",
            quality_gate="rejected",
            consumer_policy="do_not_use_as_negative_evidence",
            target_knowledge_id=target_knowledge_id,
            target_context_version=context.get("targetContextVersion"),
            diagnostics=[_diagnostic("CODE_GRAPH_NOT_READY", "Code graph service is not initialized")],
            provenance=_provenance_from_bundle(bundle),
        )
        return {**envelope, "latency_ms": _elapsed_ms(start)}
    project_id = code_graph.get("projectId") or target_knowledge_id
    result = await run_sync_with_deadline(
        deadline,
        "target-context-dangerous-callers",
        _code_graph_service.find_dangerous_callers,
        project_id,
        [str(d) for d in dangerous],
        build_snapshot_id=(bundle.get("provenance") or {}).get("buildSnapshotId"),
    )
    status = "completed_hit" if result else "completed_no_hit"
    projection_state = _dangerous_callers_projection_state(project_id)
    envelope = _base_envelope(
        surface="dangerous-callers",
        acquisition_status=status,
        quality_gate="accepted",
        consumer_policy="s3_may_derive_local_support_if_refs_validate" if result else "scoped_no_hit_record_only",
        target_knowledge_id=target_knowledge_id,
        target_context_version=context.get("targetContextVersion"),
        acquisition_id=f"acq-dangerous-callers-{int(time.time() * 1000)}",
        primary_method="code_graph_dangerous_callers",
        methods_attempted=["neo4j_call_graph_traversal"],
        methods_succeeded=["neo4j_call_graph_traversal"],
        scope={
            "projectId": project_id,
            "dangerousFunctions": dangerous,
            "methodsRequiredForNoHit": ["neo4j_call_graph_traversal"],
            "noHitBasis": "completed_required_methods",
            "projectionState": projection_state,
        },
        provenance=_provenance_from_bundle(bundle),
        provider_state={"state": "not_applicable"},
        projection_state=projection_state,
        results={"results": result},
    )
    return {**envelope, "latency_ms": _elapsed_ms(start)}
