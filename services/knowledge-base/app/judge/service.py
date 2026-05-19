"""Evidence-Grounded Judge service.

The Judge composes deterministic S5 knowledge evidence.  Its `verdict` is not a
S3 final security decision; it is an S5 evidence-grounded knowledge verdict over
one query and target context.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from app.affectedness import query_affectedness
from app.analyst.brief import BASELINE_FORBIDDEN_INFERENCES
from app.config import redact_url_for_log, redact_urls_in_text_for_log, settings
from app.graphrag.retrieval_policy import method_rank_weight
from app.identity import resolve_component_identity
from app.ledger.repository import (
    MAX_SOURCE_NESTED_OBJECT_INLINE_BYTES,
    MAX_SOURCE_SNIPPET_TEXT_INLINE_BYTES,
    SQLiteLedgerRepository,
)
from app.quality.scoring_policy import default_score_vector, evaluate_score_vector
from app.relations import detect_relation_conflicts
from app.serving.decision_cache import get_decision_fragment, store_decision_fragment
from app.serving.query_planner import build_canonical_query, normalize_control_identifier, sanitize_large_echo_value
from app.threat_retrieval import AUTHORITY as THREAT_RETRIEVAL_AUTHORITY
from app.threat_retrieval import RISK_SIGNAL_AUTHORITY
from app.threat_retrieval import build_threat_retrieval_evidence

from .models import JudgeQueryRequest

SCHEMA_VERSION = "s5-judge-answer-v1"
VERDICT_AUTHORITY = "s5_evidence_grounded_knowledge_verdict_not_s3_final_security_verdict"
CONFLICT_CONSUMER_POLICY = "conflicting_evidence_not_negative_evidence"
MAX_CONFLICTING_VALUES_IN_SUMMARY = 8
JUDGE_REASONING_PATH_STEPS = (
    "resolve_source_code_kg_context",
    "load_decision_fragment_cache",
    "resolve_component_identity",
    "evaluate_package_version_affectedness",
    "apply_exclude_controls",
    "assemble_threat_kb_context",
    "check_required_component_inputs",
)
JUDGE_REASONING_PATH_VALIDATOR_ISSUE_CODES = (
    "REASONING_PATH_ENTRY_INVALID",
    "REASONING_PATH_FIELD_MISSING",
    "REASONING_PATH_MISSING",
    "REASONING_PATH_STEP_UNKNOWN",
)
JUDGE_FALLBACK_TRACE_STAGE_CATALOG = {
    "source_code_kg_context": (
        "unresolved_context",
        "partial_context_resolution",
    ),
    "control_validation": (
        "unsupported_controls_rejected",
    ),
}
JUDGE_FALLBACK_TRACE_VALIDATOR_ISSUE_CODES = (
    "FALLBACK_TRACE_DIAGNOSTICS_MISSING",
    "FALLBACK_TRACE_ENTRY_INVALID",
    "FALLBACK_TRACE_FALLBACK_UNKNOWN",
    "FALLBACK_TRACE_FIELD_MISSING",
    "FALLBACK_TRACE_INVALID",
    "FALLBACK_TRACE_REJECTED_CONTROLS_MISSING",
    "FALLBACK_TRACE_SILENT",
    "FALLBACK_TRACE_STAGE_UNKNOWN",
)
JUDGE_CONTROL_EFFECT_CONTROLS = ("exclude",)
JUDGE_CONTROL_EFFECT_REQUIRED_FIELDS = ("control", "suppressedAdvisoryIds", "suppressedExternalIds")
JUDGE_CONTROL_EFFECT_VALIDATOR_ISSUE_CODES = (
    "CONTROL_EFFECT_ACCEPTED_CONTROL_MISMATCH",
    "CONTROL_EFFECT_CONTROL_UNKNOWN",
    "CONTROL_EFFECT_ENTRY_INVALID",
    "CONTROL_EFFECT_FIELD_MISSING",
    "CONTROL_EFFECT_SUPPRESSED_AFFECTEDNESS_MISMATCH",
    "CONTROL_EFFECT_SUPPRESSION_TRACE_MISSING",
    "CONTROL_EFFECT_SUPPRESSION_VERDICT_INVALID",
    "CONTROL_EFFECTS_INVALID",
)
JUDGE_UNCERTAINTY_REQUIRED_FIELDS = ("reason", "evidenceGaps", "requiredInputs", "conflicts")
JUDGE_UNCERTAINTY_REQUIRED_INPUT_VOCABULARY = (
    "component.version",
    "component.identity",
    "sourceContext",
    "additional affectedness evidence or re-query controls",
    "complete_or_consistent_source_code_kg_context",
)
JUDGE_FOLLOW_UP_REQUEST_KINDS = (
    "library_version_lookup",
    "source_diff_or_vendored_patch_check",
    "source_context_enrichment",
)
JUDGE_FOLLOW_UP_OWNER_LANES = ("S3/S4", "S4")
JUDGE_UNCERTAINTY_FOLLOWUP_VALIDATOR_ISSUE_CODES = (
    "FOLLOW_UP_AFFORDANCE_INVALID",
    "FOLLOW_UP_OWNER_LANE_UNKNOWN",
    "FOLLOW_UP_REASON_MISSING",
    "FOLLOW_UP_REQUEST_KIND_UNKNOWN",
    "UNCERTAINTY_FIELD_INVALID",
    "UNCERTAINTY_FIELD_MISSING",
    "UNCERTAINTY_REASON_MISSING",
    "UNCERTAINTY_REQUIRED_INPUT_UNKNOWN",
)
JUDGE_ANSWER_FIELD_VALIDATOR_ISSUE_CODES = (
    "JUDGE_ANSWER_FIELD_INVALID",
)
DECISION_CACHE_REVISION_TABLES = (
    "package_identity",
    "product_identity",
    "source_component_identity",
    "identity_alias",
    "vulnerability_advisory",
    "risk_signal",
    "affectedness_record",
    "relation_record",
    "conflict_record",
)
THREAT_RETRIEVAL_DIAGNOSTIC_METADATA_REDACTION_FIELDS = (
    "externalId",
    "expectedExternalId",
    "actualExternalId",
    "previousExternalId",
    "currentExternalId",
    "riskSignalId",
    "advisoryId",
)
THREAT_RETRIEVAL_VALIDATOR_ISSUE_FIELDS = {
    "THREAT_RETRIEVAL_RETURNED_COUNT_MISMATCH": "evidence.threatRetrieval.retrievalTrace.returnedCount",
    "THREAT_RETRIEVAL_METHODS_SUCCEEDED_MISMATCH": "evidence.threatRetrieval.retrievalTrace.methodsSucceeded",
    "THREAT_RETRIEVAL_EMBEDDING_SCOPE_MISMATCH": "evidence.threatRetrieval.retrievalTrace.embeddingScope",
    "THREAT_RETRIEVAL_MATCHED_TERMS_MISMATCH": "evidence.threatRetrieval.retrievalTrace.matchedTerms",
    "THREAT_RETRIEVAL_TOPK_OVERFLOW": "evidence.threatRetrieval.candidateEvidence",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_ACCOUNTING_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolSize",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_TRUNCATION_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolTruncated",
    "THREAT_RETRIEVAL_EXCLUDED_CANDIDATE_RETURNED": "evidence.threatRetrieval.candidateEvidence[]",
    "THREAT_RETRIEVAL_RANK_SEQUENCE_INVALID": "evidence.threatRetrieval.candidateEvidence[].rank",
    "THREAT_RETRIEVAL_METHOD_WEIGHT_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].scoreBreakdown.methodWeight",
    "THREAT_RETRIEVAL_SCORE_BREAKDOWN_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].scoreBreakdown",
    "THREAT_RETRIEVAL_RERANK_SCORE_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].rerankScore",
    "THREAT_RETRIEVAL_SCORE_BREAKDOWN_INVALID": "evidence.threatRetrieval.candidateEvidence[].scoreBreakdown",
    "THREAT_RETRIEVAL_EQUIVALENT_COUNT_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].equivalentAdvisoryCount",
    "THREAT_RETRIEVAL_EQUIVALENT_LIMIT_OVERFLOW": "evidence.threatRetrieval.candidateEvidence[].equivalentAdvisories",
    "THREAT_RETRIEVAL_EQUIVALENT_TRUNCATION_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].equivalentAdvisoriesTruncated",
    "THREAT_RETRIEVAL_EQUIVALENT_SOURCE_KINDS_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].equivalentSourceKinds",
    "THREAT_RETRIEVAL_EXCLUDED_EQUIVALENT_RETURNED": "evidence.threatRetrieval.candidateEvidence[].equivalentAdvisories[]",
    "THREAT_RETRIEVAL_EQUIVALENT_RESPONSE_BUDGET_MISMATCH": "evidence.threatRetrieval.retrievalTrace.equivalentAdvisoryReturnedCount",
    "THREAT_RETRIEVAL_EXCLUDED_RISK_SIGNAL_RETURNED": "evidence.threatRetrieval.riskSignals[]",
    "THREAT_RETRIEVAL_RISK_SIGNAL_RESPONSE_BUDGET_MISMATCH": "evidence.threatRetrieval.retrievalTrace.riskSignalReturnedCount",
    "THREAT_RETRIEVAL_SUPPRESSED_RESPONSE_BUDGET_MISMATCH": "evidence.threatRetrieval.retrievalTrace.suppressedCandidateReturnedCount",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_MISSING": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_COUNT_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreviewCount",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_LIMIT_OVERFLOW": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreviewLimit",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_TRUNCATION_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreviewTruncated",
    "THREAT_RETRIEVAL_EXCLUDED_PREVIEW_RETURNED": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[]",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RANK_SEQUENCE_INVALID": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].candidatePoolRank",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RETURNED_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].returned",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RETURNED_ID_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].externalId",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_UNRETURNED_REASON_MISSING": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].unreturnedReason",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_METHOD_WEIGHT_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].scoreBreakdown.methodWeight",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_SCORE_BREAKDOWN_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].scoreBreakdown",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RERANK_SCORE_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].rerankScore",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_SCORE_BREAKDOWN_INVALID": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].scoreBreakdown",
    "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_ORDER_INVALID": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].rerankScore",
    "THREAT_RETRIEVAL_RERANK_ORDER_INVALID": "evidence.threatRetrieval.candidateEvidence[].rerankScore",
}
THREAT_RETRIEVAL_RELATIVE_ISSUE_FIELDS = {
    "methodsSucceeded": "evidence.threatRetrieval.retrievalTrace.methodsSucceeded",
    "filtersApplied": "evidence.threatRetrieval.retrievalTrace.filtersApplied",
    "matchedTerms": "evidence.threatRetrieval.retrievalTrace.matchedTerms",
    "relationMethods": "evidence.threatRetrieval.retrievalTrace.relationMethods",
    "embeddingScope": "evidence.threatRetrieval.retrievalTrace.embeddingScope",
    "profileBoostsApplied": "evidence.threatRetrieval.retrievalTrace.profileBoostsApplied",
    "projectionState": "evidence.threatRetrieval.retrievalTrace.projectionState",
    "providerState": "evidence.threatRetrieval.retrievalTrace.providerState",
    "weaknessSemantics": "evidence.threatRetrieval.weaknessSemantics",
    "attackSemantics": "evidence.threatRetrieval.attackSemantics",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _serving_run_id(answer: dict[str, Any], created_at: str) -> str:
    canonical_query = answer.get("canonicalQuery") or {}
    payload = "\0".join(
        [
            str(canonical_query.get("canonicalQueryId") or ""),
            str(answer.get("decisionFragmentKey") or canonical_query.get("decisionFragmentKey") or ""),
            created_at,
        ]
    ).encode("utf-8")
    return f"serving-run-{hashlib.sha256(payload).hexdigest()[:16]}"


def _decision_cache_scope_hash(repo: SQLiteLedgerRepository) -> str:
    path = str(getattr(repo, "path", "") or "")
    if path == ":memory:":
        scope = f"memory:{id(repo)}"
    else:
        scope = f"sqlite:{path or getattr(repo, 'ledger_url', '')}"
    return "sha256:" + hashlib.sha256(scope.encode("utf-8")).hexdigest()


def _decision_cache_revision_hash(repo: SQLiteLedgerRepository) -> str:
    if hasattr(repo, "revision_summaries"):
        revision_payload = repo.revision_summaries(list(DECISION_CACHE_REVISION_TABLES))
    else:  # pragma: no cover - compatibility fallback for non-SQLite repository implementations
        tables = set(repo.list_tables())
        revision_payload: dict[str, list[dict[str, Any]]] = {}
        for table in DECISION_CACHE_REVISION_TABLES:
            if table in tables:
                revision_payload[table] = repo.fetch_all(table)
    encoded = json.dumps(revision_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _scoped_decision_cache_key(repo: SQLiteLedgerRepository, decision_fragment_key: str) -> tuple[str, str, str]:
    scope_hash = _decision_cache_scope_hash(repo)
    revision_hash = _decision_cache_revision_hash(repo)
    return f"{decision_fragment_key}:{scope_hash}:{revision_hash}", scope_hash, revision_hash


def _public_cache_trace(trace: dict[str, Any], *, decision_fragment_key: str, scope_hash: str, revision_hash: str) -> dict[str, Any]:
    return {
        **trace,
        "decisionFragmentKey": decision_fragment_key,
        "cacheScope": "ledger",
        "cacheScopeHash": scope_hash,
        "cacheRevisionHash": revision_hash,
    }


def _record_serving_answer(repo: SQLiteLedgerRepository, request: JudgeQueryRequest, answer: dict[str, Any]) -> dict[str, Any]:
    created_at = _now()
    serving_run_id = _serving_run_id(answer, created_at)
    request_packet = sanitize_large_echo_value(request.model_dump(by_alias=True, warnings=False))
    if isinstance(request_packet, dict) and "sourceContext" in request_packet:
        request_packet["sourceContext"] = _safe_diagnostic_value(request_packet.get("sourceContext"))
    answer["servingLedger"] = {
        "schemaVersion": "s5-serving-ledger-ref-v1",
        "recorded": True,
        "servingRunId": serving_run_id,
        "createdAt": created_at,
    }
    repo.record_serving_query(
        serving_run_id=serving_run_id,
        created_at=created_at,
        request_packet=request_packet,
        answer_packet=answer,
    )
    return answer


def _empty_score_vector(
    *,
    source_resolved: bool,
    affectedness_status: str,
    excluded: bool = False,
    hard_issue_count: int = 0,
    soft_issue_count: int = 0,
) -> dict[str, float]:
    return default_score_vector(
        source_resolved=source_resolved,
        affectedness_status=affectedness_status,
        excluded=excluded,
        hard_issue_count=hard_issue_count,
        soft_issue_count=soft_issue_count,
    )


def _quality_gate(base_gate: str, diagnostics: list[dict[str, Any]], score_policy: dict[str, Any]) -> dict[str, Any]:
    gates = {base_gate, score_policy["gate"]}
    if "rejected" in gates:
        gate = "rejected"
    elif "accepted_with_caveats" in gates:
        gate = "accepted_with_caveats"
    else:
        gate = "accepted"
    return {
        "gate": gate,
        "hardFail": score_policy["hardFail"] or base_gate == "rejected",
        "diagnostics": [*diagnostics, *score_policy.get("diagnostics", [])],
        "scorePolicy": {
            "schemaVersion": score_policy["schemaVersion"],
            "phase": score_policy["phase"],
            "requestedProfile": score_policy["requestedProfile"],
            "appliedProfile": score_policy["appliedProfile"],
            "rejectedProfiles": score_policy["rejectedProfiles"],
            "policyId": score_policy["policyId"],
            "policyVersion": score_policy["policyVersion"],
            "policyHash": score_policy["policyHash"],
            "policySource": score_policy["policySource"],
            "policyPath": score_policy["policyPath"],
            "failedThresholds": score_policy["failedThresholds"],
            "thresholds": score_policy["thresholds"],
        },
    }


def _source_context_dict(request: JudgeQueryRequest) -> dict[str, Any]:
    if request.source_context is None:
        return {}
    return _safe_diagnostic_value(request.source_context.model_dump(by_alias=True))


def _question_text(request: JudgeQueryRequest) -> str | None:
    return redact_urls_in_text_for_log(request.question) if isinstance(request.question, str) else request.question


def _public_canonical_query(canonical_query: dict[str, Any]) -> dict[str, Any]:
    public_query = dict(canonical_query)
    normalized = dict(_safe_dict(canonical_query.get("normalized")))
    if "sourceContext" in normalized:
        normalized["sourceContext"] = _safe_diagnostic_value(normalized.get("sourceContext"))
    public_query["normalized"] = normalized
    return public_query


def _resolve_source_context(
    repo: SQLiteLedgerRepository,
    request: JudgeQueryRequest,
    normalized_source_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if request.source_context is None:
        return {"resolved": False}
    request_ctx = request.source_context.model_dump(by_alias=True)
    scalar_ctx = normalized_source_context or request_ctx
    return repo.get_source_kg_context(
        repository_snapshot_id=scalar_ctx.get("repositorySnapshotId"),
        build_context_id=scalar_ctx.get("buildContextId"),
        analysis_artifact_set_id=scalar_ctx.get("analysisArtifactSetId"),
        graph_node_ids=request_ctx.get("graphNodeIds") or None,
        evidence_snippet_ids=request_ctx.get("evidenceSnippetIds") or None,
        rich_ir_artifact_ids=request_ctx.get("richIrArtifactIds") or None,
    )


def _source_context_diagnostics(source_context: dict[str, Any]) -> list[dict[str, Any]]:
    resolution = source_context.get("contextResolution") or {}
    return list(resolution.get("diagnostics") or [])


def _purl_without_version(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith("pkg:") and "@" in text:
        return text.split("@", 1)[0]
    return text


def _conflict_relevance_ids(component: dict[str, Any], affectedness: dict[str, Any], threat_retrieval: dict[str, Any] | None) -> set[str]:
    ids: set[str] = set()
    for value in (
        component.get("packageIdentityId"),
        _purl_without_version(component.get("purl")),
        component.get("cpe"),
        component.get("sourceComponentId"),
        component.get("repoUrl"),
    ):
        if value:
            ids.add(str(value))

    identity_resolution = affectedness.get("identityResolution") or {}
    ids.update(str(item) for item in identity_resolution.get("hardAffectednessPackageIds") or [] if item)
    ids.update(str(item) for item in affectedness.get("candidatePackageIdentityIds") or [] if item)
    for item in affectedness.get("evidence") or []:
        for key in ("subjectId", "packageIdentityId"):
            if item.get(key):
                ids.add(str(item[key]))

    if threat_retrieval is not None:
        for item in threat_retrieval.get("candidateEvidence") or []:
            for key in ("packageIdentityId",):
                if item.get(key):
                    ids.add(str(item[key]))
            payload = item.get("payload") or {}
            for key in ("packageIdentityId",):
                if payload.get(key):
                    ids.add(str(payload[key]))
    return {item for item in ids if item}


def _value_mentions_relevance(value: dict[str, Any], relevance_ids: set[str]) -> bool:
    payload = value.get("value") or {}
    for key in ("subjectId", "objectId", "advisoryId", "packageIdentityId", "sourceComponentId"):
        candidate = payload.get(key)
        if candidate and str(candidate) in relevance_ids:
            return True
    return False


def _conflict_is_relevant(conflict: dict[str, Any], relevance_ids: set[str]) -> bool:
    if not relevance_ids:
        return False
    subject = str(conflict.get("subjectId") or "")
    if any(_subject_mentions_identifier(subject, identifier) for identifier in relevance_ids):
        return True
    return any(_value_mentions_relevance(value, relevance_ids) for value in conflict.get("conflictingValues") or [])


def _subject_mentions_identifier(subject: str, identifier: str) -> bool:
    return subject == identifier or subject.endswith(f":{identifier}") or f"{identifier}:" in subject


def _summarize_conflict(conflict: dict[str, Any]) -> dict[str, Any]:
    evidence = conflict.get("evidence") or {}
    conflicting_values = list(conflict.get("conflictingValues") or [])
    return {
        "schemaVersion": "s5-judge-conflict-summary-v1",
        "conflictRecordId": conflict.get("conflictRecordId"),
        "conflictKind": conflict.get("conflictKind"),
        "subjectId": conflict.get("subjectId"),
        "issueCode": conflict.get("issueCode"),
        "severity": conflict.get("severity"),
        "status": conflict.get("status"),
        "consumerPolicy": CONFLICT_CONSUMER_POLICY,
        "negativeEvidenceAllowed": False,
        "allowedEffects": list(evidence.get("allowedEffects") or []),
        "forbiddenEffects": list(evidence.get("forbiddenEffects") or []),
        "involvedLedgerRefs": list(evidence.get("involvedLedgerRefs") or []),
        "conflictingValueCount": len(conflicting_values),
        "conflictingValues": [
            {
                "ledgerTable": value.get("ledgerTable"),
                "ledgerId": value.get("ledgerId"),
                "value": value.get("value"),
                "provenance": value.get("provenance") or {},
            }
            for value in conflicting_values[:MAX_CONFLICTING_VALUES_IN_SUMMARY]
        ],
        "conflictingValuesTruncated": len(conflicting_values) > MAX_CONFLICTING_VALUES_IN_SUMMARY,
    }


def _relevant_open_conflicts(
    repo: SQLiteLedgerRepository,
    component: dict[str, Any],
    affectedness: dict[str, Any],
    threat_retrieval: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    conflict_report = detect_relation_conflicts(repo, record=True)
    relevance_ids = _conflict_relevance_ids(component, affectedness, threat_retrieval)
    return [
        _summarize_conflict(conflict)
        for conflict in conflict_report["conflicts"]
        if conflict.get("status") == "open" and _conflict_is_relevant(conflict, relevance_ids)
    ]


def _conflict_diagnostics(conflicts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "code": conflict["issueCode"],
            "severity": conflict["severity"],
            "message": "typed relation/affectedness conflict is open in the S5 evidence ledger",
            "conflictRecordId": conflict["conflictRecordId"],
            "conflictKind": conflict["conflictKind"],
            "subjectId": conflict["subjectId"],
            "consumerPolicy": conflict["consumerPolicy"],
            "negativeEvidenceAllowed": False,
        }
        for conflict in conflicts
    ]


def _gate_with_conflicts(base_gate: str, conflicts: list[dict[str, Any]]) -> str:
    if any(conflict.get("severity") == "hard" for conflict in conflicts):
        return "rejected"
    if conflicts and base_gate == "accepted":
        return "accepted_with_caveats"
    return base_gate


def _gate_with_source_context_diagnostics(base_gate: str, diagnostics: list[dict[str, Any]]) -> str:
    if diagnostics and base_gate == "accepted":
        return "accepted_with_caveats"
    return base_gate


def _source_context_degrades_answer(*, source_requested: bool, source_resolved: bool, diagnostics: list[dict[str, Any]]) -> bool:
    return source_requested and (not source_resolved or bool(diagnostics))


def _degrade_status_for_source_context(status: str, *, degraded: bool) -> str:
    if degraded and status == "complete":
        return "degraded_quality"
    return status


def _uncertainty_reason(verdict: str, reason: str, *, source_context_degraded: bool) -> str | None:
    if verdict == "unknown":
        return reason
    if source_context_degraded:
        return "Source KG context was requested but unresolved or diagnostic-bearing; answer is evidence-grounded but source context quality is degraded"
    return None


def _required_inputs(verdict: str, *, source_resolved: bool, source_context_degraded: bool) -> list[str]:
    if source_context_degraded:
        return ["complete_or_consistent_source_code_kg_context"]
    if verdict != "unknown":
        return []
    return ["component.version", "component.identity", "sourceContext"] if not source_resolved else ["additional affectedness evidence or re-query controls"]


def _append_partial_source_context_fallback(fallback_trace: list[dict[str, Any]], source_context: dict[str, Any]) -> None:
    diagnostics = _source_context_diagnostics(source_context)
    if not diagnostics:
        return
    if any(item.get("stage") == "source_code_kg_context" and item.get("fallback") == "partial_context_resolution" for item in fallback_trace):
        return
    fallback_trace.append(
        {
            "stage": "source_code_kg_context",
            "fallback": "partial_context_resolution",
            "silent": False,
            "diagnostics": diagnostics,
        }
    )


def _suppressed_by_exclude(evidence: list[dict[str, Any]], excludes: set[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    kept: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for item in evidence:
        advisory_keys = {
            key
            for key in (
                normalize_control_identifier(item.get("advisoryId")),
                normalize_control_identifier(item.get("advisoryExternalId")),
            )
            if key
        }
        for signal in item.get("riskSignals") or []:
            payload = signal.get("payload") or {}
            for key in (
                normalize_control_identifier(payload.get("cve")),
                normalize_control_identifier(payload.get("cveID")),
            ):
                if key:
                    advisory_keys.add(key)
        if advisory_keys & excludes:
            suppressed.append(item)
        else:
            kept.append(item)
    return kept, suppressed


def build_judge_answer(repo: SQLiteLedgerRepository, request: JudgeQueryRequest) -> dict[str, Any]:
    repo.initialize()
    canonical_query = build_canonical_query(request)
    decision_fragment_key = canonical_query["decisionFragmentKey"]
    detect_relation_conflicts(repo, record=True)
    scoped_cache_key, cache_scope_hash, cache_revision_hash = _scoped_decision_cache_key(repo, decision_fragment_key)
    cached_fragment, cache_trace = get_decision_fragment(scoped_cache_key)
    cache_trace = _public_cache_trace(
        cache_trace,
        decision_fragment_key=decision_fragment_key,
        scope_hash=cache_scope_hash,
        revision_hash=cache_revision_hash,
    )
    source_context = _resolve_source_context(repo, request, canonical_query["normalized"]["sourceContext"])
    source_resolved = bool(source_context.get("resolved"))
    excludes = set(canonical_query["controlSummary"]["accepted"]["exclude"])
    applied_controls = canonical_query["controlSummary"]
    requested_controls = applied_controls["requested"]
    fallback_trace: list[dict[str, Any]] = []
    if request.source_context is not None and not source_resolved:
        fallback_trace.append({"stage": "source_code_kg_context", "fallback": "unresolved_context", "silent": False})
    elif request.source_context is not None:
        _append_partial_source_context_fallback(fallback_trace, source_context)
    if applied_controls["rejected"]:
        fallback_trace.append({"stage": "control_validation", "fallback": "unsupported_controls_rejected", "silent": False, "rejected": applied_controls["rejected"]})
    reasoning_path: list[dict[str, Any]] = [
        {
            "step": "resolve_source_code_kg_context",
            "status": "resolved" if source_resolved else "not_requested_or_unresolved",
            "repositorySnapshotId": (source_context.get("repositorySnapshot") or {}).get("repositorySnapshotId"),
            "buildContextId": (source_context.get("buildContext") or {}).get("buildContextId"),
            "analysisArtifactSetId": (source_context.get("analysisArtifactSet") or {}).get("analysisArtifactSetId"),
        }
    ]

    component = {key: value for key, value in canonical_query["normalized"]["component"].items() if value is not None}
    missing_inputs: list[str] = []
    identity_fields = ("name", "purl", "packageIdentityId", "cpe", "repoUrl", "sourceComponentId")
    if not any(component.get(field) for field in identity_fields):
        missing_inputs.append("component.identity")
    if not component.get("version"):
        missing_inputs.append("component.version")

    if missing_inputs:
        answer = _unknown_answer(
            repo,
            request,
            source_context=source_context,
            missing_inputs=missing_inputs,
            reason="component identity/version evidence is insufficient for affectedness evaluation",
            requested_controls=requested_controls,
            accepted_controls=applied_controls["accepted"],
            control_effects=[],
            source_resolved=source_resolved,
            canonical_query=canonical_query,
            fallback_trace=fallback_trace,
        )
        return _record_serving_answer(repo, request, answer)

    if cached_fragment is not None:
        affectedness = cached_fragment["affectedness"]
        kept_evidence = cached_fragment["keptEvidence"]
        suppressed = cached_fragment["suppressedEvidence"]
        control_effects = cached_fragment["controlEffects"]
        reasoning_path.append({"step": "load_decision_fragment_cache", "status": "hit"})
        reasoning_path.append(
            {
                "step": "resolve_component_identity",
                "status": (affectedness.get("identityResolution") or {}).get("status"),
                "hardAffectednessPackageIds": (affectedness.get("identityResolution") or {}).get("hardAffectednessPackageIds", []),
                "cached": True,
            }
        )
    else:
        affectedness = query_affectedness(repo, component)
        reasoning_path.append(
            {
                "step": "resolve_component_identity",
                "status": (affectedness.get("identityResolution") or {}).get("status"),
                "hardAffectednessPackageIds": (affectedness.get("identityResolution") or {}).get("hardAffectednessPackageIds", []),
                "cached": False,
            }
        )
        reasoning_path.append(
            {
                "step": "evaluate_package_version_affectedness",
                "status": affectedness["affectedness"],
                "candidatePackageIdentityIds": affectedness.get("candidatePackageIdentityIds", []),
                "identityStatus": (affectedness.get("identityResolution") or {}).get("status"),
            }
        )
        evidence = list(affectedness.get("evidence") or [])
        kept_evidence, suppressed = _suppressed_by_exclude(evidence, excludes)
        control_effects = []
        if suppressed:
            control_effects.append(
                {
                    "control": "exclude",
                    "suppressedAdvisoryIds": sorted({item.get("advisoryId") for item in suppressed if item.get("advisoryId")}),
                    "suppressedExternalIds": sorted({item.get("advisoryExternalId") for item in suppressed if item.get("advisoryExternalId")}),
                }
            )
            reasoning_path.append({"step": "apply_exclude_controls", "status": "suppressed", "suppressedCount": len(suppressed)})
        cache_trace = store_decision_fragment(
            scoped_cache_key,
            {
                "affectedness": affectedness,
                "keptEvidence": kept_evidence,
                "suppressedEvidence": suppressed,
                "controlEffects": control_effects,
            },
            cache_trace,
        )
        cache_trace = _public_cache_trace(
            cache_trace,
            decision_fragment_key=decision_fragment_key,
            scope_hash=cache_scope_hash,
            revision_hash=cache_revision_hash,
        )

    if affectedness["affectedness"] == "affected" and kept_evidence:
        verdict = "affected"
        status = "complete"
        quality_gate = "accepted"
        reason = "source-backed affectedness range contains the requested component version"
    elif affectedness["affectedness"] == "known_not_affected" and kept_evidence:
        verdict = "not_affected"
        status = "complete"
        quality_gate = "accepted"
        reason = "source-backed affectedness ranges exclude the requested component version"
    elif suppressed and not kept_evidence:
        verdict = "unknown"
        status = "requires_requery"
        quality_gate = "accepted_with_caveats"
        reason = "all otherwise matching advisories were suppressed by explicit exclude controls"
    else:
        verdict = "unknown"
        status = "requires_requery"
        quality_gate = "accepted_with_caveats"
        reason = "affectedness evidence is insufficient for the requested component/version"

    source_evidence = _source_evidence(source_context)
    threat_retrieval = build_threat_retrieval_evidence(
        repo,
        component,
        affectedness,
        affectedness.get("identityResolution"),
        applied_controls,
        query_terms_extra=canonical_query["normalized"].get("questionTerms") or [],
    )
    reasoning_path.append(
        {
            "step": "assemble_threat_kb_context",
            "status": "complete" if threat_retrieval["candidateEvidence"] else "no_context",
            "methodsUsed": threat_retrieval["methodsUsed"],
            "diagnostics": threat_retrieval["diagnostics"],
        }
    )
    source_context_diagnostics = _source_context_diagnostics(source_context)
    source_context_degraded = _source_context_degrades_answer(
        source_requested=request.source_context is not None,
        source_resolved=source_resolved,
        diagnostics=source_context_diagnostics,
    )
    status = _degrade_status_for_source_context(status, degraded=source_context_degraded)
    conflicts = _relevant_open_conflicts(repo, component, affectedness, threat_retrieval)
    conflict_diagnostics = _conflict_diagnostics(conflicts)
    hard_conflict_count = sum(1 for conflict in conflicts if conflict.get("severity") == "hard")
    soft_conflict_count = len(conflicts) - hard_conflict_count
    quality_gate = _gate_with_source_context_diagnostics(quality_gate, source_context_diagnostics)
    if source_context_degraded:
        quality_gate = _gate_with_source_context_diagnostics(quality_gate, [{"code": "SOURCE_KG_CONTEXT_DEGRADED"}])
    quality_gate = _gate_with_conflicts(quality_gate, conflicts)
    score_vector = _empty_score_vector(
        source_resolved=source_resolved,
        affectedness_status=affectedness["affectedness"],
        excluded=bool(suppressed),
        hard_issue_count=hard_conflict_count,
        soft_issue_count=len(source_context_diagnostics) + soft_conflict_count,
    )
    score_policy = evaluate_score_vector(score_vector, phase="serving", profile=settings.default_scoring_profile)
    answer = {
        "schemaVersion": SCHEMA_VERSION,
        "verdictAuthority": VERDICT_AUTHORITY,
        "canonicalQuery": _public_canonical_query(canonical_query),
        "decisionFragmentKey": decision_fragment_key,
        "cacheTrace": cache_trace,
        "verdict": verdict,
        "status": status,
        "reason": reason,
        "queryContext": {
            "question": _question_text(request),
            "component": component,
            "sourceContext": _source_context_dict(request),
        },
        "appliedControls": {
            "requested": requested_controls,
            "accepted": applied_controls["accepted"],
            "rejected": applied_controls["rejected"],
            "ignored": applied_controls["ignored"],
        },
        "controlEffects": control_effects,
        "evidence": {
            "affectedness": kept_evidence,
            "suppressedAffectedness": suppressed,
            "sourceCodeKg": source_evidence,
            "identityResolution": affectedness.get("identityResolution"),
            "threatRetrieval": threat_retrieval,
        },
        "reasoningPath": reasoning_path,
        "fallbackTrace": fallback_trace,
        "uncertainty": {
            "reason": _uncertainty_reason(verdict, reason, source_context_degraded=source_context_degraded),
            "evidenceGaps": _evidence_gaps(verdict, source_resolved, source_context_degraded=source_context_degraded),
            "requiredInputs": _required_inputs(verdict, source_resolved=source_resolved, source_context_degraded=source_context_degraded),
            "conflicts": conflicts,
        },
        "followUpAffordances": _follow_up_affordances(
            verdict,
            missing_inputs=[],
            source_resolved=source_resolved,
            source_context_degraded=source_context_degraded,
        ),
        "qualityGate": _quality_gate(quality_gate, [*affectedness.get("diagnostics", []), *source_context_diagnostics, *conflict_diagnostics], score_policy),
        "scoreVector": score_vector,
        "forbiddenInferences": BASELINE_FORBIDDEN_INFERENCES,
    }
    return _record_serving_answer(repo, request, answer)


def _unknown_answer(
    repo: SQLiteLedgerRepository,
    request: JudgeQueryRequest,
    *,
    source_context: dict[str, Any],
    missing_inputs: list[str],
    reason: str,
    requested_controls: dict[str, Any],
    accepted_controls: dict[str, Any],
    control_effects: list[dict[str, Any]],
    source_resolved: bool,
    canonical_query: dict[str, Any] | None = None,
    fallback_trace: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    canonical_query = canonical_query or build_canonical_query(request)
    component = {key: value for key, value in canonical_query["normalized"]["component"].items() if value is not None}
    identity_resolution = resolve_component_identity(repo, component) if (component or "component.identity" in missing_inputs) else None
    threat_retrieval = None
    question_terms_extra = canonical_query["normalized"].get("questionTerms") or []
    if component or question_terms_extra:
        threat_retrieval = build_threat_retrieval_evidence(
            repo,
            component,
            {"evidence": [], "identityResolution": identity_resolution, "affectedness": "unknown"},
            identity_resolution,
            canonical_query["controlSummary"],
            query_terms_extra=question_terms_extra,
        )
    fallback_trace = list(fallback_trace or [])
    if request.source_context is not None and not source_resolved and not any(item.get("fallback") == "unresolved_context" for item in fallback_trace):
        fallback_trace.append({"stage": "source_code_kg_context", "fallback": "unresolved_context", "silent": False})
    elif request.source_context is not None:
        _append_partial_source_context_fallback(fallback_trace, source_context)
    if canonical_query["controlSummary"]["rejected"] and not any(item.get("fallback") == "unsupported_controls_rejected" for item in fallback_trace):
        fallback_trace.append(
            {
                "stage": "control_validation",
                "fallback": "unsupported_controls_rejected",
                "silent": False,
                "rejected": canonical_query["controlSummary"]["rejected"],
            }
        )
    source_context_diagnostics = _source_context_diagnostics(source_context)
    source_context_degraded = _source_context_degrades_answer(
        source_requested=request.source_context is not None,
        source_resolved=source_resolved,
        diagnostics=source_context_diagnostics,
    )
    affectedness_for_conflicts = {
        "evidence": [],
        "identityResolution": identity_resolution,
        "candidatePackageIdentityIds": (identity_resolution or {}).get("hardAffectednessPackageIds", []),
        "affectedness": "unknown",
    }
    conflicts = _relevant_open_conflicts(repo, component, affectedness_for_conflicts, threat_retrieval)
    conflict_diagnostics = _conflict_diagnostics(conflicts)
    hard_conflict_count = sum(1 for conflict in conflicts if conflict.get("severity") == "hard")
    soft_conflict_count = len(conflicts) - hard_conflict_count
    score_vector = _empty_score_vector(
        source_resolved=source_resolved,
        affectedness_status="unknown",
        hard_issue_count=hard_conflict_count,
        soft_issue_count=len(source_context_diagnostics) + soft_conflict_count,
    )
    score_policy = evaluate_score_vector(score_vector, phase="serving", profile=settings.default_scoring_profile)
    cache_scope_hash = _decision_cache_scope_hash(repo)
    cache_revision_hash = _decision_cache_revision_hash(repo)
    cache_trace = _public_cache_trace(
        {
            "schemaVersion": "s5-decision-cache-trace-v1",
            "decisionFragmentKey": canonical_query["decisionFragmentKey"],
            "hit": False,
            "miss": True,
            "stored": False,
            "reason": "missing_inputs_not_cached",
        },
        decision_fragment_key=canonical_query["decisionFragmentKey"],
        scope_hash=cache_scope_hash,
        revision_hash=cache_revision_hash,
    )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "verdictAuthority": VERDICT_AUTHORITY,
        "canonicalQuery": _public_canonical_query(canonical_query),
        "decisionFragmentKey": canonical_query["decisionFragmentKey"],
        "cacheTrace": cache_trace,
        "verdict": "unknown",
        "status": "requires_requery" if missing_inputs else "insufficient_input",
        "reason": reason,
        "queryContext": {
            "question": _question_text(request),
            "component": dict(request.component or {}),
            "sourceContext": _source_context_dict(request),
        },
        "appliedControls": {"requested": requested_controls, "accepted": accepted_controls, "rejected": canonical_query["controlSummary"]["rejected"], "ignored": canonical_query["controlSummary"]["ignored"]},
        "controlEffects": control_effects,
        "evidence": {
            "affectedness": [],
            "suppressedAffectedness": [],
            "sourceCodeKg": _source_evidence(source_context),
            "identityResolution": identity_resolution,
            **({"threatRetrieval": threat_retrieval} if threat_retrieval is not None else {}),
        },
        "reasoningPath": [
            {
                "step": "resolve_source_code_kg_context",
                "status": "resolved" if source_resolved else "not_requested_or_unresolved",
            },
            {
                "step": "resolve_component_identity",
                "status": (identity_resolution or {}).get("status"),
                "hardAffectednessPackageIds": (identity_resolution or {}).get("hardAffectednessPackageIds", []),
            },
            *(
                [
                    {
                        "step": "assemble_threat_kb_context",
                        "status": "complete" if threat_retrieval and threat_retrieval["candidateEvidence"] else "no_context",
                        "methodsUsed": (threat_retrieval or {}).get("methodsUsed", []),
                        "diagnostics": (threat_retrieval or {}).get("diagnostics", []),
                    }
                ]
                if threat_retrieval is not None
                else []
            ),
            {"step": "check_required_component_inputs", "status": "missing", "missingInputs": missing_inputs},
        ],
        "fallbackTrace": fallback_trace,
        "uncertainty": {
            "reason": reason,
            "evidenceGaps": [
                *missing_inputs,
                *(["source code kg context"] if source_context_degraded and "source code kg context" not in set(missing_inputs) else []),
            ],
            "requiredInputs": [
                *missing_inputs,
                *(
                    ["complete_or_consistent_source_code_kg_context"]
                    if source_context_degraded and "complete_or_consistent_source_code_kg_context" not in set(missing_inputs)
                    else []
                ),
            ],
            "conflicts": conflicts,
        },
        "followUpAffordances": _follow_up_affordances(
            "unknown",
            missing_inputs=missing_inputs,
            source_resolved=source_resolved,
            source_context_degraded=source_context_degraded,
        ),
        "qualityGate": _quality_gate(
            _gate_with_conflicts("accepted_with_caveats", conflicts),
            [{"code": "GROUNDED_UNKNOWN", "missingInputs": missing_inputs}, *source_context_diagnostics, *conflict_diagnostics],
            score_policy,
        ),
        "scoreVector": score_vector,
        "forbiddenInferences": BASELINE_FORBIDDEN_INFERENCES,
    }


def _source_evidence(source_context: dict[str, Any]) -> dict[str, Any]:
    return {
        "repositorySnapshot": source_context.get("repositorySnapshot"),
        "buildContext": source_context.get("buildContext"),
        "analysisArtifactSet": source_context.get("analysisArtifactSet"),
        "sourceArtifacts": source_context.get("sourceArtifacts", []),
        "graphNodes": source_context.get("graphNodes", []),
        "graphEdges": source_context.get("graphEdges", []),
        "evidenceSnippets": source_context.get("evidenceSnippets", []),
        "richIrArtifacts": source_context.get("richIrArtifacts", []),
        "contextResolution": source_context.get("contextResolution"),
        "resolved": bool(source_context.get("resolved")),
    }


def _threat_advisory_keys(item: dict[str, Any]) -> set[str]:
    if not isinstance(item, dict):
        return set()
    keys = {
        normalize_control_identifier(item.get("advisoryId")),
        normalize_control_identifier(item.get("externalId")),
    }
    keys.update(
        key
        for key in (normalize_control_identifier(alias) for alias in item.get("aliases", []) or [])
        if key
    )
    return {key for key in keys if key}


def _risk_signal_keys(item: dict[str, Any]) -> set[str]:
    if not isinstance(item, dict):
        return set()
    payload = item.get("payload") or {}
    if not isinstance(payload, dict):
        payload = {}
    keys = {
        normalize_control_identifier(item.get("advisoryId")),
        normalize_control_identifier(payload.get("cve")),
        normalize_control_identifier(payload.get("cveID")),
    }
    return {key for key in keys if key}


def _evidence_gaps(verdict: str, source_resolved: bool, *, source_context_degraded: bool = False) -> list[str]:
    gaps: list[str] = []
    if verdict == "unknown":
        gaps.append("affectedness evidence")
    if not source_resolved or source_context_degraded:
        gaps.append("source code kg context")
    return gaps


def _follow_up_affordances(
    verdict: str,
    *,
    missing_inputs: list[str],
    source_resolved: bool,
    source_context_degraded: bool = False,
) -> list[dict[str, Any]]:
    affordances = []
    if source_context_degraded:
        affordances.append(
            {
                "ownerLane": "S3/S4",
                "requestKind": "source_context_enrichment",
                "reason": "Source KG context was requested but unresolved, partial, inconsistent, or truncated",
            }
        )
    if verdict != "unknown":
        return affordances
    if "component.version" in missing_inputs:
        affordances.append(
            {
                "ownerLane": "S4",
                "requestKind": "library_version_lookup",
                "reason": "component version is required before S5 can prove affectedness",
            }
        )
    if source_resolved:
        affordances.append(
            {
                "ownerLane": "S4",
                "requestKind": "source_diff_or_vendored_patch_check",
                "reason": "Source KG is available; unresolved version/diff/vendored patch facts can be refined by S4",
            }
        )
    else:
        affordances.append(
            {
                "ownerLane": "S3/S4",
                "requestKind": "source_context_enrichment",
                "reason": "Source KG context was absent or unresolved",
            }
        )
    return affordances


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _answer_evidence(answer: dict[str, Any]) -> dict[str, Any]:
    return _safe_dict(answer.get("evidence"))


def _source_code_kg_evidence(answer: dict[str, Any]) -> dict[str, Any]:
    return _safe_dict(_answer_evidence(answer).get("sourceCodeKg"))


def _safe_diagnostic_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_large_echo_value(redact_url_for_log(value))
    if isinstance(value, list):
        return sanitize_large_echo_value([_safe_diagnostic_value(item) for item in value])
    if isinstance(value, dict):
        safe_value = {redact_url_for_log(str(key)): _safe_diagnostic_value(item) for key, item in value.items()}
        return sanitize_large_echo_value(safe_value)
    return value


def _threat_retrieval_validation_issues(answer: dict[str, Any]) -> list[dict[str, Any]]:
    threat = _safe_dict(_answer_evidence(answer).get("threatRetrieval"))
    if not threat:
        return []
    issues: list[dict[str, Any]] = []
    candidates = _safe_dict_list(threat.get("candidateEvidence"))
    trace = _safe_dict(threat.get("retrievalTrace"))

    def safe_authority(value: Any) -> Any:
        return redact_url_for_log(value) if isinstance(value, str) else value

    def safe_issue_metadata(value: Any) -> Any:
        return _safe_diagnostic_value(value)

    def redacted_issue(issue: dict[str, Any]) -> dict[str, Any]:
        redacted = {
            key: safe_issue_metadata(value) if key in THREAT_RETRIEVAL_DIAGNOSTIC_METADATA_REDACTION_FIELDS else value
            for key, value in issue.items()
        }
        if "field" not in redacted:
            field = THREAT_RETRIEVAL_VALIDATOR_ISSUE_FIELDS.get(str(redacted.get("code") or ""))
            if field:
                redacted["field"] = field
        elif isinstance(redacted.get("field"), str):
            redacted["field"] = THREAT_RETRIEVAL_RELATIVE_ISSUE_FIELDS.get(redacted["field"], redacted["field"])
        return redacted

    def context_authority_issue(field: str, actual_authority: Any, **metadata: Any) -> None:
        if actual_authority == THREAT_RETRIEVAL_AUTHORITY:
            return
        issue = {
            "code": "THREAT_RETRIEVAL_AUTHORITY_INVALID",
            "field": field,
            "expectedAuthority": THREAT_RETRIEVAL_AUTHORITY,
            "actualAuthority": safe_authority(actual_authority),
        }
        issue.update({key: safe_authority(value) for key, value in metadata.items() if value is not None})
        issues.append(issue)

    def check_context_authority_items(field: str, records: Any, *metadata_keys: str) -> None:
        if not isinstance(records, list):
            return
        for record in records:
            if not isinstance(record, dict):
                continue
            context_authority_issue(
                field,
                record.get("authority"),
                **{key: record.get(key) for key in metadata_keys},
            )

    context_authority_issue("evidence.threatRetrieval.authority", threat.get("authority"))
    context_authority_issue("evidence.threatRetrieval.retrievalTrace.authority", trace.get("authority"))
    check_context_authority_items(
        "evidence.threatRetrieval.candidateEvidence[].authority",
        candidates,
        "advisoryId",
        "externalId",
    )
    check_context_authority_items(
        "evidence.threatRetrieval.suppressedCandidateEvidence[].authority",
        threat.get("suppressedCandidateEvidence"),
        "advisoryId",
        "externalId",
    )
    check_context_authority_items(
        "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].authority",
        trace.get("candidatePoolPreview"),
        "candidatePoolRank",
        "advisoryId",
        "externalId",
    )
    check_context_authority_items(
        "evidence.threatRetrieval.weaknessSemantics[].authority",
        threat.get("weaknessSemantics"),
        "weaknessId",
        "externalId",
    )
    check_context_authority_items(
        "evidence.threatRetrieval.attackSemantics[].authority",
        threat.get("attackSemantics"),
        "attackPatternId",
        "externalId",
    )
    if threat.get("negativeEvidenceAllowed") is not False:
        issues.append(
            {
                "code": "THREAT_RETRIEVAL_NEGATIVE_EVIDENCE_ALLOWED",
                "field": "evidence.threatRetrieval.negativeEvidenceAllowed",
                "actualValue": threat.get("negativeEvidenceAllowed"),
            }
        )
    if trace.get("negativeEvidenceAllowed") is not False:
        issues.append(
            {
                "code": "THREAT_RETRIEVAL_NEGATIVE_EVIDENCE_ALLOWED",
                "field": "evidence.threatRetrieval.retrievalTrace.negativeEvidenceAllowed",
                "actualValue": trace.get("negativeEvidenceAllowed"),
            }
        )
    excludes = {key for key in (normalize_control_identifier(item) for item in _accepted_exclude_controls(answer)) if key}
    if trace.get("returnedCount") != len(candidates):
        issues.append({"code": "THREAT_RETRIEVAL_RETURNED_COUNT_MISMATCH"})
    required_trace_fields = {
        "methodsSucceeded": list,
        "filtersApplied": list,
        "matchedTerms": list,
        "relationMethods": list,
        "embeddingScope": str,
        "profileBoostsApplied": list,
        "projectionState": dict,
        "providerState": dict,
    }
    for field, expected_type in required_trace_fields.items():
        if not isinstance(trace.get(field), expected_type):
            issues.append({"code": "THREAT_RETRIEVAL_TRACE_FIELD_MISSING", "field": field})
    if isinstance(trace.get("methodsUsed"), list) and isinstance(trace.get("methodsSucceeded"), list):
        missing_succeeded = sorted(set(trace["methodsUsed"]) - set(trace["methodsSucceeded"]))
        if missing_succeeded:
            issues.append({"code": "THREAT_RETRIEVAL_METHODS_SUCCEEDED_MISMATCH", "missingMethods": missing_succeeded})
    if trace.get("embeddingUsed") is False and trace.get("embeddingScope") != "none":
        issues.append({"code": "THREAT_RETRIEVAL_EMBEDDING_SCOPE_MISMATCH", "embeddingScope": trace.get("embeddingScope")})
    if isinstance(trace.get("matchedTerms"), list) and trace.get("matchedTerms") != threat.get("queryTerms"):
        issues.append({"code": "THREAT_RETRIEVAL_MATCHED_TERMS_MISMATCH"})
    if isinstance(trace.get("topK"), int) and len(candidates) > trace["topK"]:
        issues.append({"code": "THREAT_RETRIEVAL_TOPK_OVERFLOW"})
    candidate_set_size = trace.get("candidateSetSize")
    candidate_set_total_count = trace.get("candidateSetTotalCount")
    candidate_pool_size = trace.get("candidatePoolSize")
    candidate_pool_policy = trace.get("candidatePoolPolicy") if isinstance(trace.get("candidatePoolPolicy"), dict) else {}
    policy_candidate_pool_k = candidate_pool_policy.get("candidatePoolK")
    if (
        not isinstance(candidate_set_size, int)
        or not isinstance(candidate_set_total_count, int)
        or not isinstance(candidate_pool_size, int)
        or not isinstance(policy_candidate_pool_k, int)
        or candidate_set_total_count != candidate_set_size
        or candidate_pool_size > candidate_set_size
        or candidate_pool_size > policy_candidate_pool_k
    ):
        issues.append(
            {
                "code": "THREAT_RETRIEVAL_CANDIDATE_POOL_ACCOUNTING_MISMATCH",
                "candidateSetSize": candidate_set_size,
                "candidateSetTotalCount": candidate_set_total_count,
                "candidatePoolSize": candidate_pool_size,
                "policyCandidatePoolK": policy_candidate_pool_k,
            }
        )
    if isinstance(candidate_set_size, int) and isinstance(candidate_pool_size, int):
        expected_pool_truncated = candidate_set_size > candidate_pool_size
        truncated_pool_size_mismatch = (
            expected_pool_truncated
            and isinstance(policy_candidate_pool_k, int)
            and candidate_pool_size != policy_candidate_pool_k
        )
        if bool(trace.get("candidatePoolTruncated")) != expected_pool_truncated or truncated_pool_size_mismatch or (
            expected_pool_truncated and trace.get("candidatePoolTruncationReason") != "candidate_pool_k_cap"
        ):
            issues.append(
                {
                    "code": "THREAT_RETRIEVAL_CANDIDATE_POOL_TRUNCATION_MISMATCH",
                    "expectedTruncated": expected_pool_truncated,
                    "actualTruncated": trace.get("candidatePoolTruncated"),
                    "actualReason": trace.get("candidatePoolTruncationReason"),
                }
            )
    rerank_scores_by_rank: list[tuple[float, dict[str, Any]]] = []
    for expected_rank, candidate in enumerate(candidates, start=1):
        if excludes & _threat_advisory_keys(candidate):
            issues.append({"code": "THREAT_RETRIEVAL_EXCLUDED_CANDIDATE_RETURNED", "externalId": candidate.get("externalId")})
        if candidate.get("rank") != expected_rank:
            issues.append(
                {
                    "code": "THREAT_RETRIEVAL_RANK_SEQUENCE_INVALID",
                    "externalId": candidate.get("externalId"),
                    "expectedRank": expected_rank,
                    "actualRank": candidate.get("rank"),
                }
            )
        methods = candidate.get("retrievalMethods") or []
        score = candidate.get("scoreBreakdown") or {}
        if methods and "methodWeight" in score:
            expected_weight = method_rank_weight(str(methods[0]))
            if score.get("methodWeight") != expected_weight:
                issues.append(
                    {
                        "code": "THREAT_RETRIEVAL_METHOD_WEIGHT_MISMATCH",
                        "externalId": candidate.get("externalId"),
                        "method": methods[0],
                        "expectedMethodWeight": expected_weight,
                        "actualMethodWeight": score.get("methodWeight"),
                    }
                )
        if score:
            try:
                expected_score = round(
                    float(score.get("baseScore") or 0.0)
                    + float(score.get("methodWeight") or 0.0)
                    + float(score.get("lexicalBoost") or 0.0)
                    + float(score.get("profileBoost") or 0.0),
                    6,
                )
                if round(float(score.get("finalRerankScore")), 6) != expected_score:
                    issues.append({"code": "THREAT_RETRIEVAL_SCORE_BREAKDOWN_MISMATCH", "externalId": candidate.get("externalId")})
                if "rerankScore" in candidate and round(float(candidate.get("rerankScore")), 6) != expected_score:
                    issues.append({"code": "THREAT_RETRIEVAL_RERANK_SCORE_MISMATCH", "externalId": candidate.get("externalId")})
                rerank_scores_by_rank.append((expected_score, candidate))
            except (TypeError, ValueError):
                issues.append({"code": "THREAT_RETRIEVAL_SCORE_BREAKDOWN_INVALID", "externalId": candidate.get("externalId")})
        if any(field in candidate for field in ("equivalenceKey", "equivalentSourceKinds", "equivalentAdvisoryCount", "equivalentAdvisories")):
            equivalents = _safe_dict_list(candidate.get("equivalentAdvisories"))
            actual_count = candidate.get("equivalentAdvisoryCount")
            limit = candidate.get("equivalentAdvisoryLimit")
            truncated = bool(candidate.get("equivalentAdvisoriesTruncated"))
            visible_count = len(equivalents) + 1
            if not isinstance(actual_count, int) or actual_count < visible_count:
                issues.append(
                    {
                        "code": "THREAT_RETRIEVAL_EQUIVALENT_COUNT_MISMATCH",
                        "externalId": candidate.get("externalId"),
                        "minimumCount": visible_count,
                        "actualCount": actual_count,
                    }
                )
            if isinstance(limit, int) and len(equivalents) > limit:
                issues.append({"code": "THREAT_RETRIEVAL_EQUIVALENT_LIMIT_OVERFLOW", "externalId": candidate.get("externalId")})
            if isinstance(actual_count, int):
                expected_truncated = actual_count > visible_count
                if truncated != expected_truncated:
                    issues.append(
                        {
                            "code": "THREAT_RETRIEVAL_EQUIVALENT_TRUNCATION_MISMATCH",
                            "externalId": candidate.get("externalId"),
                            "expectedTruncated": expected_truncated,
                            "actualTruncated": truncated,
                        }
                    )
            expected_source_kinds = sorted(
                {
                    str(kind)
                    for kind in [
                        candidate.get("sourceKind"),
                        *(item.get("sourceKind") for item in equivalents),
                    ]
                    if kind
                }
            )
            actual_source_kinds = sorted(candidate.get("equivalentSourceKinds") or [])
            source_kind_mismatch = (
                not set(expected_source_kinds) <= set(actual_source_kinds)
                if truncated
                else actual_source_kinds != expected_source_kinds
            )
            if source_kind_mismatch:
                issues.append(
                    {
                        "code": "THREAT_RETRIEVAL_EQUIVALENT_SOURCE_KINDS_MISMATCH",
                        "externalId": candidate.get("externalId"),
                        "expectedSourceKinds": expected_source_kinds,
                        "actualSourceKinds": actual_source_kinds,
                    }
                )
            for equivalent in equivalents:
                if equivalent.get("authority") != THREAT_RETRIEVAL_AUTHORITY:
                    issues.append(
                        {
                            "code": "THREAT_RETRIEVAL_EQUIVALENT_AUTHORITY_INVALID",
                            "field": "evidence.threatRetrieval.candidateEvidence[].equivalentAdvisories[].authority",
                            "advisoryId": safe_authority(equivalent.get("advisoryId")),
                            "externalId": safe_authority(equivalent.get("externalId")),
                            "expectedAuthority": THREAT_RETRIEVAL_AUTHORITY,
                            "actualAuthority": safe_authority(equivalent.get("authority")),
                        }
                    )
                if excludes & _threat_advisory_keys(equivalent):
                    issues.append({"code": "THREAT_RETRIEVAL_EXCLUDED_EQUIVALENT_RETURNED", "externalId": equivalent.get("externalId")})
    equivalent_response_limit = trace.get("equivalentAdvisoryResponseLimit")
    equivalent_returned_count = trace.get("equivalentAdvisoryReturnedCount")
    actual_equivalent_returned_count = sum(len(_safe_dict_list(candidate.get("equivalentAdvisories"))) for candidate in candidates)
    expected_equivalent_response_truncated = any(bool(candidate.get("equivalentAdvisoriesTruncated")) for candidate in candidates)
    if (
        not isinstance(equivalent_response_limit, int)
        or not isinstance(equivalent_returned_count, int)
        or equivalent_returned_count != actual_equivalent_returned_count
        or actual_equivalent_returned_count > equivalent_response_limit
        or bool(trace.get("equivalentAdvisoryResponseTruncated")) != expected_equivalent_response_truncated
    ):
        issues.append(
            {
                "code": "THREAT_RETRIEVAL_EQUIVALENT_RESPONSE_BUDGET_MISMATCH",
                "expectedReturnedCount": actual_equivalent_returned_count,
                "actualReturnedCount": equivalent_returned_count,
                "responseLimit": equivalent_response_limit,
                "expectedTruncated": expected_equivalent_response_truncated,
                "actualTruncated": trace.get("equivalentAdvisoryResponseTruncated"),
            }
        )
    risk_signals = _safe_dict_list(threat.get("riskSignals"))
    for signal in risk_signals:
        if excludes & _risk_signal_keys(signal):
            issues.append({"code": "THREAT_RETRIEVAL_EXCLUDED_RISK_SIGNAL_RETURNED", "riskSignalId": signal.get("riskSignalId")})
        if signal.get("authority") != RISK_SIGNAL_AUTHORITY:
            issues.append(
                {
                    "code": "THREAT_RETRIEVAL_RISK_SIGNAL_AUTHORITY_INVALID",
                    "field": "evidence.threatRetrieval.riskSignals[].authority",
                    "riskSignalId": safe_authority(signal.get("riskSignalId")),
                    "advisoryId": safe_authority(signal.get("advisoryId")),
                    "expectedAuthority": RISK_SIGNAL_AUTHORITY,
                    "actualAuthority": safe_authority(signal.get("authority")),
                }
            )
    risk_signal_total_count = trace.get("riskSignalTotalCount")
    risk_signal_returned_count = trace.get("riskSignalReturnedCount")
    risk_signal_response_limit = trace.get("riskSignalResponseLimit")
    actual_risk_signal_returned_count = len(risk_signals)
    expected_risk_signal_response_truncated = (
        isinstance(risk_signal_total_count, int)
        and risk_signal_total_count > actual_risk_signal_returned_count
    )
    if (
        not isinstance(risk_signal_total_count, int)
        or not isinstance(risk_signal_returned_count, int)
        or not isinstance(risk_signal_response_limit, int)
        or risk_signal_returned_count != actual_risk_signal_returned_count
        or actual_risk_signal_returned_count > risk_signal_response_limit
        or risk_signal_total_count < actual_risk_signal_returned_count
        or bool(trace.get("riskSignalResponseTruncated")) != expected_risk_signal_response_truncated
    ):
        issues.append(
            {
                "code": "THREAT_RETRIEVAL_RISK_SIGNAL_RESPONSE_BUDGET_MISMATCH",
                "expectedReturnedCount": actual_risk_signal_returned_count,
                "actualReturnedCount": risk_signal_returned_count,
                "totalCount": risk_signal_total_count,
                "responseLimit": risk_signal_response_limit,
                "expectedTruncated": expected_risk_signal_response_truncated,
                "actualTruncated": trace.get("riskSignalResponseTruncated"),
            }
        )
    suppressed_candidate_total_count = trace.get("suppressedCandidateTotalCount")
    suppressed_candidate_returned_count = trace.get("suppressedCandidateReturnedCount")
    suppressed_candidate_response_limit = trace.get("suppressedCandidateResponseLimit")
    actual_suppressed_candidate_returned_count = len(_safe_dict_list(threat.get("suppressedCandidateEvidence")))
    expected_suppressed_candidate_response_truncated = (
        isinstance(suppressed_candidate_total_count, int)
        and suppressed_candidate_total_count > actual_suppressed_candidate_returned_count
    )
    if (
        not isinstance(suppressed_candidate_total_count, int)
        or not isinstance(suppressed_candidate_returned_count, int)
        or not isinstance(suppressed_candidate_response_limit, int)
        or suppressed_candidate_returned_count != actual_suppressed_candidate_returned_count
        or actual_suppressed_candidate_returned_count > suppressed_candidate_response_limit
        or suppressed_candidate_total_count < actual_suppressed_candidate_returned_count
        or bool(trace.get("suppressedCandidateResponseTruncated")) != expected_suppressed_candidate_response_truncated
    ):
        issues.append(
            {
                "code": "THREAT_RETRIEVAL_SUPPRESSED_RESPONSE_BUDGET_MISMATCH",
                "expectedReturnedCount": actual_suppressed_candidate_returned_count,
                "actualReturnedCount": suppressed_candidate_returned_count,
                "totalCount": suppressed_candidate_total_count,
                "responseLimit": suppressed_candidate_response_limit,
                "expectedTruncated": expected_suppressed_candidate_response_truncated,
                "actualTruncated": trace.get("suppressedCandidateResponseTruncated"),
            }
        )
    for prefix, evidence_field in (("weaknessSemantic", "weaknessSemantics"), ("attackSemantic", "attackSemantics")):
        total_count = trace.get(f"{prefix}TotalCount")
        returned_count = trace.get(f"{prefix}ReturnedCount")
        response_limit = trace.get(f"{prefix}ResponseLimit")
        actual_returned_count = len(_safe_dict_list(threat.get(evidence_field)))
        expected_truncated = isinstance(total_count, int) and total_count > actual_returned_count
        if (
            not isinstance(total_count, int)
            or not isinstance(returned_count, int)
            or not isinstance(response_limit, int)
            or returned_count != actual_returned_count
            or actual_returned_count > response_limit
            or total_count < actual_returned_count
            or bool(trace.get(f"{prefix}ResponseTruncated")) != expected_truncated
        ):
            issues.append(
                {
                    "code": "THREAT_RETRIEVAL_SEMANTIC_RESPONSE_BUDGET_MISMATCH",
                    "field": evidence_field,
                    "expectedReturnedCount": actual_returned_count,
                    "actualReturnedCount": returned_count,
                    "totalCount": total_count,
                    "responseLimit": response_limit,
                    "expectedTruncated": expected_truncated,
                    "actualTruncated": trace.get(f"{prefix}ResponseTruncated"),
                }
            )
    preview = trace.get("candidatePoolPreview")
    if not isinstance(preview, list):
        issues.append({"code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_MISSING"})
    else:
        if trace.get("candidatePoolPreviewCount") != len(preview):
            issues.append({"code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_COUNT_MISMATCH"})
        preview_limit = trace.get("candidatePoolPreviewLimit")
        if isinstance(preview_limit, int) and len(preview) > preview_limit:
            issues.append({"code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_LIMIT_OVERFLOW"})
        candidate_pool_size = trace.get("candidatePoolSize")
        preview_truncated = bool(trace.get("candidatePoolPreviewTruncated"))
        if isinstance(candidate_pool_size, int) and isinstance(preview_limit, int):
            expected_truncated = candidate_pool_size > preview_limit
            if preview_truncated != expected_truncated:
                issues.append({"code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_TRUNCATION_MISMATCH"})
        preview_scores_by_rank: list[tuple[float, dict[str, Any]]] = []
        for expected_rank, item in enumerate(_safe_dict_list(preview), start=1):
            if excludes & _threat_advisory_keys(item):
                issues.append({"code": "THREAT_RETRIEVAL_EXCLUDED_PREVIEW_RETURNED", "externalId": item.get("externalId")})
            if item.get("candidatePoolRank") != expected_rank:
                issues.append(
                    {
                        "code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RANK_SEQUENCE_INVALID",
                        "externalId": item.get("externalId"),
                        "expectedRank": expected_rank,
                        "actualRank": item.get("candidatePoolRank"),
                    }
                )
            expected_returned = expected_rank <= len(candidates)
            if item.get("returned") != expected_returned:
                issues.append(
                    {
                        "code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RETURNED_MISMATCH",
                        "externalId": item.get("externalId"),
                        "candidatePoolRank": expected_rank,
                        "expectedReturned": expected_returned,
                        "actualReturned": item.get("returned"),
                    }
                )
            elif expected_returned and expected_rank <= len(candidates):
                expected_external_id = candidates[expected_rank - 1].get("externalId")
                if item.get("externalId") != expected_external_id:
                    issues.append(
                        {
                            "code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RETURNED_ID_MISMATCH",
                            "candidatePoolRank": expected_rank,
                            "expectedExternalId": expected_external_id,
                            "actualExternalId": item.get("externalId"),
                        }
                    )
            elif not expected_returned and item.get("unreturnedReason") != "outside_final_top_k":
                issues.append(
                    {
                        "code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_UNRETURNED_REASON_MISSING",
                        "externalId": item.get("externalId"),
                    }
                )
            methods = item.get("retrievalMethods") or []
            score = item.get("scoreBreakdown") or {}
            if methods and "methodWeight" in score:
                expected_weight = method_rank_weight(str(methods[0]))
                if score.get("methodWeight") != expected_weight:
                    issues.append(
                        {
                            "code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_METHOD_WEIGHT_MISMATCH",
                            "externalId": item.get("externalId"),
                            "method": methods[0],
                            "expectedMethodWeight": expected_weight,
                            "actualMethodWeight": score.get("methodWeight"),
                        }
                    )
            if score:
                try:
                    expected_score = round(
                        float(score.get("baseScore") or 0.0)
                        + float(score.get("methodWeight") or 0.0)
                        + float(score.get("lexicalBoost") or 0.0)
                        + float(score.get("profileBoost") or 0.0),
                        6,
                    )
                    if round(float(score.get("finalRerankScore")), 6) != expected_score:
                        issues.append({"code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_SCORE_BREAKDOWN_MISMATCH", "externalId": item.get("externalId")})
                    if "rerankScore" in item and round(float(item.get("rerankScore")), 6) != expected_score:
                        issues.append({"code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RERANK_SCORE_MISMATCH", "externalId": item.get("externalId")})
                    preview_scores_by_rank.append((expected_score, item))
                except (TypeError, ValueError):
                    issues.append({"code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_SCORE_BREAKDOWN_INVALID", "externalId": item.get("externalId")})
        for previous, current in zip(preview_scores_by_rank, preview_scores_by_rank[1:]):
            previous_score, previous_item = previous
            current_score, current_item = current
            if current_score > previous_score:
                issues.append(
                    {
                        "code": "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_ORDER_INVALID",
                        "previousExternalId": previous_item.get("externalId"),
                        "previousScore": previous_score,
                        "currentExternalId": current_item.get("externalId"),
                        "currentScore": current_score,
                    }
                )
    for previous, current in zip(rerank_scores_by_rank, rerank_scores_by_rank[1:]):
        previous_score, previous_candidate = previous
        current_score, current_candidate = current
        if current_score > previous_score:
            issues.append(
                {
                    "code": "THREAT_RETRIEVAL_RERANK_ORDER_INVALID",
                    "previousExternalId": previous_candidate.get("externalId"),
                    "previousScore": previous_score,
                    "currentExternalId": current_candidate.get("externalId"),
                    "currentScore": current_score,
                }
            )
    return [redacted_issue(issue) for issue in issues]


def _source_kg_rich_ir_payload_validation_issues(answer: dict[str, Any]) -> list[dict[str, Any]]:
    source_evidence = _source_code_kg_evidence(answer)
    issues: list[dict[str, Any]] = []
    for rich_ir in _safe_dict_list(source_evidence.get("richIrArtifacts")):
        payload_byte_length = rich_ir.get("payloadByteLength")
        payload_max_inline_bytes = rich_ir.get("payloadMaxInlineBytes")
        payload_truncated = rich_ir.get("payloadTruncated")
        payload_redacted = rich_ir.get("payloadRedacted")
        payload_over_limit = (
            isinstance(payload_byte_length, int)
            and isinstance(payload_max_inline_bytes, int)
            and payload_byte_length > payload_max_inline_bytes
        )
        redaction_claimed = payload_truncated is True or payload_redacted is True
        if not payload_over_limit and not redaction_claimed:
            continue

        invalid_reasons: list[str] = []
        if rich_ir.get("payload") is not None:
            invalid_reasons.append("payload_present_for_redacted_rich_ir")
        if payload_truncated is not True:
            invalid_reasons.append("payload_truncated_flag_missing")
        if payload_redacted is not True:
            invalid_reasons.append("payload_redacted_flag_missing")
        if not isinstance(payload_byte_length, int) or not isinstance(payload_max_inline_bytes, int):
            invalid_reasons.append("payload_size_metadata_missing")
        elif payload_byte_length <= payload_max_inline_bytes and redaction_claimed:
            invalid_reasons.append("payload_size_metadata_not_over_limit")
        if invalid_reasons:
            issues.append(
                {
                    "code": "SOURCE_KG_RICH_IR_PAYLOAD_REDACTION_INVALID",
                    "richIrArtifactId": _safe_diagnostic_value(rich_ir.get("richIrArtifactId")),
                    "reasons": invalid_reasons,
                }
            )
    return issues


def _source_kg_snippet_text_validation_issues(answer: dict[str, Any]) -> list[dict[str, Any]]:
    source_evidence = _source_code_kg_evidence(answer)
    issues: list[dict[str, Any]] = []
    for snippet in _safe_dict_list(source_evidence.get("evidenceSnippets")):
        snippet_text = snippet.get("snippetText")
        text_byte_length = len(snippet_text.encode("utf-8")) if isinstance(snippet_text, str) else 0
        declared_byte_length = snippet.get("snippetTextByteLength")
        max_inline_bytes = snippet.get("snippetTextMaxInlineBytes", MAX_SOURCE_SNIPPET_TEXT_INLINE_BYTES)
        truncated = snippet.get("snippetTextTruncated")
        declared_over_limit = (
            isinstance(declared_byte_length, int)
            and isinstance(max_inline_bytes, int)
            and declared_byte_length > max_inline_bytes
        )
        visible_over_limit = isinstance(max_inline_bytes, int) and text_byte_length > max_inline_bytes
        if not declared_over_limit and not visible_over_limit and truncated is not True:
            continue

        invalid_reasons: list[str] = []
        if not isinstance(declared_byte_length, int) or not isinstance(max_inline_bytes, int):
            invalid_reasons.append("snippet_text_size_metadata_missing")
        elif declared_byte_length <= max_inline_bytes and truncated is True:
            invalid_reasons.append("snippet_text_size_metadata_not_over_limit")
        if visible_over_limit:
            invalid_reasons.append("snippet_text_present_over_inline_limit")
        if declared_over_limit and truncated is not True:
            invalid_reasons.append("snippet_text_truncated_flag_missing")
        if invalid_reasons:
            issues.append(
                {
                    "code": "SOURCE_KG_SNIPPET_TEXT_TRUNCATION_INVALID",
                    "evidenceSnippetId": _safe_diagnostic_value(snippet.get("evidenceSnippetId")),
                    "reasons": invalid_reasons,
                }
            )
    return issues


def _source_kg_url_redaction_validation_issues(answer: dict[str, Any]) -> list[dict[str, Any]]:
    source_evidence = _source_code_kg_evidence(answer)
    issues: list[dict[str, Any]] = []

    def contains_unredacted_credential_url(value: Any) -> bool:
        if isinstance(value, str):
            return bool(value) and redact_url_for_log(value) != value
        if isinstance(value, list):
            return any(contains_unredacted_credential_url(item) for item in value)
        if isinstance(value, dict):
            return any(
                contains_unredacted_credential_url(key) or contains_unredacted_credential_url(item)
                for key, item in value.items()
            )
        return False

    def check_record(
        record_kind: str,
        record: dict[str, Any] | None,
        field: str,
        field_path: str,
        id_field: str | None = None,
    ) -> None:
        if not isinstance(record, dict):
            return
        value = record.get(field)
        if not isinstance(value, str) or not value:
            return
        if redact_url_for_log(value) == value:
            return
        issue: dict[str, Any] = {
            "code": "SOURCE_KG_URL_REDACTION_INVALID",
            "recordKind": record_kind,
            "field": field_path,
        }
        if id_field and record.get(id_field):
            issue[id_field] = _safe_diagnostic_value(record.get(id_field))
        issues.append(issue)

    def check_nested_record(
        record_kind: str,
        record: dict[str, Any] | None,
        fields: tuple[str, ...],
        field_path_prefix: str,
        id_field: str | None = None,
    ) -> None:
        if not isinstance(record, dict):
            return
        for field in fields:
            value = record.get(field)
            if value is None or not contains_unredacted_credential_url(value):
                continue
            issue: dict[str, Any] = {
                "code": "SOURCE_KG_URL_REDACTION_INVALID",
                "recordKind": record_kind,
                "field": f"{field_path_prefix}.{field}",
            }
            if id_field and record.get(id_field):
                issue[id_field] = _safe_diagnostic_value(record.get(id_field))
            issues.append(issue)

    check_record(
        "repositorySnapshot",
        source_evidence.get("repositorySnapshot"),
        "repositoryUrl",
        "repositorySnapshot.repositoryUrl",
        "repositorySnapshotId",
    )
    check_nested_record(
        "repositorySnapshot",
        source_evidence.get("repositorySnapshot"),
        ("submoduleHashes", "metadata", "provenance"),
        "repositorySnapshot",
        "repositorySnapshotId",
    )
    for artifact in _safe_dict_list(source_evidence.get("sourceArtifacts")):
        check_record(
            "sourceArtifact",
            artifact,
            "artifactUri",
            "sourceArtifacts[].artifactUri",
            "sourceRepositoryArtifactId",
        )
        check_nested_record(
            "sourceArtifact",
            artifact,
            ("metadata", "provenance"),
            "sourceArtifacts[]",
            "sourceRepositoryArtifactId",
        )
    check_nested_record(
        "buildContext",
        source_evidence.get("buildContext"),
        ("toolchain", "dependencyGraph", "buildMetadata", "provenance"),
        "buildContext",
        "buildContextId",
    )
    check_nested_record(
        "analysisArtifactSet",
        source_evidence.get("analysisArtifactSet"),
        ("analysisConfig", "artifactHashes", "provenance"),
        "analysisArtifactSet",
        "analysisArtifactSetId",
    )
    for node in _safe_dict_list(source_evidence.get("graphNodes")):
        check_nested_record(
            "graphNode",
            node,
            ("symbol", "metadata"),
            "graphNodes[]",
            "sourceGraphNodeId",
        )
    for edge in _safe_dict_list(source_evidence.get("graphEdges")):
        check_nested_record(
            "graphEdge",
            edge,
            ("evidence", "metadata"),
            "graphEdges[]",
            "sourceGraphEdgeId",
        )
    for snippet in _safe_dict_list(source_evidence.get("evidenceSnippets")):
        check_nested_record(
            "evidenceSnippet",
            snippet,
            ("provenance",),
            "evidenceSnippets[]",
            "evidenceSnippetId",
        )
    for rich_ir in _safe_dict_list(source_evidence.get("richIrArtifacts")):
        check_record(
            "richIrArtifact",
            rich_ir,
            "uri",
            "richIrArtifacts[].uri",
            "richIrArtifactId",
        )
        check_nested_record(
            "richIrArtifact",
            rich_ir,
            ("provenance",),
            "richIrArtifacts[]",
            "richIrArtifactId",
        )
    return issues


def _source_kg_compile_commands_artifact_validation_issues(answer: dict[str, Any]) -> list[dict[str, Any]]:
    source_evidence = _source_code_kg_evidence(answer)
    build_context = source_evidence.get("buildContext") or {}
    if not isinstance(build_context, dict):
        return []
    compile_commands_artifact_id = build_context.get("compileCommandsArtifactId")
    if compile_commands_artifact_id in (None, ""):
        return []
    if not isinstance(compile_commands_artifact_id, str):
        issue: dict[str, Any] = {
            "code": "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID",
            "field": "buildContext.compileCommandsArtifactId",
            "valueType": type(compile_commands_artifact_id).__name__,
            "reasons": ["compile_commands_artifact_id_invalid"],
        }
        if build_context.get("buildContextId"):
            issue["buildContextId"] = _safe_diagnostic_value(build_context.get("buildContextId"))
        return [issue]

    source_artifacts = _safe_dict_list(source_evidence.get("sourceArtifacts"))
    artifact_ids = {
        artifact.get("sourceRepositoryArtifactId")
        for artifact in source_artifacts
        if isinstance(artifact, dict) and artifact.get("sourceRepositoryArtifactId")
    }
    context_resolution = source_evidence.get("contextResolution") or {}
    source_artifact_resolution = (
        context_resolution.get("sourceArtifacts")
        if isinstance(context_resolution, dict)
        else None
    )

    invalid_reasons: list[str] = []
    if compile_commands_artifact_id not in artifact_ids:
        invalid_reasons.append("compile_commands_artifact_not_in_source_artifacts")
    if not isinstance(source_artifact_resolution, dict):
        invalid_reasons.append("source_artifact_resolution_missing")
    else:
        requested_ids = set(_safe_string_list(source_artifact_resolution.get("requestedIds")))
        resolved_ids = set(_safe_string_list(source_artifact_resolution.get("resolvedIds")))
        missing_ids = set(_safe_string_list(source_artifact_resolution.get("missingIds")))
        if compile_commands_artifact_id not in requested_ids:
            invalid_reasons.append("compile_commands_artifact_not_requested")
        if compile_commands_artifact_id not in resolved_ids:
            invalid_reasons.append("compile_commands_artifact_not_resolved")
        if compile_commands_artifact_id in missing_ids:
            invalid_reasons.append("compile_commands_artifact_marked_missing")

    if not invalid_reasons:
        return []
    issue: dict[str, Any] = {
        "code": "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID",
        "compileCommandsArtifactId": _safe_diagnostic_value(compile_commands_artifact_id),
        "reasons": invalid_reasons,
    }
    if build_context.get("buildContextId"):
        issue["buildContextId"] = _safe_diagnostic_value(build_context.get("buildContextId"))
    return [issue]


def _source_kg_context_resolution_integrity_issues(answer: dict[str, Any]) -> list[dict[str, Any]]:
    source_evidence = _source_code_kg_evidence(answer)
    context_resolution = source_evidence.get("contextResolution")
    if not isinstance(context_resolution, dict):
        context_resolution = {}

    issues: list[dict[str, Any]] = []

    def safe_ids(ids: list[str]) -> list[str]:
        return [_safe_diagnostic_value(item) for item in ids]

    def issue(field: str, reasons: list[str], *, served_ids: list[str], resolved_ids: list[str]) -> None:
        payload: dict[str, Any] = {
            "code": "SOURCE_KG_CONTEXT_RESOLUTION_INVALID",
            "field": field,
            "reasons": reasons,
        }
        if served_ids:
            payload["servedIds"] = safe_ids(served_ids)
        if resolved_ids:
            payload["resolvedIds"] = safe_ids(resolved_ids)
        issues.append(payload)

    def scalar(record_key: str, id_field: str) -> None:
        record = source_evidence.get(record_key)
        entry = context_resolution.get(record_key)
        served_id = record.get(id_field) if isinstance(record, dict) and isinstance(record.get(id_field), str) else None
        if not isinstance(entry, dict):
            if served_id:
                issue(f"{record_key}.resolvedId", ["resolution_entry_missing"], served_ids=[served_id], resolved_ids=[])
            return
        raw_requested_id = entry.get("requestedId")
        raw_resolved_id = entry.get("resolvedId")
        raw_missing_ids = entry.get("missingIds")
        if raw_requested_id is not None and not isinstance(raw_requested_id, str):
            issue(
                f"{record_key}.requestedId",
                ["requested_id_invalid"],
                served_ids=[served_id] if served_id else [],
                resolved_ids=[],
            )
        if not isinstance(raw_missing_ids, list) or any(not isinstance(item, str) for item in raw_missing_ids):
            issue(
                f"{record_key}.missingIds",
                ["missing_ids_invalid"],
                served_ids=[served_id] if served_id else [],
                resolved_ids=[],
            )
        elif served_id and served_id in raw_missing_ids:
            issue(
                f"{record_key}.missingIds",
                ["served_id_marked_missing"],
                served_ids=[served_id],
                resolved_ids=[],
            )
        resolved_id = raw_resolved_id if isinstance(raw_resolved_id, str) else None
        reasons: list[str] = []
        if raw_resolved_id is not None and not isinstance(raw_resolved_id, str):
            reasons.append("resolved_id_invalid")
        if served_id != resolved_id:
            reasons.append("resolved_id_does_not_match_served_id")
        if reasons:
            issue(
                f"{record_key}.resolvedId",
                reasons,
                served_ids=[served_id] if served_id else [],
                resolved_ids=[resolved_id] if resolved_id else [],
            )

    def collection(record_key: str, id_field: str) -> None:
        records = _safe_dict_list(source_evidence.get(record_key))
        served_ids = [
            record.get(id_field)
            for record in records
            if isinstance(record, dict) and isinstance(record.get(id_field), str)
        ]
        entry = context_resolution.get(record_key)
        if not isinstance(entry, dict):
            if served_ids:
                issue(f"{record_key}.resolvedIds", ["resolution_entry_missing"], served_ids=served_ids, resolved_ids=[])
            return
        raw_requested_ids = entry.get("requestedIds")
        raw_resolved_ids = entry.get("resolvedIds")
        raw_missing_ids = entry.get("missingIds")
        if not isinstance(raw_requested_ids, list) or any(not isinstance(item, str) for item in raw_requested_ids):
            issue(f"{record_key}.requestedIds", ["requested_ids_invalid"], served_ids=served_ids, resolved_ids=[])
        resolved_ids = [item for item in raw_resolved_ids if isinstance(item, str)] if isinstance(raw_resolved_ids, list) else []
        missing_ids = [item for item in raw_missing_ids if isinstance(item, str)] if isinstance(raw_missing_ids, list) else []
        reasons: list[str] = []
        if not isinstance(raw_resolved_ids, list) or len(resolved_ids) != len(raw_resolved_ids):
            reasons.append("resolved_ids_invalid")
        if not isinstance(raw_missing_ids, list) or len(missing_ids) != len(raw_missing_ids):
            issue(f"{record_key}.missingIds", ["missing_ids_invalid"], served_ids=served_ids, resolved_ids=resolved_ids)
        elif any(item in served_ids for item in missing_ids):
            issue(f"{record_key}.missingIds", ["served_id_marked_missing"], served_ids=served_ids, resolved_ids=resolved_ids)
        if served_ids != resolved_ids:
            reasons.append("resolved_ids_do_not_match_served_ids")
        if reasons:
            issue(
                f"{record_key}.resolvedIds",
                reasons,
                served_ids=served_ids,
                resolved_ids=resolved_ids,
            )

    scalar("repositorySnapshot", "repositorySnapshotId")
    scalar("buildContext", "buildContextId")
    scalar("analysisArtifactSet", "analysisArtifactSetId")
    collection("sourceArtifacts", "sourceRepositoryArtifactId")
    collection("graphNodes", "sourceGraphNodeId")
    collection("evidenceSnippets", "evidenceSnippetId")
    collection("richIrArtifacts", "richIrArtifactId")
    return issues


def _source_kg_nested_object_validation_issues(answer: dict[str, Any]) -> list[dict[str, Any]]:
    source_evidence = _source_code_kg_evidence(answer)
    issues: list[dict[str, Any]] = []

    def visible_byte_length(value: Any) -> int:
        return len(json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8"))

    def check_record(record_kind: str, record: dict[str, Any] | None, fields: tuple[str, ...], id_field: str | None = None) -> None:
        if not isinstance(record, dict):
            return
        for field in fields:
            value = record.get(field)
            declared_byte_length = record.get(f"{field}ByteLength")
            max_inline_bytes = record.get(f"{field}MaxInlineBytes", MAX_SOURCE_NESTED_OBJECT_INLINE_BYTES)
            truncated = record.get(f"{field}Truncated")
            redacted = record.get(f"{field}Redacted")
            declared_over_limit = (
                isinstance(declared_byte_length, int)
                and isinstance(max_inline_bytes, int)
                and declared_byte_length > max_inline_bytes
            )
            redaction_claimed = truncated is True or redacted is True
            visible_over_limit = value is not None and isinstance(max_inline_bytes, int) and visible_byte_length(value) > max_inline_bytes
            if not declared_over_limit and not visible_over_limit and not redaction_claimed:
                continue

            invalid_reasons: list[str] = []
            if value is not None and (declared_over_limit or redaction_claimed):
                invalid_reasons.append("nested_object_present_for_redacted_field")
            if visible_over_limit:
                invalid_reasons.append("nested_object_present_over_inline_limit")
            if not isinstance(declared_byte_length, int) or not isinstance(max_inline_bytes, int):
                invalid_reasons.append("nested_object_size_metadata_missing")
            elif declared_byte_length <= max_inline_bytes and redaction_claimed:
                invalid_reasons.append("nested_object_size_metadata_not_over_limit")
            if declared_over_limit and truncated is not True:
                invalid_reasons.append("nested_object_truncated_flag_missing")
            if declared_over_limit and redacted is not True:
                invalid_reasons.append("nested_object_redacted_flag_missing")
            if invalid_reasons:
                issue: dict[str, Any] = {
                    "code": "SOURCE_KG_NESTED_OBJECT_REDACTION_INVALID",
                    "recordKind": record_kind,
                    "field": field,
                    "reasons": invalid_reasons,
                }
                if id_field and record.get(id_field):
                    issue[id_field] = _safe_diagnostic_value(record.get(id_field))
                issues.append(issue)

    check_record("repositorySnapshot", source_evidence.get("repositorySnapshot"), ("submoduleHashes", "metadata", "provenance"), "repositorySnapshotId")
    for artifact in _safe_dict_list(source_evidence.get("sourceArtifacts")):
        check_record("sourceArtifact", artifact, ("metadata", "provenance"), "sourceRepositoryArtifactId")
    check_record("buildContext", source_evidence.get("buildContext"), ("toolchain", "dependencyGraph", "buildMetadata", "provenance"), "buildContextId")
    check_record(
        "analysisArtifactSet",
        source_evidence.get("analysisArtifactSet"),
        ("analysisConfig", "artifactHashes", "provenance"),
        "analysisArtifactSetId",
    )
    for node in _safe_dict_list(source_evidence.get("graphNodes")):
        check_record("graphNode", node, ("symbol", "metadata"), "sourceGraphNodeId")
    for edge in _safe_dict_list(source_evidence.get("graphEdges")):
        check_record("graphEdge", edge, ("evidence", "metadata"), "sourceGraphEdgeId")
    for snippet in _safe_dict_list(source_evidence.get("evidenceSnippets")):
        check_record("evidenceSnippet", snippet, ("provenance",), "evidenceSnippetId")
    for rich_ir in _safe_dict_list(source_evidence.get("richIrArtifacts")):
        check_record("richIrArtifact", rich_ir, ("provenance",), "richIrArtifactId")
    return issues


def _uncertainty_followup_validation_issues(answer: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    uncertainty = answer.get("uncertainty")
    if not isinstance(uncertainty, dict):
        return [{"code": "UNCERTAINTY_FIELD_MISSING", "field": "uncertainty"}]

    for field in JUDGE_UNCERTAINTY_REQUIRED_FIELDS:
        if field not in uncertainty:
            issues.append({"code": "UNCERTAINTY_FIELD_MISSING", "field": f"uncertainty.{field}"})

    reason = uncertainty.get("reason")
    reason_required = answer.get("verdict") == "unknown" or answer.get("status") in {
        "degraded_quality",
        "requires_requery",
        "insufficient_input",
    }
    if reason_required and (not isinstance(reason, str) or not reason.strip()):
        issues.append({"code": "UNCERTAINTY_REASON_MISSING", "field": "uncertainty.reason"})
    elif reason is not None and not isinstance(reason, str):
        issues.append({"code": "UNCERTAINTY_FIELD_INVALID", "field": "uncertainty.reason"})

    evidence_gaps = uncertainty.get("evidenceGaps")
    if not isinstance(evidence_gaps, list) or any(not isinstance(item, str) or not item.strip() for item in evidence_gaps):
        issues.append({"code": "UNCERTAINTY_FIELD_INVALID", "field": "uncertainty.evidenceGaps"})

    conflicts = uncertainty.get("conflicts")
    if not isinstance(conflicts, list) or any(not isinstance(item, dict) for item in conflicts):
        issues.append({"code": "UNCERTAINTY_FIELD_INVALID", "field": "uncertainty.conflicts"})

    required_inputs = uncertainty.get("requiredInputs")
    allowed_required_inputs = set(JUDGE_UNCERTAINTY_REQUIRED_INPUT_VOCABULARY)
    if not isinstance(required_inputs, list):
        issues.append({"code": "UNCERTAINTY_FIELD_MISSING", "field": "uncertainty.requiredInputs"})
    else:
        for index, item in enumerate(required_inputs):
            if not isinstance(item, str) or item not in allowed_required_inputs:
                issues.append(
                    {
                        "code": "UNCERTAINTY_REQUIRED_INPUT_UNKNOWN",
                        "field": "uncertainty.requiredInputs[]",
                        "index": index,
                        "requiredInput": item,
                    }
                )

    followups = answer.get("followUpAffordances")
    if not isinstance(followups, list):
        return [*issues, {"code": "FOLLOW_UP_AFFORDANCE_INVALID", "field": "followUpAffordances"}]

    allowed_request_kinds = set(JUDGE_FOLLOW_UP_REQUEST_KINDS)
    allowed_owner_lanes = set(JUDGE_FOLLOW_UP_OWNER_LANES)
    for index, item in enumerate(followups):
        if not isinstance(item, dict):
            issues.append({"code": "FOLLOW_UP_AFFORDANCE_INVALID", "field": "followUpAffordances[]", "index": index})
            continue
        request_kind = item.get("requestKind")
        if not isinstance(request_kind, str) or request_kind not in allowed_request_kinds:
            issues.append(
                {
                    "code": "FOLLOW_UP_REQUEST_KIND_UNKNOWN",
                    "field": "followUpAffordances[].requestKind",
                    "index": index,
                    "requestKind": request_kind,
                }
            )
        owner_lane = item.get("ownerLane")
        if not isinstance(owner_lane, str) or owner_lane not in allowed_owner_lanes:
            issues.append(
                {
                    "code": "FOLLOW_UP_OWNER_LANE_UNKNOWN",
                    "field": "followUpAffordances[].ownerLane",
                    "index": index,
                    "ownerLane": owner_lane,
                }
            )
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            issues.append({"code": "FOLLOW_UP_REASON_MISSING", "field": "followUpAffordances[].reason", "index": index})

    return issues


def _safe_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _safe_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _accepted_exclude_controls(answer: dict[str, Any]) -> list[str]:
    return _safe_string_list(_safe_dict(_safe_dict(answer.get("appliedControls")).get("accepted")).get("exclude"))


def validate_judge_answer(answer: dict[str, Any]) -> list[dict[str, Any]]:
    """Contract validator used by tests and future quality gates."""

    issues: list[dict[str, Any]] = []
    if answer.get("schemaVersion") != SCHEMA_VERSION:
        issues.append({"code": "INVALID_SCHEMA_VERSION"})
    if answer.get("verdictAuthority") != VERDICT_AUTHORITY:
        issues.append({"code": "INVALID_VERDICT_AUTHORITY"})
    issues.extend(_reasoning_path_validation_issues(answer))
    issues.extend(_fallback_trace_validation_issues(answer))
    issues.extend(_control_effect_validation_issues(answer))
    for field in ("canonicalQuery", "decisionFragmentKey", "cacheTrace", "fallbackTrace", "servingLedger"):
        if field not in answer:
            issues.append({"code": "MISSING_SERVING_FIELD", "field": field})
    cache_trace_present = "cacheTrace" in answer
    cache_trace_raw = answer.get("cacheTrace")
    if cache_trace_present and not isinstance(cache_trace_raw, dict):
        issues.append({"code": "JUDGE_ANSWER_FIELD_INVALID", "field": "cacheTrace"})
    cache_trace = _safe_dict(cache_trace_raw)
    if cache_trace_present and isinstance(cache_trace_raw, dict):
        if cache_trace.get("cacheScope") != "ledger" or not cache_trace.get("cacheScopeHash"):
            issues.append({"code": "DECISION_CACHE_TRACE_SCOPE_MISSING"})
        if not cache_trace.get("cacheRevisionHash"):
            issues.append({"code": "DECISION_CACHE_TRACE_REVISION_MISSING"})
    forbidden = set(_safe_string_list(answer.get("forbiddenInferences")))
    required_forbidden = set(BASELINE_FORBIDDEN_INFERENCES)
    missing_forbidden = sorted(required_forbidden - forbidden)
    if missing_forbidden:
        issues.append({"code": "MISSING_FORBIDDEN_INFERENCES", "missing": missing_forbidden})
    verdict = answer.get("verdict")
    if verdict == "unknown":
        uncertainty = answer.get("uncertainty") if isinstance(answer.get("uncertainty"), dict) else {}
        if not uncertainty.get("reason") or not uncertainty.get("evidenceGaps") or not answer.get("followUpAffordances"):
            issues.append({"code": "LAZY_UNKNOWN"})
    issues.extend(_uncertainty_followup_validation_issues(answer))
    issues.extend(_threat_retrieval_validation_issues(answer))
    issues.extend(_source_kg_rich_ir_payload_validation_issues(answer))
    issues.extend(_source_kg_snippet_text_validation_issues(answer))
    issues.extend(_source_kg_url_redaction_validation_issues(answer))
    issues.extend(_source_kg_compile_commands_artifact_validation_issues(answer))
    issues.extend(_source_kg_context_resolution_integrity_issues(answer))
    issues.extend(_source_kg_nested_object_validation_issues(answer))
    if "queryContext" in answer and not isinstance(answer.get("queryContext"), dict):
        issues.append({"code": "JUDGE_ANSWER_FIELD_INVALID", "field": "queryContext"})
    if "evidence" in answer and not isinstance(answer.get("evidence"), dict):
        issues.append({"code": "JUDGE_ANSWER_FIELD_INVALID", "field": "evidence"})
    if "appliedControls" in answer and not isinstance(answer.get("appliedControls"), dict):
        issues.append({"code": "JUDGE_ANSWER_FIELD_INVALID", "field": "appliedControls"})
    evidence_packet = _answer_evidence(answer)
    if "sourceCodeKg" in evidence_packet and not isinstance(evidence_packet.get("sourceCodeKg"), dict):
        issues.append({"code": "JUDGE_ANSWER_FIELD_INVALID", "field": "evidence.sourceCodeKg"})
    requested_source_context = _safe_dict(_safe_dict(answer.get("queryContext")).get("sourceContext"))
    if requested_source_context:
        source_evidence = _source_code_kg_evidence(answer)
        raw_fallback_trace = answer.get("fallbackTrace")
        fallback_trace = [item for item in raw_fallback_trace if isinstance(item, dict)] if isinstance(raw_fallback_trace, list) else []
        unresolved_context_explained = any(
            item.get("stage") == "source_code_kg_context"
            and item.get("fallback") == "unresolved_context"
            and item.get("silent") is False
            for item in fallback_trace
        )
        if not source_evidence.get("resolved") and not unresolved_context_explained:
            issues.append({"code": "SOURCE_KG_CONTEXT_IGNORED"})
        partial_context_explained = any(
            item.get("stage") == "source_code_kg_context"
            and item.get("fallback") == "partial_context_resolution"
            and item.get("silent") is False
            for item in fallback_trace
        )
        source_context_resolution = _safe_dict(source_evidence.get("contextResolution"))
        if source_context_resolution.get("partial") and not partial_context_explained:
            issues.append({"code": "SOURCE_KG_PARTIAL_CONTEXT_SILENT"})
        source_context_diagnostics = source_context_resolution.get("diagnostics") or []
        source_context_degraded = not source_evidence.get("resolved") or bool(source_context_diagnostics)
        if source_context_degraded and answer.get("status") == "complete":
            issues.append({"code": "SOURCE_KG_CONTEXT_DEGRADED_STATUS_MISSING"})
        if source_context_degraded and answer.get("status") in {"degraded_quality", "requires_requery", "insufficient_input"}:
            uncertainty = answer.get("uncertainty") if isinstance(answer.get("uncertainty"), dict) else {}
            followups = _safe_dict_list(answer.get("followUpAffordances"))
            required_inputs = set(_safe_string_list(uncertainty.get("requiredInputs")))
            evidence_gaps = set(_safe_string_list(uncertainty.get("evidenceGaps")))
            if "complete_or_consistent_source_code_kg_context" not in required_inputs:
                issues.append({"code": "SOURCE_KG_CONTEXT_REQUIRED_INPUT_MISSING"})
            if not any(item.get("requestKind") == "source_context_enrichment" for item in followups):
                issues.append({"code": "SOURCE_KG_CONTEXT_FOLLOWUP_MISSING"})
            if "source code kg context" not in evidence_gaps:
                issues.append({"code": "UNCERTAINTY_FIELD_INVALID", "field": "uncertainty.evidenceGaps"})
    uncertainty = answer.get("uncertainty") if isinstance(answer.get("uncertainty"), dict) else {}
    conflicts = _safe_dict_list(uncertainty.get("conflicts"))
    if conflicts:
        quality_gate_packet = answer.get("qualityGate") if isinstance(answer.get("qualityGate"), dict) else {}
        diagnostics = _safe_dict_list(quality_gate_packet.get("diagnostics"))
        diagnostic_conflict_ids = {item.get("conflictRecordId") for item in diagnostics if item.get("conflictRecordId")}
        quality_gate = quality_gate_packet.get("gate")
        for conflict in conflicts:
            conflict_id = conflict.get("conflictRecordId")
            if conflict.get("consumerPolicy") != CONFLICT_CONSUMER_POLICY or conflict.get("negativeEvidenceAllowed") is not False:
                issues.append({"code": "CONFLICT_USED_AS_NEGATIVE_EVIDENCE", "conflictRecordId": conflict_id})
            if "negative_evidence" not in set(_safe_string_list(conflict.get("forbiddenEffects"))):
                issues.append({"code": "CONFLICT_FORBIDDEN_EFFECTS_INCOMPLETE", "conflictRecordId": conflict_id})
            conflicting_values = _safe_dict_list(conflict.get("conflictingValues"))
            conflicting_value_count = conflict.get("conflictingValueCount")
            truncated = bool(conflict.get("conflictingValuesTruncated"))
            if not conflicting_values:
                issues.append({"code": "CONFLICT_VALUES_MISSING", "conflictRecordId": conflict_id})
            if len(conflicting_values) > MAX_CONFLICTING_VALUES_IN_SUMMARY:
                issues.append({"code": "CONFLICT_VALUES_OVER_LIMIT", "conflictRecordId": conflict_id})
            if not isinstance(conflicting_value_count, int) or conflicting_value_count < len(conflicting_values):
                issues.append({"code": "CONFLICT_VALUES_COUNT_INVALID", "conflictRecordId": conflict_id})
            elif conflicting_value_count > len(conflicting_values) and not truncated:
                issues.append({"code": "CONFLICT_VALUES_TRUNCATION_INVALID", "conflictRecordId": conflict_id})
            elif conflicting_value_count == len(conflicting_values) and truncated:
                issues.append({"code": "CONFLICT_VALUES_TRUNCATION_INVALID", "conflictRecordId": conflict_id})
            if conflict_id not in diagnostic_conflict_ids:
                issues.append({"code": "CONFLICT_DIAGNOSTIC_SILENT", "conflictRecordId": conflict_id})
            if conflict.get("severity") == "hard" and quality_gate != "rejected":
                issues.append({"code": "HARD_CONFLICT_NOT_REJECTED", "conflictRecordId": conflict_id})
    return issues


def _reasoning_path_validation_issues(answer: dict[str, Any]) -> list[dict[str, Any]]:
    reasoning_path = answer.get("reasoningPath")
    if not isinstance(reasoning_path, list) or not reasoning_path:
        return [{"code": "REASONING_PATH_MISSING"}]

    allowed_steps = set(JUDGE_REASONING_PATH_STEPS)
    issues: list[dict[str, Any]] = []
    for index, entry in enumerate(reasoning_path):
        if not isinstance(entry, dict):
            issues.append({"code": "REASONING_PATH_ENTRY_INVALID", "index": index})
            continue

        step = entry.get("step")
        status = entry.get("status")
        if not isinstance(step, str) or not step:
            issues.append({"code": "REASONING_PATH_FIELD_MISSING", "index": index, "field": "step"})
            continue
        if step not in allowed_steps:
            issues.append({"code": "REASONING_PATH_STEP_UNKNOWN", "index": index, "step": step})
        if not isinstance(status, str) or not status:
            issues.append({"code": "REASONING_PATH_FIELD_MISSING", "index": index, "field": "status"})

    return issues


def _fallback_trace_validation_issues(answer: dict[str, Any]) -> list[dict[str, Any]]:
    if "fallbackTrace" not in answer:
        return []

    fallback_trace = answer.get("fallbackTrace")
    if fallback_trace is None:
        return [{"code": "FALLBACK_TRACE_INVALID"}]
    if not isinstance(fallback_trace, list):
        return [{"code": "FALLBACK_TRACE_INVALID"}]

    issues: list[dict[str, Any]] = []
    for index, entry in enumerate(fallback_trace):
        if not isinstance(entry, dict):
            issues.append({"code": "FALLBACK_TRACE_ENTRY_INVALID", "index": index})
            continue

        stage = entry.get("stage")
        fallback = entry.get("fallback")
        silent = entry.get("silent")
        missing_fields = [
            field
            for field, value in (("stage", stage), ("fallback", fallback), ("silent", silent))
            if value is None
        ]
        for field in missing_fields:
            issues.append({"code": "FALLBACK_TRACE_FIELD_MISSING", "index": index, "field": field})
        if missing_fields:
            continue

        if not isinstance(stage, str) or not stage:
            issues.append({"code": "FALLBACK_TRACE_FIELD_MISSING", "index": index, "field": "stage"})
            continue
        if not isinstance(fallback, str) or not fallback:
            issues.append({"code": "FALLBACK_TRACE_FIELD_MISSING", "index": index, "field": "fallback"})
            continue
        if silent is not False:
            issues.append({"code": "FALLBACK_TRACE_SILENT", "index": index, "stage": stage, "fallback": fallback})

        allowed_fallbacks = JUDGE_FALLBACK_TRACE_STAGE_CATALOG.get(stage)
        if allowed_fallbacks is None:
            issues.append({"code": "FALLBACK_TRACE_STAGE_UNKNOWN", "index": index, "stage": stage})
        elif fallback not in set(allowed_fallbacks):
            issues.append({"code": "FALLBACK_TRACE_FALLBACK_UNKNOWN", "index": index, "stage": stage, "fallback": fallback})
        elif fallback == "partial_context_resolution" and (
            not isinstance(entry.get("diagnostics"), list) or not entry.get("diagnostics")
        ):
            issues.append({"code": "FALLBACK_TRACE_DIAGNOSTICS_MISSING", "index": index, "stage": stage, "fallback": fallback})
        elif fallback == "unsupported_controls_rejected" and (
            not isinstance(entry.get("rejected"), list) or not entry.get("rejected")
        ):
            issues.append({"code": "FALLBACK_TRACE_REJECTED_CONTROLS_MISSING", "index": index, "stage": stage, "fallback": fallback})

    return issues


def _control_effect_validation_issues(answer: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = _answer_evidence(answer)
    suppressed_affectedness = _safe_dict_list(evidence.get("suppressedAffectedness"))
    if "controlEffects" not in answer:
        return [{"code": "CONTROL_EFFECT_SUPPRESSION_TRACE_MISSING"}] if suppressed_affectedness else []

    control_effects = answer.get("controlEffects")
    if control_effects is None:
        return [{"code": "CONTROL_EFFECTS_INVALID"}]
    if not isinstance(control_effects, list):
        return [{"code": "CONTROL_EFFECTS_INVALID"}]

    issues: list[dict[str, Any]] = []
    valid_effects: list[dict[str, Any]] = []
    for index, entry in enumerate(control_effects):
        if not isinstance(entry, dict):
            issues.append({"code": "CONTROL_EFFECT_ENTRY_INVALID", "index": index})
            continue

        control = entry.get("control")
        if not isinstance(control, str) or not control:
            issues.append({"code": "CONTROL_EFFECT_FIELD_MISSING", "index": index, "field": "control"})
            continue
        if control not in set(JUDGE_CONTROL_EFFECT_CONTROLS):
            issues.append({"code": "CONTROL_EFFECT_CONTROL_UNKNOWN", "index": index, "control": control})
            continue

        missing_fields = [field for field in JUDGE_CONTROL_EFFECT_REQUIRED_FIELDS if field not in entry]
        for field in missing_fields:
            issues.append({"code": "CONTROL_EFFECT_FIELD_MISSING", "index": index, "field": field})
        if missing_fields:
            continue

        for field in ("suppressedAdvisoryIds", "suppressedExternalIds"):
            if not isinstance(entry.get(field), list):
                issues.append({"code": "CONTROL_EFFECT_FIELD_MISSING", "index": index, "field": field})
        valid_effects.append(entry)

    if suppressed_affectedness:
        exclude_effects = [entry for entry in valid_effects if entry.get("control") == "exclude"]
        if not exclude_effects:
            issues.append({"code": "CONTROL_EFFECT_SUPPRESSION_TRACE_MISSING"})
        else:
            expected_advisory_ids = {
                item.get("advisoryId")
                for item in suppressed_affectedness
                if isinstance(item, dict) and isinstance(item.get("advisoryId"), str) and item.get("advisoryId")
            }
            expected_external_ids = {
                item.get("advisoryExternalId")
                for item in suppressed_affectedness
                if isinstance(item, dict) and isinstance(item.get("advisoryExternalId"), str) and item.get("advisoryExternalId")
            }
            traced_advisory_ids = {
                advisory_id
                for entry in exclude_effects
                for advisory_id in _safe_string_list(entry.get("suppressedAdvisoryIds"))
                if advisory_id
            }
            traced_external_ids = {
                external_id
                for entry in exclude_effects
                for external_id in _safe_string_list(entry.get("suppressedExternalIds"))
                if external_id
            }
            if expected_advisory_ids != traced_advisory_ids or expected_external_ids != traced_external_ids:
                issues.append(
                    {
                        "code": "CONTROL_EFFECT_SUPPRESSED_AFFECTEDNESS_MISMATCH",
                        "missingAdvisoryIds": sorted(expected_advisory_ids - traced_advisory_ids),
                        "extraAdvisoryIds": sorted(traced_advisory_ids - expected_advisory_ids),
                        "missingExternalIds": sorted(expected_external_ids - traced_external_ids),
                        "extraExternalIds": sorted(traced_external_ids - expected_external_ids),
                    }
                )
            accepted_excludes = {
                normalize_control_identifier(value)
                for value in _accepted_exclude_controls(answer)
                if normalize_control_identifier(value)
            }
            unmatched_suppressed = []
            for item in suppressed_affectedness:
                if not isinstance(item, dict):
                    continue
                keys = {
                    key
                    for key in (
                        normalize_control_identifier(item.get("advisoryId")),
                        normalize_control_identifier(item.get("advisoryExternalId")),
                    )
                    if key
                }
                for signal in _safe_dict_list(item.get("riskSignals")):
                    payload = signal.get("payload") or {}
                    if not isinstance(payload, dict):
                        continue
                    for key in (
                        normalize_control_identifier(payload.get("cve")),
                        normalize_control_identifier(payload.get("cveID")),
                    ):
                        if key:
                            keys.add(key)
                if keys and not (keys & accepted_excludes):
                    unmatched_suppressed.append(
                        {
                            "advisoryId": item.get("advisoryId"),
                            "advisoryExternalId": item.get("advisoryExternalId"),
                        }
                    )
            if unmatched_suppressed:
                issues.append(
                    {
                        "code": "CONTROL_EFFECT_ACCEPTED_CONTROL_MISMATCH",
                        "unmatchedSuppressedAffectedness": unmatched_suppressed[:8],
                    }
                )
        if not evidence.get("affectedness") and (
            answer.get("verdict") != "unknown" or answer.get("status") != "requires_requery"
        ):
            issues.append({"code": "CONTROL_EFFECT_SUPPRESSION_VERDICT_INVALID"})

    return issues
