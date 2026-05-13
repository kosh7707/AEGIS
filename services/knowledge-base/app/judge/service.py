"""Evidence-Grounded Judge service.

The Judge composes deterministic S5 knowledge evidence.  Its `verdict` is not a
S3 final security decision; it is an S5 evidence-grounded knowledge verdict over
one query and target context.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from app.affectedness import query_affectedness
from app.analyst.brief import BASELINE_FORBIDDEN_INFERENCES
from app.config import settings
from app.identity import resolve_component_identity
from app.ledger.repository import SQLiteLedgerRepository
from app.quality.scoring_policy import default_score_vector, evaluate_score_vector
from app.serving.decision_cache import get_decision_fragment, store_decision_fragment
from app.serving.query_planner import build_canonical_query, normalize_control_identifier
from app.threat_retrieval import build_threat_retrieval_evidence

from .models import JudgeQueryRequest

SCHEMA_VERSION = "s5-judge-answer-v1"
VERDICT_AUTHORITY = "s5_evidence_grounded_knowledge_verdict_not_s3_final_security_verdict"


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


def _record_serving_answer(repo: SQLiteLedgerRepository, request: JudgeQueryRequest, answer: dict[str, Any]) -> dict[str, Any]:
    created_at = _now()
    serving_run_id = _serving_run_id(answer, created_at)
    answer["servingLedger"] = {
        "schemaVersion": "s5-serving-ledger-ref-v1",
        "recorded": True,
        "servingRunId": serving_run_id,
        "createdAt": created_at,
    }
    repo.record_serving_query(
        serving_run_id=serving_run_id,
        created_at=created_at,
        request_packet=request.model_dump(by_alias=True),
        answer_packet=answer,
    )
    return answer


def _empty_score_vector(*, source_resolved: bool, affectedness_status: str, excluded: bool = False) -> dict[str, float]:
    return default_score_vector(source_resolved=source_resolved, affectedness_status=affectedness_status, excluded=excluded)


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
    return request.source_context.model_dump(by_alias=True)


def _resolve_source_context(
    repo: SQLiteLedgerRepository,
    request: JudgeQueryRequest,
    normalized_source_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if request.source_context is None:
        return {"resolved": False}
    ctx = normalized_source_context or request.source_context.model_dump(by_alias=True)
    return repo.get_source_kg_context(
        repository_snapshot_id=ctx.get("repositorySnapshotId"),
        build_context_id=ctx.get("buildContextId"),
        analysis_artifact_set_id=ctx.get("analysisArtifactSetId"),
        graph_node_ids=ctx.get("graphNodeIds") or None,
        evidence_snippet_ids=ctx.get("evidenceSnippetIds") or None,
        rich_ir_artifact_ids=ctx.get("richIrArtifactIds") or None,
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
    cached_fragment, cache_trace = get_decision_fragment(decision_fragment_key)
    source_context = _resolve_source_context(repo, request, canonical_query["normalized"]["sourceContext"])
    source_resolved = bool(source_context.get("resolved"))
    excludes = set(canonical_query["controlSummary"]["accepted"]["exclude"])
    applied_controls = canonical_query["controlSummary"]
    requested_controls = applied_controls["requested"]
    fallback_trace: list[dict[str, Any]] = []
    if request.source_context is not None and not source_resolved:
        fallback_trace.append({"stage": "source_code_kg_context", "fallback": "unresolved_context", "silent": False})
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
            decision_fragment_key,
            {
                "affectedness": affectedness,
                "keptEvidence": kept_evidence,
                "suppressedEvidence": suppressed,
                "controlEffects": control_effects,
            },
            cache_trace,
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
    )
    reasoning_path.append(
        {
            "step": "assemble_threat_kb_context",
            "status": "complete" if threat_retrieval["candidateEvidence"] else "no_context",
            "methodsUsed": threat_retrieval["methodsUsed"],
            "diagnostics": threat_retrieval["diagnostics"],
        }
    )
    score_vector = _empty_score_vector(source_resolved=source_resolved, affectedness_status=affectedness["affectedness"], excluded=bool(suppressed))
    score_policy = evaluate_score_vector(score_vector, phase="serving", profile=settings.default_scoring_profile)
    answer = {
        "schemaVersion": SCHEMA_VERSION,
        "verdictAuthority": VERDICT_AUTHORITY,
        "canonicalQuery": canonical_query,
        "decisionFragmentKey": decision_fragment_key,
        "cacheTrace": cache_trace,
        "verdict": verdict,
        "status": status,
        "reason": reason,
        "queryContext": {
            "question": request.question,
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
            "reason": reason if verdict == "unknown" else None,
            "evidenceGaps": _evidence_gaps(verdict, source_resolved),
            "requiredInputs": [] if verdict != "unknown" else ["component.version", "component.identity", "sourceContext"] if not source_resolved else ["additional affectedness evidence or re-query controls"],
            "conflicts": [],
        },
        "followUpAffordances": _follow_up_affordances(verdict, missing_inputs=[], source_resolved=source_resolved),
        "qualityGate": _quality_gate(quality_gate, affectedness.get("diagnostics", []), score_policy),
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
    if component.get("version"):
        threat_retrieval = build_threat_retrieval_evidence(
            repo,
            component,
            {"evidence": [], "identityResolution": identity_resolution, "affectedness": "unknown"},
            identity_resolution,
            canonical_query["controlSummary"],
        )
    fallback_trace = list(fallback_trace or [])
    if request.source_context is not None and not source_resolved and not any(item.get("fallback") == "unresolved_context" for item in fallback_trace):
        fallback_trace.append({"stage": "source_code_kg_context", "fallback": "unresolved_context", "silent": False})
    if canonical_query["controlSummary"]["rejected"] and not any(item.get("fallback") == "unsupported_controls_rejected" for item in fallback_trace):
        fallback_trace.append(
            {
                "stage": "control_validation",
                "fallback": "unsupported_controls_rejected",
                "silent": False,
                "rejected": canonical_query["controlSummary"]["rejected"],
            }
        )
    score_vector = _empty_score_vector(source_resolved=source_resolved, affectedness_status="unknown")
    score_policy = evaluate_score_vector(score_vector, phase="serving", profile=settings.default_scoring_profile)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "verdictAuthority": VERDICT_AUTHORITY,
        "canonicalQuery": canonical_query,
        "decisionFragmentKey": canonical_query["decisionFragmentKey"],
        "cacheTrace": {"schemaVersion": "s5-decision-cache-trace-v1", "decisionFragmentKey": canonical_query["decisionFragmentKey"], "hit": False, "miss": True, "stored": False, "reason": "missing_inputs_not_cached"},
        "verdict": "unknown",
        "status": "requires_requery" if missing_inputs else "insufficient_input",
        "reason": reason,
        "queryContext": {
            "question": request.question,
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
            "evidenceGaps": missing_inputs,
            "requiredInputs": missing_inputs,
            "conflicts": [],
        },
        "followUpAffordances": _follow_up_affordances("unknown", missing_inputs=missing_inputs, source_resolved=source_resolved),
        "qualityGate": _quality_gate(
            "accepted_with_caveats",
            [{"code": "GROUNDED_UNKNOWN", "missingInputs": missing_inputs}],
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
        "graphNodes": source_context.get("graphNodes", []),
        "graphEdges": source_context.get("graphEdges", []),
        "evidenceSnippets": source_context.get("evidenceSnippets", []),
        "richIrArtifacts": source_context.get("richIrArtifacts", []),
        "resolved": bool(source_context.get("resolved")),
    }


def _evidence_gaps(verdict: str, source_resolved: bool) -> list[str]:
    gaps: list[str] = []
    if verdict == "unknown":
        gaps.append("affectedness evidence")
    if not source_resolved:
        gaps.append("source code kg context")
    return gaps


def _follow_up_affordances(verdict: str, *, missing_inputs: list[str], source_resolved: bool) -> list[dict[str, Any]]:
    if verdict != "unknown":
        return []
    affordances = []
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


def validate_judge_answer(answer: dict[str, Any]) -> list[dict[str, Any]]:
    """Contract validator used by tests and future quality gates."""

    issues: list[dict[str, Any]] = []
    if answer.get("schemaVersion") != SCHEMA_VERSION:
        issues.append({"code": "INVALID_SCHEMA_VERSION"})
    if answer.get("verdictAuthority") != VERDICT_AUTHORITY:
        issues.append({"code": "INVALID_VERDICT_AUTHORITY"})
    for field in ("canonicalQuery", "decisionFragmentKey", "cacheTrace", "fallbackTrace", "servingLedger"):
        if field not in answer:
            issues.append({"code": "MISSING_SERVING_FIELD", "field": field})
    forbidden = set(answer.get("forbiddenInferences") or [])
    required_forbidden = set(BASELINE_FORBIDDEN_INFERENCES)
    missing_forbidden = sorted(required_forbidden - forbidden)
    if missing_forbidden:
        issues.append({"code": "MISSING_FORBIDDEN_INFERENCES", "missing": missing_forbidden})
    verdict = answer.get("verdict")
    if verdict == "unknown":
        uncertainty = answer.get("uncertainty") or {}
        if not uncertainty.get("reason") or not uncertainty.get("evidenceGaps") or not answer.get("followUpAffordances"):
            issues.append({"code": "LAZY_UNKNOWN"})
    requested_source_context = ((answer.get("queryContext") or {}).get("sourceContext") or {})
    if requested_source_context:
        source_evidence = ((answer.get("evidence") or {}).get("sourceCodeKg") or {})
        fallback_trace = answer.get("fallbackTrace") or []
        unresolved_context_explained = any(
            item.get("stage") == "source_code_kg_context"
            and item.get("fallback") == "unresolved_context"
            and item.get("silent") is False
            for item in fallback_trace
        )
        if not source_evidence.get("resolved") and not unresolved_context_explained:
            issues.append({"code": "SOURCE_KG_CONTEXT_IGNORED"})
    return issues
