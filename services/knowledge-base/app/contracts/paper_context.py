"""Machine-readable S5 paper-context contract snapshot."""

from __future__ import annotations

FORBIDDEN_LEAKAGE_CLASSES = ["cve_id", "fix_commit", "advisory", "exploit_writeup", "patch_text"]


def paper_context_contract_snapshot() -> dict:
    return {
        "schemaVersion": "s5-paper-context-contract-v1",
        "contractVersion": "s5-paper-context-api-v1",
        "producer": "s5-knowledge-base",
        "status": "implemented_hard_now_subset_freeze_gate_not_passed",
        "consumerBoundary": "contextual_support_not_final_verdict",
        "negativeEvidenceAllowed": False,
        "defaultVisibilityMode": "generic",
        "endpoints": [
            {
                "toolName": "prepare_code_kb",
                "method": "POST",
                "path": "/v1/paper/code-kb/prepare",
                "requestSchemaVersion": "s5-prepare-code-kb-request-v1",
                "responseSchemaVersion": "s5-prepare-code-kb-response-v1",
                "timeoutHeaderRequired": True,
            },
            {
                "toolName": "retrieve_finding_context",
                "method": "POST",
                "path": "/v1/paper/finding-context/retrieve",
                "requestSchemaVersion": "s5-retrieve-finding-context-request-v1",
                "responseSchemaVersion": "s5-retrieve-finding-context-response-v1",
                "timeoutHeaderRequired": True,
            },
            {
                "toolName": "retrieve_generic_threat_context",
                "method": "POST",
                "path": "/v1/paper/threat-context/generic",
                "requestSchemaVersion": "s5-retrieve-generic-threat-context-request-v1",
                "responseSchemaVersion": "s5-retrieve-generic-threat-context-response-v1",
                "timeoutHeaderRequired": True,
            },
        ],
        "enums": {
            "surfaceStatus": ["produced", "no_hit", "partial", "not_available", "error"],
            "sourceType": ["code", "symbol", "cwe", "capec", "generic_security_note", "library_provenance", "diagnostic"],
            "visibleLeakageClass": ["generic", *FORBIDDEN_LEAKAGE_CLASSES],
            "visibilityMode": ["generic"],
        },
        "policies": {
            "mainlineVisibilityMode": "generic",
            "mainlineForbiddenLeakageClasses": list(FORBIDDEN_LEAKAGE_CLASSES),
            "b2b4EvidenceControl": "same_rows_text_order_required",
            "forbiddenInferencePolicy": "producer_status_is_not_final_triage",
            "paperErrorCodesPreserved": True,
            "idempotencyFingerprintExcludes": ["requestId", "X-Request-Id", "X-Timeout-Ms", "attemptMetadata"],
        },
        "freezeGate": {
            "s5VisiblePacketSchemaFinalized": False,
            "hardNowSubsetImplemented": True,
            "visibleLeakageClassRequiredForEveryVisibleRow": True,
            "genericThreatKbLeakageCorpusTestRequired": True,
            "diagnosticStatusNotTpFpEvidence": True,
            "finalVerdictFieldsForbidden": True,
            "s5FreezeGate": "not_run",
        },
        "producerBoundary": {
            "s5HitMeans": "contextual_support_only",
            "s5NoHitMeans": "context_gap_only",
            "finalTriageOwner": "s3",
        },
    }
