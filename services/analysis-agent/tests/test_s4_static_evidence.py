from app.core.s4_static_evidence import (
    extract_static_evidence_contract,
    summarize_static_evidence_contract,
)


def test_quality_gate_split_pass_is_not_static_evidence_readiness():
    payload = {
        "success": True,
        "findings": [],
        "qualityGate": {
            "validationMetrics": {"status": "pass"},
            "testMetrics": {"status": "pass"},
            "canaryMetrics": {"status": "pass"},
            "localQualityAssessment": {"status": "fail"},
        },
    }

    contract = extract_static_evidence_contract(payload)
    summary = summarize_static_evidence_contract(contract)

    assert contract == {}
    assert summary["ready"] is False
    assert "STATIC_EVIDENCE_CONTRACT_MISSING" in summary["reasonCodes"]


def _ready_static_contract(**overrides):
    contract = {
        "gates": {
            "systemStability": {"status": "pass"},
            "evidenceReadiness": {"status": "ready"},
            "claimSupportReadiness": {"status": "pass"},
        },
        "coverage": {
            "staticToolExecution": {"status": "provided", "consumerPolicy": "observed_positive_evidence_only"},
            "sastFindings": {"status": "provided", "consumerPolicy": "observed_positive_evidence_only"},
            "findingLocations": {"status": "provided", "consumerPolicy": "observed_positive_evidence_only"},
            "findingCweMapping": {"status": "provided", "consumerPolicy": "observed_positive_evidence_only"},
            "originClassification": {"status": "provided", "consumerPolicy": "observed_positive_evidence_only"},
        },
        "claimBoundaries": {
            "mustNotSupportAlone": [
                "absence-of-vulnerability-from-empty-findings",
                "external-vulnerability-affectedness",
                "semantic-graph-completeness",
                "runtime-exploitability",
                "final-security-verdict",
            ],
            "negativeEvidencePolicy": "empty-or-missing-s4-evidence-is-not-negative-security-evidence",
        },
        "claimBoundaryMatrix": [{"claimId": "absence-of-vulnerability", "support": "out-of-scope"}],
        "toolEvidenceMatrix": [{"toolId": "semgrep", "status": "complete"}],
    }
    contract.update(overrides)
    return contract


_CURRENT_SIX = ["semgrep", "cppcheck", "flawfinder", "clang-tidy", "scan-build", "gcc-fanalyzer"]


def _complete_static_contract(**overrides):
    contract = _ready_static_contract(
        claimBoundaryMatrix=[
            {"claimId": "local-static-artifact", "supportStatus": "supported"},
            {"claimId": "reported-finding-positive-evidence", "supportStatus": "not_applicable"},
            {"claimId": "absence-of-vulnerability", "supportStatus": "unsupported"},
            {"claimId": "cwe-absence", "supportStatus": "unsupported"},
            {"claimId": "build-configuration-dependent-negative-claim", "supportStatus": "unsupported"},
            {"claimId": "runtime-behavior", "supportStatus": "unsupported"},
            {"claimId": "external-vulnerability-affectedness", "supportStatus": "unsupported"},
            {"claimId": "semantic-graph-completeness", "supportStatus": "unsupported"},
            {"claimId": "exploitability-judgment", "supportStatus": "unsupported"},
            {"claimId": "final-security-verdict", "supportStatus": "unsupported"},
        ],
        toolEvidenceMatrix=[
            {
                "toolId": tool_id,
                "status": "ok",
                "consumerPolicy": "local_tool_execution_state_only_not_vulnerability_verdict",
            }
            for tool_id in _CURRENT_SIX
        ],
    )
    contract.update(overrides)
    return contract


def test_empty_static_evidence_matrices_are_not_ready():
    summary = summarize_static_evidence_contract(_ready_static_contract(
        claimBoundaryMatrix=[],
        toolEvidenceMatrix=[],
    ))

    assert summary["ready"] is False
    assert "CLAIM_BOUNDARY_MATRIX_EMPTY" in summary["reasonCodes"]
    assert "TOOL_EVIDENCE_MATRIX_EMPTY" in summary["reasonCodes"]


def test_declared_required_tool_coverage_is_checked_without_s3_hardcoding_toolset():
    summary = summarize_static_evidence_contract(_ready_static_contract(
        expectedToolSet={"requiredToolIds": ["semgrep", "cppcheck"]},
        toolEvidenceMatrix=[{"toolId": "semgrep", "status": "complete"}],
    ))

    assert summary["ready"] is False
    assert any("cppcheck" in code for code in summary["reasonCodes"])


def test_complete_current_six_contract_is_ready_with_exact_summary_schema():
    summary = summarize_static_evidence_contract(_complete_static_contract())

    assert summary["ready"] is True
    assert summary["localStaticEvidenceReady"] is True
    assert summary["summarySchemaVersion"] == "s4-static-evidence-contract-consumer-summary-v1"
    assert summary["observedToolIds"] == _CURRENT_SIX
    assert set(summary) == {
        "summarySchemaVersion",
        "ready",
        "localStaticEvidenceReady",
        "reasonCodes",
        "summary",
        "systemStability",
        "evidenceReadiness",
        "claimSupportReadiness",
        "hasClaimBoundaryMatrix",
        "hasToolEvidenceMatrix",
        "claimBoundaryMatrixCount",
        "toolEvidenceMatrixCount",
        "declaredRequiredToolIds",
        "observedToolIds",
        "missingRequiredToolIds",
        "requiredCoverageStatuses",
        "claimSupportStatuses",
        "toolMatrixStatuses",
        "toolConsumerPolicies",
        "unsupportedClaims",
        "unsafeProjection",
    }


def test_pass_gates_without_required_coverage_are_not_ready():
    contract = _complete_static_contract(coverage={})

    summary = summarize_static_evidence_contract(contract)

    assert summary["ready"] is False
    assert summary["localStaticEvidenceReady"] is False
    assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" in summary["reasonCodes"]
    assert "COVERAGE_SURFACE_MISSING:staticToolExecution" in summary["reasonCodes"]


def test_duplicate_tool_or_claim_rows_are_unsafe_projection():
    contract = _complete_static_contract(
        toolEvidenceMatrix=[
            *_complete_static_contract()["toolEvidenceMatrix"],
            {
                "toolId": "semgrep",
                "status": "ok",
                "consumerPolicy": "local_tool_execution_state_only_not_vulnerability_verdict",
            },
        ],
        claimBoundaryMatrix=[
            *_complete_static_contract()["claimBoundaryMatrix"],
            {"claimId": "absence-of-vulnerability", "supportStatus": "supported"},
        ],
    )

    summary = summarize_static_evidence_contract(contract)

    assert summary["ready"] is False
    assert summary["unsafeProjection"] is True
    assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" in summary["reasonCodes"]
    assert summary["claimSupportStatuses"]["absence-of-vulnerability"] == "unsupported"


def test_malformed_present_containers_are_unsafe_projection():
    summary = summarize_static_evidence_contract(_complete_static_contract(coverage="not-a-map"))

    assert summary["ready"] is False
    assert summary["unsafeProjection"] is True
    assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" in summary["reasonCodes"]


def test_degraded_contract_missing_completeness_is_not_ready_but_not_unsafe_by_itself():
    summary = summarize_static_evidence_contract({
        "gates": {
            "systemStability": {"status": "degraded", "reasonCodes": ["TOOL_PARTIAL:scan-build"]},
            "evidenceReadiness": {"status": "partial", "reasonCodes": ["LOCAL_EVIDENCE_PARTIAL"]},
            "claimSupportReadiness": {"status": "partial", "reasonCodes": ["LOCAL_ARTIFACT_DEGRADED"]},
        },
        "coverage": {},
        "claimBoundaryMatrix": [],
        "toolEvidenceMatrix": [],
    })

    assert summary["ready"] is False
    assert summary["unsafeProjection"] is False
    assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" not in summary["reasonCodes"]
