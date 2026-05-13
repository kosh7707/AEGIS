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
