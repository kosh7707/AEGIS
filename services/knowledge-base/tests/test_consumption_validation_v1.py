from __future__ import annotations

from app.evaluation.consumption_validation import (
    CLAIM_SUPPORT_FORBIDDEN_CLASSES,
    CONDITIONAL_PASS_REQUIREMENTS,
    REQUIRED_SCENARIO_CASE_IDS,
    REQUIRED_SOURCE_KINDS,
    build_consumption_validation_report,
    build_s3_conditional_pass_audit,
    build_source_family_audit,
    load_consumption_manifest,
    load_source_manifest,
    validate_consumption_manifest,
)


def _cases_by_id():
    manifest = load_consumption_manifest()
    return {case["caseId"]: case for case in manifest["scenarioCases"]}


def test_consumption_manifest_is_schema_valid_and_covers_required_scenarios():
    manifest = load_consumption_manifest()

    assert validate_consumption_manifest(manifest) == []
    assert manifest["schemaVersion"] == "s5-consumption-validation-v1"
    assert REQUIRED_SCENARIO_CASE_IDS <= {case["caseId"] for case in manifest["scenarioCases"]}
    assert REQUIRED_SOURCE_KINDS <= {row["sourceKind"] for row in build_source_family_audit(load_source_manifest())["rows"]}
    assert set(CONDITIONAL_PASS_REQUIREMENTS) <= set(manifest["s3ConditionalPassRequirementIds"])



def test_s3_evidence_mapping_prohibits_knowledge_operational_negative_claim_support():
    manifest = load_consumption_manifest()

    for case in manifest["scenarioCases"]:
        expected = case["expectedS3"]
        if expected["evidenceClass"] in CLAIM_SUPPORT_FORBIDDEN_CLASSES:
            assert expected["maySupportClaim"] is False, case["caseId"]
            assert any("supportingEvidenceRefs" in item for item in case["forbiddenUses"]) or expected["evidenceClass"] != "knowledge"

    cases = _cases_by_id()
    assert cases["version-known-cve-discovery-hit-contextual-only"]["expectedS3"]["placement"] == [
        "contextualEvidenceRefs",
        "caveats",
    ]
    assert "true_positive" in cases["s5-completed-hit-knowledge-not-tp-or-claim-support"]["forbiddenUses"]


def test_completed_no_hit_cases_are_scoped_or_downgraded_non_negative():
    report = build_consumption_validation_report()

    assert report["s3S4Consumption"]["noHitEligibilityIssues"] == []
    candidate = _cases_by_id()["candidate-range-out-excludes-only-specific-cve"]
    assert candidate["s5Envelope"]["acquisitionStatus"] == "completed_no_hit"
    assert candidate["expectedS3"]["negativeScope"] == "specific_candidate_only"
    assert "library_safe" in candidate["forbiddenUses"]

    keyword = _cases_by_id()["keyword-only-fallback-no-result-not-no-hit"]
    assert keyword["s5Envelope"]["acquisitionStatus"] == "incomplete_acquisition"
    assert keyword["s5Envelope"]["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert keyword["expectedS3"]["mayBeNegativeEvidence"] is False



def test_source_family_audit_has_no_silent_omissions_and_marks_manifest_only_deferrals():
    audit = build_source_family_audit(load_source_manifest())
    rows = {row["sourceFamilyItem"]: row for row in audit["rows"]}

    assert audit["status"] == "passed"
    assert set(rows) == set(load_consumption_manifest()["sourceFamilyAuditExpectations"])
    assert REQUIRED_SOURCE_KINDS <= {row["sourceKind"] for row in audit["rows"]}
    for item in ["vuln-osv", "vuln-nvd-cve", "vuln-ghsa", "vuln-cisa-kev", "vuln-first-epss", "weakness-cwe", "package-cpe-dictionary", "profile-automotive-specialization", "tool-rule-semgrep"]:
        assert rows[item]["status"] == "fixture_backed"
        assert rows[item]["sourceKind"]
        assert rows[item]["rationale"]
    for item in ["attack-capec", "attack-ics", "attack-enterprise-subset"]:
        assert rows[item]["status"] == "fixture_backed"
        assert rows[item]["rawArtifactCount"] == 1
        assert rows[item]["manifestCompletedCoverage"] is True
        assert rows[item]["rationale"]



def test_s3_conditional_pass_audit_is_row_by_row_and_explicit():
    audit = build_s3_conditional_pass_audit()

    assert audit["status"] == "passed"
    assert {row["requirementId"] for row in audit["rows"]} == set(CONDITIONAL_PASS_REQUIREMENTS)
    for row in audit["rows"]:
        assert row["status"] in {"implemented", "fixture_backed", "manifest_only_deferred", "not_applicable"}
        assert row["evidenceRefs"], row["requirementId"]
        assert row["rationale"], row["requirementId"]



def test_consumption_report_safety_checks_separate_runtime_from_offline_quality():
    report = build_consumption_validation_report()

    assert report["schemaVersion"] == "s5-consumption-validation-report-v1"
    assert report["offlineOnly"] is True
    assert report["runtimeClaimSupport"] is False
    assert report["status"] == "passed"
    assert report["manifestIssues"] == []
    assert report["safetyChecks"] == {
        "noUnsafeNegativeEvidence": True,
        "noKnowledgeOnlyClaimSupport": True,
        "noRuntimeOfflineVocabularyLeak": True,
        "runtimeOfflineVocabularyLeakCases": [],
    }
    assert report["offlineQualityGateRefs"] == [
        "services/knowledge-base/fixtures/golden-set-v1/manifest.json"
    ]
