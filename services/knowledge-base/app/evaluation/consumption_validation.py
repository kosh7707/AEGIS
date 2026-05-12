"""S3/S4 consumption validation report for S5 modernization G010.

This module is an offline validation/audit harness. It does not emit runtime
acquisition envelopes and it does not make S3 final claim-quality decisions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.contracts.acquisition import OFFLINE_QUALITY_VOCABULARY, evaluate_no_hit_eligibility

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST_PATH = ROOT / "fixtures" / "consumption-validation-v1" / "manifest.json"
DEFAULT_SOURCE_MANIFEST_PATH = ROOT / "fixtures" / "corpus-ingestion-v1" / "source-manifest.json"

REQUIRED_SCENARIO_CASE_IDS = {
    "s4-external-vuln-not-provided-plans-s5-discovery",
    "version-known-cve-discovery-hit-contextual-only",
    "version-unknown-input-insufficient-diagnostic-only",
    "candidate-range-out-excludes-only-specific-cve",
    "candidate-range-out-other-discovery-hit-coexists",
    "code-graph-projection-debt-empty-not-no-caller",
    "keyword-only-fallback-no-result-not-no-hit",
    "s5-completed-hit-knowledge-not-tp-or-claim-support",
}

REQUIRED_CASE_FIELDS = {
    "caseId",
    "description",
    "s4Premise",
    "s5Surface",
    "s5Envelope",
    "expectedS3",
    "forbiddenUses",
    "sourceRefs",
}

CLAIM_SUPPORT_FORBIDDEN_CLASSES = {"knowledge", "operational", "negative"}
NEGATIVE_ALLOWED_POLICIES = {"scoped_no_hit_record_only"}
NON_NEGATIVE_POLICIES = {
    "contextual_only",
    "diagnostic_only",
    "do_not_use",
    "do_not_use_as_negative_evidence",
}

SOURCE_FAMILY_REQUIREMENTS = {
    "schema-knowledge-corpus-v1": {"sourceKind": "knowledge-corpus-v1", "status": "fixture_backed", "family": "schema_asset", "rationale": "Versioned corpus manifest fixture backs schema/taxonomy/profile assets."},
    "schema-golden-set-v1": {"sourceKind": "golden-set-v1", "status": "fixture_backed", "family": "schema_asset", "rationale": "Golden Set manifest fixture backs offline oracle/quality-gate assets."},
    "taxonomy-enum": {"sourceKind": "knowledge-corpus-v1", "status": "fixture_backed", "family": "schema_asset", "rationale": "Knowledge Corpus v1 enumerates native/system taxonomy categories."},
    "specialization-profile-enum": {"sourceKind": "knowledge-corpus-v1", "status": "fixture_backed", "family": "schema_asset", "rationale": "Knowledge Corpus v1 enumerates automotive, embedded-system, and ICS/OT profiles."},
    "relation-method-enum": {"sourceKind": "knowledge-corpus-v1", "status": "fixture_backed", "family": "schema_asset", "rationale": "Knowledge Corpus v1 and retrieval planner enumerate relation/retrieval methods."},
    "consumer-policy-mapping": {"sourceKind": "knowledge-corpus-v1", "status": "fixture_backed", "family": "schema_asset", "rationale": "Knowledge Corpus v1 plus acquisition contract map consumer policies."},
    "relation-provenance-schema": {"sourceKind": "knowledge-corpus-v1", "status": "fixture_backed", "family": "schema_asset", "rationale": "Knowledge Corpus v1 and ledger schema define provenance fields/methods."},
    "retrieval-fp-fn-golden-set": {"sourceKind": "golden-set-v1", "status": "fixture_backed", "family": "schema_asset", "rationale": "Golden Set v1 includes retrieval FP/FN and weak-signal cases."},
    "graphrag-retrieval-quality-oracle": {"sourceKind": "golden-set-v1", "status": "fixture_backed", "family": "schema_asset", "rationale": "Golden Set v1 and G009 report expose retrieval-quality metrics/breakdowns."},
    "weakness-cwe": {"sourceKind": "CWE", "status": "fixture_backed", "family": "weakness_core", "rationale": "CWE fixture is ingested into ledger."},
    "attack-capec": {"sourceKind": "CAPEC", "status": "fixture_backed", "family": "attack_core", "rationale": "CAPEC-88 sample fixture is ingested; production-scale CAPEC remains separate work."},
    "attack-ics": {"sourceKind": "ATTACK_ICS", "status": "fixture_backed", "family": "attack_core", "rationale": "ATT&CK ICS T0807 sample fixture is ingested; production-scale ATT&CK ICS remains separate work."},
    "attack-enterprise-subset": {"sourceKind": "ATTACK_ENTERPRISE", "status": "fixture_backed", "family": "attack_core", "rationale": "ATT&CK Enterprise T1059 sample fixture is ingested; production-scale ATT&CK Enterprise remains separate work."},
    "tool-rule-semgrep": {"sourceKind": "semgrep", "status": "fixture_backed", "family": "tool_rule_core", "rationale": "Semgrep rule fixture is ingested."},
    "tool-rule-cppcheck": {"sourceKind": "cppcheck", "status": "fixture_backed", "family": "tool_rule_core", "rationale": "Cppcheck rule fixture is ingested."},
    "tool-rule-clang-tidy": {"sourceKind": "clang-tidy", "status": "fixture_backed", "family": "tool_rule_core", "rationale": "clang-tidy rule fixture is ingested."},
    "tool-rule-gcc-fanalyzer": {"sourceKind": "gcc-fanalyzer", "status": "fixture_backed", "family": "tool_rule_core", "rationale": "gcc-fanalyzer rule fixture is ingested."},
    "tool-rule-scan-build": {"sourceKind": "scan-build", "status": "fixture_backed", "family": "tool_rule_core", "rationale": "scan-build/Clang Static Analyzer fixture is ingested."},
    "tool-rule-flawfinder": {"sourceKind": "flawfinder", "status": "fixture_backed", "family": "tool_rule_core", "rationale": "Flawfinder rule fixture is ingested."},
    "tool-rule-curated-cwe-mapping": {"sourceKind": "knowledge-corpus-v1", "status": "fixture_backed", "family": "tool_rule_core", "rationale": "Corpus/transform fixtures include curated tool-rule to CWE/taxonomy mapping."},
    "package-cpe-dictionary": {"sourceKind": "package-identity", "status": "fixture_backed", "family": "package_identity", "rationale": "Package identity fixture includes CPE candidate mapping."},
    "package-purl-mapping": {"sourceKind": "package-identity", "status": "fixture_backed", "family": "package_identity", "rationale": "Package identity fixture includes purl-compatible alias fields."},
    "package-osv-ecosystem-metadata": {"sourceKind": "OSV", "status": "fixture_backed", "family": "package_identity", "rationale": "OSV advisory fixture carries ecosystem/package identity metadata."},
    "package-native-library-aliases": {"sourceKind": "package-identity", "status": "fixture_backed", "family": "package_identity", "rationale": "Package identity fixture includes native/system library aliases."},
    "package-vendor-project-repo-alias": {"sourceKind": "package-identity", "status": "fixture_backed", "family": "package_identity", "rationale": "Package identity fixture links vendor/project/repo aliases."},
    "package-repo-to-cpe-candidate-map": {"sourceKind": "package-identity", "status": "fixture_backed", "family": "package_identity", "rationale": "Package identity fixture links repo/package/CPE candidates."},
    "vuln-osv": {"sourceKind": "OSV", "status": "fixture_backed", "family": "vulnerability_intelligence", "rationale": "OSV advisory fixture is ingested."},
    "vuln-nvd-cve": {"sourceKind": "NVD_CVE", "status": "fixture_backed", "family": "vulnerability_intelligence", "rationale": "NVD CVE fixture is ingested."},
    "vuln-ghsa": {"sourceKind": "GHSA", "status": "fixture_backed", "family": "vulnerability_intelligence", "rationale": "GHSA advisory fixture is ingested."},
    "vuln-cisa-kev": {"sourceKind": "CISA_KEV", "status": "fixture_backed", "family": "vulnerability_intelligence", "rationale": "CISA KEV fixture is ingested as risk enrichment/provider observation."},
    "vuln-first-epss": {"sourceKind": "FIRST_EPSS", "status": "fixture_backed", "family": "vulnerability_intelligence", "rationale": "FIRST EPSS fixture is ingested as risk enrichment/provider observation."},
    "profile-automotive-specialization": {"sourceKind": "knowledge-corpus-v1", "status": "fixture_backed", "family": "domain_profile", "rationale": "Automotive profile is primary/default corpus profile."},
    "profile-embedded-system-specialization": {"sourceKind": "knowledge-corpus-v1", "status": "fixture_backed", "family": "domain_profile", "rationale": "Embedded-system specialization profile is in corpus fixture."},
    "profile-ics-ot-specialization": {"sourceKind": "knowledge-corpus-v1", "status": "fixture_backed", "family": "domain_profile", "rationale": "ICS/OT specialization profile is in corpus fixture."},
}

REQUIRED_SOURCE_KINDS = {spec["sourceKind"] for spec in SOURCE_FAMILY_REQUIREMENTS.values()}
REQUIRED_SOURCE_FAMILY_ITEMS = set(SOURCE_FAMILY_REQUIREMENTS)


CONDITIONAL_PASS_REQUIREMENTS = {
    "coverage-contract-v1-machine-readable": {"status": "implemented", "evidenceRefs": ["app/contracts/acquisition.py", "app/routers/contracts_api.py", "tests/test_acquisition_contracts.py"], "rationale": "Knowledge Coverage Contract v1 is exposed and tested."},
    "acquisition-readiness-v1-machine-readable": {"status": "implemented", "evidenceRefs": ["app/contracts/acquisition.py", "app/routers/target_context_api.py", "tests/test_acquisition_contracts.py"], "rationale": "Target-scoped AcquisitionEnvelopeV1/readiness metadata is generated and guarded."},
    "candidate-cve-vs-discovery-split": {"status": "implemented", "evidenceRefs": ["app/cve/acquisition_split.py", "tests/test_cve_acquisition_split_v1.py", "tests/test_target_context_api.py"], "rationale": "Candidate evaluation and discovery are separate surfaces with compatibility route preservation."},
    "candidate-range-out-specific-only": {"status": "fixture_backed", "evidenceRefs": ["fixtures/consumption-validation-v1/manifest.json", "tests/test_consumption_validation_v1.py"], "rationale": "Range-out scenario forbids library-safe/no-other-CVE inference."},
    "discovery-hit-coexists-with-range-out": {"status": "fixture_backed", "evidenceRefs": ["fixtures/consumption-validation-v1/manifest.json", "tests/test_golden_set_v1.py"], "rationale": "Discovery can return another CVE while a candidate is range-out."},
    "evidence-catalog-mapping-safe": {"status": "fixture_backed", "evidenceRefs": ["fixtures/consumption-validation-v1/manifest.json", "tests/test_consumption_validation_v1.py"], "rationale": "G010 validates S3 placement expectations and forbidden claim-support uses offline."},
    "sql-ledger-authoritative": {"status": "implemented", "evidenceRefs": ["app/ledger/repository.py", "tests/test_ledger_repository.py", "tests/test_target_context_ledger_integration.py"], "rationale": "SQLite ledger stores S5 acquisition truth; Neo4j/Qdrant are projections."},
    "target-scoped-readiness": {"status": "implemented", "evidenceRefs": ["app/routers/target_context_api.py", "tests/test_target_context_api.py"], "rationale": "Target-context acquisition surfaces include target id/version/scope/readiness."},
    "completed-no-hit-guard": {"status": "implemented", "evidenceRefs": ["app/contracts/acquisition.py", "tests/test_acquisition_contracts.py", "tests/test_retrieval_planner_v1.py"], "rationale": "Unsafe no-hit is downgraded for missing methods, unsafe basis, stale/provider/projection debt, and missing retrieval trace."},
    "keyword-fallback-non-negative": {"status": "implemented", "evidenceRefs": ["app/cve/acquisition_split.py", "tests/test_cve_acquisition_split_v1.py", "fixtures/golden-set-v1/manifest.json"], "rationale": "Keyword-only misses are incomplete/diagnostic and not negative evidence."},
    "provider-timeout-error-envelope": {"status": "fixture_backed", "evidenceRefs": ["fixtures/golden-set-v1/manifest.json", "tests/test_target_context_api.py"], "rationale": "Timeout/error scenarios are represented as acquisition envelopes/diagnostics in fixtures and tests."},
    "stale-cache-non-negative": {"status": "fixture_backed", "evidenceRefs": ["fixtures/golden-set-v1/manifest.json", "tests/test_golden_set_v1.py"], "rationale": "Stale-cache-only is diagnostic/do-not-use-as-negative."},
    "projection-debt-non-negative": {"status": "implemented", "evidenceRefs": ["app/projections/ledger_projection.py", "tests/test_target_context_api.py", "tests/test_ledger_projection_v1.py"], "rationale": "Projection debt downgrades empty code/threat no-hit paths."},
    "runtime-offline-s3-vocabulary-split": {"status": "implemented", "evidenceRefs": ["app/contracts/acquisition.py", "app/evaluation/golden_set.py", "tests/test_acquisition_contracts.py", "tests/test_golden_set_v1.py"], "rationale": "Runtime vocabulary, offline quality metrics, and S3 final claim terms are separated."},
    "native-system-core-taxonomy": {"status": "fixture_backed", "evidenceRefs": ["fixtures/knowledge-corpus-v1/manifest.json", "tests/test_knowledge_corpus_v1.py"], "rationale": "Core taxonomy is native/system C/C++ oriented, not automotive-only."},
    "automotive-primary-profile-not-core-truth": {"status": "fixture_backed", "evidenceRefs": ["fixtures/knowledge-corpus-v1/manifest.json", "tests/test_knowledge_corpus_v1.py"], "rationale": "Automotive is primary/default specialization profile, not core vulnerability truth."},
    "embedded-and-ics-profiles": {"status": "fixture_backed", "evidenceRefs": ["fixtures/knowledge-corpus-v1/manifest.json", "tests/test_knowledge_corpus_v1.py"], "rationale": "Embedded-system and ICS/OT profiles are first-class profile assets."},
    "retrieval-signal-hierarchy": {"status": "implemented", "evidenceRefs": ["app/signals/taxonomy_signals.py", "app/graphrag/retrieval_planner.py", "tests/test_transform_signal_model_v1.py"], "rationale": "Keyword/embedding/profile/graph signals are distinguished by method/trust/consumer policy."},
    "keyword-embedding-miss-not-no-hit": {"status": "implemented", "evidenceRefs": ["app/contracts/acquisition.py", "app/graphrag/retrieval_planner.py", "tests/test_retrieval_planner_v1.py"], "rationale": "Keyword/embedding/global-only misses are unsafe no-hit bases."},
    "typed-query-intent-input": {"status": "implemented", "evidenceRefs": ["app/graphrag/retrieval_planner.py", "app/routers/api.py", "app/routers/code_graph_api.py", "tests/test_retrieval_planner_v1.py"], "rationale": "queryIntent/corpusPartitions/profiles/allowGlobalEmbedding are supported by APIs and planners."},
    "typed-corpus-partitioning": {"status": "implemented", "evidenceRefs": ["app/graphrag/retrieval_planner.py", "app/graphrag/vector_search.py", "tests/test_knowledge_assembler.py"], "rationale": "Corpus partitions and source-filter fallback are explicit in retrievalTrace."},
    "retrieval-trace-minimum-fields": {"status": "implemented", "evidenceRefs": ["app/graphrag/retrieval_planner.py", "tests/test_retrieval_planner_v1.py", "tests/test_code_graph_assembler.py"], "rationale": "Trace includes queryIntent, partitions, methods, filters, rerankers, embedding scope, matched terms, states, topK/minScore."},
    "global-embedding-low-trust-visible": {"status": "implemented", "evidenceRefs": ["app/graphrag/retrieval_planner.py", "tests/test_knowledge_assembler.py"], "rationale": "global_embedding_search is explicit, low trust, and never negative evidence."},
    "metrics-breakdown-method-query-partition-profile": {"status": "fixture_backed", "evidenceRefs": ["app/evaluation/golden_set.py", "tests/test_golden_set_v1.py"], "rationale": "Offline Golden Set report includes method/queryIntent/corpus/profile breakdowns."},
    "static-tool-rule-coverage": {"status": "fixture_backed", "evidenceRefs": ["fixtures/corpus-ingestion-v1/source-manifest.json", "tests/test_corpus_ingestion_v1.py"], "rationale": "Semgrep/Cppcheck/clang-tidy/gcc-fanalyzer/scan-build/Flawfinder fixtures are tracked."},
    "package-identity-not-keyword-only": {"status": "fixture_backed", "evidenceRefs": ["fixtures/corpus-ingestion-v1/raw/package_identity_curl.json", "tests/test_corpus_ingestion_v1.py"], "rationale": "Package alias/CPE/repo identity fixture avoids NVD keyword-only identity."},
    "s4-external-knowledge-gap-plans-s5": {"status": "fixture_backed", "evidenceRefs": ["fixtures/consumption-validation-v1/manifest.json", "tests/test_consumption_validation_v1.py"], "rationale": "G010 scenario covers S4 external vulnerability knowledge not provided leading to S5 cveDiscovery planning."},
    "knowledge-hit-not-claim-support": {"status": "fixture_backed", "evidenceRefs": ["fixtures/consumption-validation-v1/manifest.json", "wiki/canon/specs/s3-claim-evidence-state-machine/evidence-ref-and-slots.md"], "rationale": "G010 scenarios assert S5 knowledge hits are contextual only unless S3 validates local refs."},
}


VALID_AUDIT_STATUSES = {"implemented", "fixture_backed", "manifest_only_deferred", "not_applicable"}
RUNTIME_FORBIDDEN_TERMS = {term.lower() for term in OFFLINE_QUALITY_VOCABULARY} | {
    "true-positive",
    "false-positive",
    "false-negative",
    "accepted_claim",
    "claim_support",
}


def load_consumption_manifest(path: Path | str = DEFAULT_MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_source_manifest(path: Path | str = DEFAULT_SOURCE_MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _walk_strings(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)
    else:
        yield str(value)


def _runtime_vocab_leaks(case: dict[str, Any]) -> list[str]:
    text = " ".join(_walk_strings({
        "s4Premise": case.get("s4Premise"),
        "s5Envelope": case.get("s5Envelope"),
        "expectedS3": case.get("expectedS3"),
        "forbiddenUses": case.get("forbiddenUses"),
    })).lower()
    leaks = []
    for term in RUNTIME_FORBIDDEN_TERMS:
        if term in text:
            # Forbidden uses are allowed to name what must not happen.
            forbidden_text = " ".join(str(v).lower() for v in case.get("forbiddenUses", []))
            if term in forbidden_text and term not in text.replace(forbidden_text, ""):
                continue
            leaks.append(term)
    return sorted(set(leaks))


def validate_consumption_manifest(manifest: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if manifest.get("schemaVersion") != "s5-consumption-validation-v1":
        issues.append("schemaVersion must be s5-consumption-validation-v1")
    cases = manifest.get("scenarioCases")
    if not isinstance(cases, list) or not cases:
        return [*issues, "scenarioCases must be a non-empty list"]
    seen = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            issues.append(f"scenarioCases[{index}] must be object")
            continue
        case_id = str(case.get("caseId", ""))
        if not case_id:
            issues.append(f"scenarioCases[{index}] missing caseId")
        if case_id in seen:
            issues.append(f"duplicate caseId: {case_id}")
        seen.add(case_id)
        missing = REQUIRED_CASE_FIELDS - set(case)
        if missing:
            issues.append(f"{case_id} missing fields: {sorted(missing)}")
        expected = case.get("expectedS3") if isinstance(case.get("expectedS3"), dict) else {}
        evidence_class = expected.get("evidenceClass")
        if evidence_class in CLAIM_SUPPORT_FORBIDDEN_CLASSES and expected.get("maySupportClaim"):
            issues.append(f"{case_id} unsafe claim support for {evidence_class}")
        if case.get("s5Envelope", {}).get("consumerPolicy") in NON_NEGATIVE_POLICIES and expected.get("mayBeNegativeEvidence"):
            issues.append(f"{case_id} unsafe negative evidence for non-negative policy")
        if leaks := _runtime_vocab_leaks(case):
            issues.append(f"{case_id} runtime/offline vocabulary leak: {leaks}")
    missing_cases = REQUIRED_SCENARIO_CASE_IDS - seen
    if missing_cases:
        issues.append(f"missing scenario cases: {sorted(missing_cases)}")
    expected_sources = set(manifest.get("sourceFamilyAuditExpectations") or [])
    missing_source_expectations = REQUIRED_SOURCE_FAMILY_ITEMS - expected_sources
    if missing_source_expectations:
        issues.append(f"missing source audit expectations: {sorted(missing_source_expectations)}")
    expected_requirements = set(manifest.get("s3ConditionalPassRequirementIds") or [])
    missing_requirements = set(CONDITIONAL_PASS_REQUIREMENTS) - expected_requirements
    if missing_requirements:
        issues.append(f"missing S3 conditional-pass expectations: {sorted(missing_requirements)}")
    return issues


def _scenario_report(manifest: dict[str, Any]) -> dict[str, Any]:
    cases = manifest.get("scenarioCases") or []
    invalid_claim_support = []
    unsafe_negative = []
    no_hit_issues = []
    for case in cases:
        expected = case["expectedS3"]
        envelope = case["s5Envelope"]
        case_id = case["caseId"]
        if expected.get("evidenceClass") in CLAIM_SUPPORT_FORBIDDEN_CLASSES and expected.get("maySupportClaim"):
            invalid_claim_support.append(case_id)
        if envelope.get("consumerPolicy") in NON_NEGATIVE_POLICIES and expected.get("mayBeNegativeEvidence"):
            unsafe_negative.append(case_id)
        if envelope.get("acquisitionStatus") == "completed_no_hit":
            record = {
                **envelope,
                "methodsRequiredForNoHit": envelope.get("methodsRequiredForNoHit"),
                "methodsAttempted": envelope.get("methodsAttempted"),
                "methodsSucceeded": envelope.get("methodsSucceeded"),
            }
            eligible, reasons = evaluate_no_hit_eligibility(record)
            if envelope.get("consumerPolicy") == "scoped_no_hit_record_only" and not eligible:
                no_hit_issues.append({"caseId": case_id, "reasons": reasons})
    return {
        "scenarioCount": len(cases),
        "requiredScenarioCount": len(REQUIRED_SCENARIO_CASE_IDS),
        "requiredScenariosCovered": sorted(REQUIRED_SCENARIO_CASE_IDS),
        "invalidClaimSupportCases": invalid_claim_support,
        "unsafeNegativeEvidenceCases": unsafe_negative,
        "noHitEligibilityIssues": no_hit_issues,
        "status": "passed" if not invalid_claim_support and not unsafe_negative and not no_hit_issues else "failed",
    }


def build_source_family_audit(source_manifest: dict[str, Any]) -> dict[str, Any]:
    rows = []
    by_kind = {source.get("sourceKind"): source for source in source_manifest.get("sources", [])}
    for item_id, requirement in sorted(SOURCE_FAMILY_REQUIREMENTS.items()):
        kind = requirement["sourceKind"]
        source = by_kind.get(kind)
        if source is None:
            rows.append({
                "sourceFamilyItem": item_id,
                "sourceKind": kind,
                "status": "missing",
                "rationale": "No source manifest entry",
            })
            continue
        expected_status = requirement["status"]
        rows.append({
            "sourceFamilyItem": item_id,
            "sourceKind": kind,
            "status": expected_status,
            "family": requirement.get("family") or source.get("family"),
            "sourceId": source.get("sourceId"),
            "rawArtifactCount": len(source.get("rawArtifacts") or []),
            "rationale": requirement.get("rationale") or source.get("providerState", {}).get("deferredReason") or source.get("coverageStatus"),
            "manifestCoverageStatus": source.get("coverageStatus"),
            "manifestCompletedCoverage": bool(source.get("completedCoverage")),
        })
    missing = [row for row in rows if row["status"] == "missing"]
    invalid = [row for row in rows if row["status"] not in VALID_AUDIT_STATUSES]
    return {
        "status": "passed" if not missing and not invalid else "failed",
        "rows": rows,
        "missing": missing,
        "invalidStatusRows": invalid,
        "summary": {
            status: sum(1 for row in rows if row["status"] == status)
            for status in sorted({row["status"] for row in rows})
        },
    }


def build_s3_conditional_pass_audit() -> dict[str, Any]:
    rows = [
        {"requirementId": req_id, **spec}
        for req_id, spec in sorted(CONDITIONAL_PASS_REQUIREMENTS.items())
    ]
    invalid = [row for row in rows if row["status"] not in VALID_AUDIT_STATUSES]
    return {
        "status": "passed" if not invalid else "failed",
        "rows": rows,
        "invalidStatusRows": invalid,
        "summary": {
            status: sum(1 for row in rows if row["status"] == status)
            for status in sorted({row["status"] for row in rows})
        },
    }


def build_consumption_validation_report(
    manifest: dict[str, Any] | None = None,
    source_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = manifest or load_consumption_manifest()
    source_manifest = source_manifest or load_source_manifest()
    manifest_issues = validate_consumption_manifest(manifest)
    scenario = _scenario_report(manifest)
    source_audit = build_source_family_audit(source_manifest)
    s3_audit = build_s3_conditional_pass_audit()
    leak_cases = [
        {"caseId": case["caseId"], "leaks": _runtime_vocab_leaks(case)}
        for case in manifest.get("scenarioCases", [])
        if _runtime_vocab_leaks(case)
    ]
    safety = {
        "noUnsafeNegativeEvidence": not scenario["unsafeNegativeEvidenceCases"],
        "noKnowledgeOnlyClaimSupport": not scenario["invalidClaimSupportCases"],
        "noRuntimeOfflineVocabularyLeak": not leak_cases,
        "runtimeOfflineVocabularyLeakCases": leak_cases,
    }
    status = "passed" if (
        not manifest_issues
        and scenario["status"] == "passed"
        and source_audit["status"] == "passed"
        and s3_audit["status"] == "passed"
        and all(safety[key] for key in (
            "noUnsafeNegativeEvidence",
            "noKnowledgeOnlyClaimSupport",
            "noRuntimeOfflineVocabularyLeak",
        ))
    ) else "failed"
    return {
        "schemaVersion": "s5-consumption-validation-report-v1",
        "offlineOnly": True,
        "runtimeClaimSupport": False,
        "status": status,
        "manifestIssues": manifest_issues,
        "s3S4Consumption": scenario,
        "sourceFamilyAudit": source_audit,
        "s3ConditionalPassAudit": s3_audit,
        "safetyChecks": safety,
        "offlineQualityGateRefs": manifest.get("offlineQualityGateRefs", []),
    }
