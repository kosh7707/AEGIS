from __future__ import annotations

import json
from copy import deepcopy

from app.ingestion.corpus_ingestion import ingest_fixture_corpus
from app.judge.models import JudgeQueryRequest
from app.judge.service import build_judge_answer, validate_judge_answer
from app.ledger.repository import SQLiteLedgerRepository
from app.source_kg.models import SourceCodeKgIngestRequest
from app.source_kg.service import ingest_source_kg


def _repo(tmp_path):
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    ingest_fixture_corpus(repo)
    return repo


def _source_payload():
    return {
        "schemaVersion": "s5-source-code-kg-ingest-request-v1",
        "repositorySnapshot": {
            "repositoryUrl": "https://github.com/aegis-fixtures/curl-vuln.git",
            "repositoryId": "fixture-curl-vuln",
            "commitHash": "curl-commit-800",
            "treeHash": "curl-tree-800",
            "submoduleHashes": {},
        },
        "sourceArtifacts": [
            {
                "artifactUri": "file:///fixtures/curl-vuln.tar.zst",
                "mediaType": "application/zstd",
                "checksumSha256": "sha256:" + "e" * 64,
                "storageMode": "content_addressed",
            }
        ],
        "buildContext": {
            "projectId": "re100",
            "targetId": "re100:http-client",
            "buildTarget": "http-client",
            "toolchain": {"compiler": "gcc", "targetArch": "armv7"},
            "dependencyGraph": {"libraries": [{"name": "curl", "version": "8.0.0"}]},
            "buildMetadata": {"linkedLibraries": ["curl"]},
        },
        "analysisArtifactSet": {
            "analyzerName": "s4-static-fixture",
            "analyzerVersion": "1.0",
            "analysisConfig": {"enabled": ["callgraph"]},
            "artifactHashes": {"callgraph": "sha256:curl-callgraph"},
        },
        "evidenceSnippets": [
            {
                "evidenceSnippetId": "snippet-curl-call",
                "filePath": "src/http_client.cpp",
                "lineStart": 42,
                "lineEnd": 44,
                "language": "cpp",
                "snippetText": "curl_easy_perform(handle);",
            }
        ],
        "graphNodes": [
            {
                "nodeKind": "function",
                "stableId": "func:perform_request",
                "displayName": "perform_request",
                "filePath": "src/http_client.cpp",
                "lineStart": 40,
                "lineEnd": 50,
                "metadata": {"component": "curl", "reachable": True},
                "evidenceSnippetId": "snippet-curl-call",
            }
        ],
        "graphEdges": [],
        "richIrArtifacts": [
            {
                "artifactKind": "symbol_table",
                "mediaType": "application/json",
                "uri": "file:///fixtures/curl-symbols.json",
                "checksumSha256": "sha256:" + "f" * 64,
                "payload": {"symbols": ["curl_easy_perform"]},
            }
        ],
    }


def _ingest_source_context(repo):
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(_source_payload())).model_dump(by_alias=True)
    return {
        "repositorySnapshotId": result["repositorySnapshotId"],
        "buildContextId": result["buildContextId"],
        "analysisArtifactSetId": result["analysisArtifactSetId"],
        "graphNodeIds": result["ids"]["sourceGraphNodeIds"],
        "evidenceSnippetIds": result["ids"]["evidenceSnippetIds"],
        "richIrArtifactIds": result["ids"]["richIrArtifactIds"],
    }


def _judge_request(component, source_context, controls=None):
    return JudgeQueryRequest.model_validate(
        {
            "schemaVersion": "s5-judge-query-v1",
            "question": "Is this component affected in the current build target?",
            "component": component,
            "sourceContext": source_context,
            "controls": controls or {},
        }
    )


def _set_nested_value(packet, path, value):
    cursor = packet
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value


def test_judge_answer_separates_verdict_status_and_uses_source_kg_context(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    assert answer["schemaVersion"] == "s5-judge-answer-v1"
    assert answer["verdictAuthority"] == "s5_evidence_grounded_knowledge_verdict_not_s3_final_security_verdict"
    assert answer["verdict"] == "affected"
    assert answer["status"] == "complete"
    assert answer["qualityGate"]["gate"] == "accepted"
    assert answer["qualityGate"]["scorePolicy"]["phase"] == "serving"
    assert answer["qualityGate"]["scorePolicy"]["appliedProfile"] == "balanced"
    assert answer["qualityGate"]["scorePolicy"]["requestedProfile"] is None
    assert answer["qualityGate"]["scorePolicy"]["policyHash"].startswith("sha256:")
    assert answer["qualityGate"]["scorePolicy"]["failedThresholds"] == []
    assert "overallAnswerability" in answer["scoreVector"]
    assert "s5_final_security_verdict" in answer["forbiddenInferences"]
    assert "complete_project_safety" in answer["forbiddenInferences"]
    assert answer["queryContext"]["sourceContext"]["analysisArtifactSetId"] == source_context["analysisArtifactSetId"]
    assert answer["evidence"]["sourceCodeKg"]["resolved"] is True
    assert answer["evidence"]["sourceCodeKg"]["repositorySnapshot"]["commitHash"] == "curl-commit-800"
    assert answer["evidence"]["sourceCodeKg"]["graphNodes"][0]["stableId"] == "func:perform_request"
    assert answer["evidence"]["sourceCodeKg"]["evidenceSnippets"][0]["evidenceSnippetId"] == "snippet-curl-call"
    assert answer["evidence"]["sourceCodeKg"]["richIrArtifacts"][0]["artifactKind"] == "symbol_table"
    assert answer["reasoningPath"][0]["step"] == "resolve_source_code_kg_context"
    assert answer["reasoningPath"][0]["status"] == "resolved"
    assert validate_judge_answer(answer) == []


def test_judge_validator_tolerates_malformed_evidence_list_entries(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    malformed_cases = []

    bad_candidate = deepcopy(answer)
    bad_candidate["evidence"]["threatRetrieval"]["candidateEvidence"] = ["bad"]
    malformed_cases.append(bad_candidate)

    bad_equivalent = deepcopy(answer)
    bad_equivalent["evidence"]["threatRetrieval"]["candidateEvidence"][0]["equivalentAdvisories"] = ["bad"]
    malformed_cases.append(bad_equivalent)

    bad_risk_signal = deepcopy(answer)
    bad_risk_signal["evidence"]["threatRetrieval"]["riskSignals"] = ["bad"]
    malformed_cases.append(bad_risk_signal)

    bad_preview = deepcopy(answer)
    bad_preview["evidence"]["threatRetrieval"]["retrievalTrace"]["candidatePoolPreview"] = ["bad"]
    malformed_cases.append(bad_preview)

    bad_rich_ir = deepcopy(answer)
    bad_rich_ir["evidence"]["sourceCodeKg"]["richIrArtifacts"] = ["bad"]
    malformed_cases.append(bad_rich_ir)

    bad_snippet = deepcopy(answer)
    bad_snippet["evidence"]["sourceCodeKg"]["evidenceSnippets"] = ["bad"]
    malformed_cases.append(bad_snippet)

    for malformed in malformed_cases:
        assert isinstance(validate_judge_answer(malformed), list)


def test_judge_validator_tolerates_malformed_core_answer_containers(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    answer = build_judge_answer(
        repo,
        _judge_request(
            {"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"},
            source_context,
            controls={"exclude": ["CVE-2026-0001"]},
        ),
    )

    malformed_cases = []

    bad_forbidden = deepcopy(answer)
    bad_forbidden["forbiddenInferences"] = 123
    malformed_cases.append(bad_forbidden)

    bad_context_resolution = deepcopy(answer)
    bad_context_resolution["evidence"]["sourceCodeKg"]["contextResolution"] = ["bad"]
    malformed_cases.append(bad_context_resolution)

    bad_source_artifacts = deepcopy(answer)
    bad_source_artifacts["evidence"]["sourceCodeKg"]["sourceArtifacts"] = 123
    malformed_cases.append(bad_source_artifacts)

    bad_graph_nodes = deepcopy(answer)
    bad_graph_nodes["evidence"]["sourceCodeKg"]["graphNodes"] = 123
    malformed_cases.append(bad_graph_nodes)

    bad_suppressed_affectedness = deepcopy(answer)
    bad_suppressed_affectedness["evidence"]["suppressedAffectedness"] = 123
    malformed_cases.append(bad_suppressed_affectedness)

    bad_accepted_exclude = deepcopy(answer)
    bad_accepted_exclude["appliedControls"]["accepted"]["exclude"] = 123
    malformed_cases.append(bad_accepted_exclude)

    for malformed in malformed_cases:
        assert isinstance(validate_judge_answer(malformed), list)


def test_judge_validator_tolerates_broad_malformed_packet_containers(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    answer = build_judge_answer(
        repo,
        _judge_request(
            {"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"},
            source_context,
            controls={"exclude": ["CVE-2026-0001"]},
        ),
    )

    mutation_paths = [
        ("canonicalQuery",),
        ("canonicalQuery", "normalized"),
        ("canonicalQuery", "controlSummary"),
        ("cacheTrace",),
        ("fallbackTrace",),
        ("servingLedger",),
        ("qualityGate",),
        ("qualityGate", "diagnostics"),
        ("qualityGate", "scorePolicy"),
        ("scoreVector",),
        ("forbiddenInferences",),
        ("reasoningPath",),
        ("controlEffects",),
        ("appliedControls",),
        ("appliedControls", "accepted"),
        ("appliedControls", "accepted", "exclude"),
        ("appliedControls", "rejected"),
        ("queryContext",),
        ("queryContext", "sourceContext"),
        ("uncertainty",),
        ("uncertainty", "requiredInputs"),
        ("uncertainty", "evidenceGaps"),
        ("uncertainty", "conflicts"),
        ("followUpAffordances",),
        ("evidence",),
        ("evidence", "affectedness"),
        ("evidence", "suppressedAffectedness"),
        ("evidence", "suppressedAffectedness", 0, "riskSignals"),
        ("evidence", "sourceCodeKg"),
        ("evidence", "sourceCodeKg", "repositorySnapshot"),
        ("evidence", "sourceCodeKg", "buildContext"),
        ("evidence", "sourceCodeKg", "analysisArtifactSet"),
        ("evidence", "sourceCodeKg", "contextResolution"),
        ("evidence", "sourceCodeKg", "sourceArtifacts"),
        ("evidence", "sourceCodeKg", "graphNodes"),
        ("evidence", "sourceCodeKg", "graphEdges"),
        ("evidence", "sourceCodeKg", "evidenceSnippets"),
        ("evidence", "sourceCodeKg", "richIrArtifacts"),
        ("evidence", "threatRetrieval"),
        ("evidence", "threatRetrieval", "candidateEvidence"),
        ("evidence", "threatRetrieval", "riskSignals"),
        ("evidence", "threatRetrieval", "suppressedCandidateEvidence"),
        ("evidence", "threatRetrieval", "weaknessSemantics"),
        ("evidence", "threatRetrieval", "attackSemantics"),
        ("evidence", "threatRetrieval", "retrievalTrace"),
    ]
    malformed_values = [123, "bad", ["bad"], {"bad": 1}, None]

    for path in mutation_paths:
        for value in malformed_values:
            malformed = deepcopy(answer)
            _set_nested_value(malformed, path, value)
            assert isinstance(validate_judge_answer(malformed), list)


def test_judge_validator_rejects_malformed_reasoning_path(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    missing_path = deepcopy(answer)
    missing_path.pop("reasoningPath")
    assert any(issue["code"] == "REASONING_PATH_MISSING" for issue in validate_judge_answer(missing_path))

    missing_status = deepcopy(answer)
    missing_status["reasoningPath"][0].pop("status")
    assert any(issue["code"] == "REASONING_PATH_FIELD_MISSING" for issue in validate_judge_answer(missing_status))

    unknown_step = deepcopy(answer)
    unknown_step["reasoningPath"][0]["step"] = "derive_s3_final_security_verdict"
    assert any(issue["code"] == "REASONING_PATH_STEP_UNKNOWN" for issue in validate_judge_answer(unknown_step))

    non_list_path = deepcopy(answer)
    non_list_path["reasoningPath"] = {"step": "resolve_source_code_kg_context", "status": "resolved"}
    assert any(issue["code"] == "REASONING_PATH_MISSING" for issue in validate_judge_answer(non_list_path))

    non_dict_entry = deepcopy(answer)
    non_dict_entry["reasoningPath"][0] = "resolve_source_code_kg_context"
    assert any(issue["code"] == "REASONING_PATH_ENTRY_INVALID" for issue in validate_judge_answer(non_dict_entry))

    missing_step = deepcopy(answer)
    missing_step["reasoningPath"][0].pop("step")
    assert any(issue["code"] == "REASONING_PATH_FIELD_MISSING" for issue in validate_judge_answer(missing_step))


def test_judge_validator_rejects_malformed_fallback_trace(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    non_list_trace = deepcopy(answer)
    non_list_trace["fallbackTrace"] = {"stage": "source_code_kg_context", "fallback": "unresolved_context", "silent": False}
    assert any(issue["code"] == "FALLBACK_TRACE_INVALID" for issue in validate_judge_answer(non_list_trace))

    non_dict_entry = deepcopy(answer)
    non_dict_entry["fallbackTrace"] = ["source_code_kg_context"]
    assert any(issue["code"] == "FALLBACK_TRACE_ENTRY_INVALID" for issue in validate_judge_answer(non_dict_entry))

    missing_field = deepcopy(answer)
    missing_field["fallbackTrace"] = [{"stage": "source_code_kg_context", "fallback": "unresolved_context"}]
    assert any(issue["code"] == "FALLBACK_TRACE_FIELD_MISSING" for issue in validate_judge_answer(missing_field))

    unknown_stage = deepcopy(answer)
    unknown_stage["fallbackTrace"] = [{"stage": "derive_security_truth", "fallback": "unresolved_context", "silent": False}]
    assert any(issue["code"] == "FALLBACK_TRACE_STAGE_UNKNOWN" for issue in validate_judge_answer(unknown_stage))

    unknown_fallback = deepcopy(answer)
    unknown_fallback["fallbackTrace"] = [{"stage": "source_code_kg_context", "fallback": "silent_clean_pass", "silent": False}]
    assert any(issue["code"] == "FALLBACK_TRACE_FALLBACK_UNKNOWN" for issue in validate_judge_answer(unknown_fallback))

    silent_fallback = deepcopy(answer)
    silent_fallback["fallbackTrace"] = [{"stage": "source_code_kg_context", "fallback": "unresolved_context", "silent": True}]
    assert any(issue["code"] == "FALLBACK_TRACE_SILENT" for issue in validate_judge_answer(silent_fallback))

    partial_without_diagnostics = deepcopy(answer)
    partial_without_diagnostics["fallbackTrace"] = [
        {"stage": "source_code_kg_context", "fallback": "partial_context_resolution", "silent": False}
    ]
    assert any(
        issue["code"] == "FALLBACK_TRACE_DIAGNOSTICS_MISSING"
        for issue in validate_judge_answer(partial_without_diagnostics)
    )

    partial_with_empty_diagnostics = deepcopy(answer)
    partial_with_empty_diagnostics["fallbackTrace"] = [
        {"stage": "source_code_kg_context", "fallback": "partial_context_resolution", "silent": False, "diagnostics": []}
    ]
    assert any(
        issue["code"] == "FALLBACK_TRACE_DIAGNOSTICS_MISSING"
        for issue in validate_judge_answer(partial_with_empty_diagnostics)
    )

    rejected_without_controls = deepcopy(answer)
    rejected_without_controls["fallbackTrace"] = [
        {"stage": "control_validation", "fallback": "unsupported_controls_rejected", "silent": False}
    ]
    assert any(
        issue["code"] == "FALLBACK_TRACE_REJECTED_CONTROLS_MISSING"
        for issue in validate_judge_answer(rejected_without_controls)
    )

    rejected_with_empty_controls = deepcopy(answer)
    rejected_with_empty_controls["fallbackTrace"] = [
        {"stage": "control_validation", "fallback": "unsupported_controls_rejected", "silent": False, "rejected": []}
    ]
    assert any(
        issue["code"] == "FALLBACK_TRACE_REJECTED_CONTROLS_MISSING"
        for issue in validate_judge_answer(rejected_with_empty_controls)
    )


def test_judge_source_kg_evidence_redacts_credential_bearing_urls(tmp_path):
    repo = _repo(tmp_path)
    payload = _source_payload()
    payload["repositorySnapshot"]["repositoryUrl"] = (
        "https://repo_user:repo_password@git.example.com/curl.git?access_token=repo-token&ref=main"
    )
    payload["richIrArtifacts"][0]["uri"] = (
        "https://artifact_user:artifact_password@artifacts.example.com/curl-symbols.json?api_key=artifact-secret&download=1"
    )
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)
    source_context = {
        "repositorySnapshotId": result["repositorySnapshotId"],
        "buildContextId": result["buildContextId"],
        "analysisArtifactSetId": result["analysisArtifactSetId"],
        "graphNodeIds": result["ids"]["sourceGraphNodeIds"],
        "evidenceSnippetIds": result["ids"]["evidenceSnippetIds"],
        "richIrArtifactIds": result["ids"]["richIrArtifactIds"],
    }

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    source_kg = answer["evidence"]["sourceCodeKg"]
    assert source_kg["repositorySnapshot"]["repositoryUrl"] == (
        "https://***:***@git.example.com/curl.git?access_token=***&ref=main"
    )
    assert source_kg["richIrArtifacts"][0]["uri"] == (
        "https://***:***@artifacts.example.com/curl-symbols.json?api_key=***&download=1"
    )
    answer_text = str(answer)
    for secret in ["repo_user", "repo_password", "repo-token", "artifact_user", "artifact_password", "artifact-secret"]:
        assert secret not in answer_text
    assert validate_judge_answer(answer) == []


def test_judge_caveats_inconsistent_source_kg_context_without_silent_clean_accept(tmp_path):
    repo = _repo(tmp_path)
    first = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(_source_payload())).model_dump(by_alias=True)
    changed = _source_payload()
    changed["repositorySnapshot"]["commitHash"] = "curl-commit-801"
    changed["repositorySnapshot"]["treeHash"] = "curl-tree-801"
    changed["evidenceSnippets"][0]["evidenceSnippetId"] = "snippet-curl-call-801"
    changed["graphNodes"][0]["evidenceSnippetId"] = "snippet-curl-call-801"
    second = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(changed)).model_dump(by_alias=True)
    source_context = {
        "repositorySnapshotId": first["repositorySnapshotId"],
        "analysisArtifactSetId": second["analysisArtifactSetId"],
        "graphNodeIds": second["ids"]["sourceGraphNodeIds"],
    }

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    assert answer["verdict"] == "affected"
    assert answer["status"] == "degraded_quality"
    assert answer["qualityGate"]["gate"] == "accepted_with_caveats"
    assert any(item["code"] == "SOURCE_KG_CONTEXT_INCONSISTENT" for item in answer["qualityGate"]["diagnostics"])
    assert "Source KG context" in answer["uncertainty"]["reason"]
    assert "source code kg context" in answer["uncertainty"]["evidenceGaps"]
    assert answer["uncertainty"]["requiredInputs"] == ["complete_or_consistent_source_code_kg_context"]
    assert any(item["requestKind"] == "source_context_enrichment" for item in answer["followUpAffordances"])
    assert any(item["fallback"] == "partial_context_resolution" and item["silent"] is False for item in answer["fallbackTrace"])
    assert answer["evidence"]["sourceCodeKg"]["contextResolution"]["complete"] is False
    assert validate_judge_answer(answer) == []


def test_judge_redacts_out_of_lineage_source_kg_explicit_rows(tmp_path):
    repo = _repo(tmp_path)
    first = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(_source_payload())).model_dump(by_alias=True)
    changed = _source_payload()
    changed["repositorySnapshot"]["commitHash"] = "curl-commit-801"
    changed["repositorySnapshot"]["treeHash"] = "curl-tree-801"
    changed["evidenceSnippets"][0]["evidenceSnippetId"] = "snippet-curl-call-801"
    changed["graphNodes"][0]["evidenceSnippetId"] = "snippet-curl-call-801"
    changed["richIrArtifacts"][0]["richIrArtifactId"] = "rich-ir-curl-801"
    second = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(changed)).model_dump(by_alias=True)
    source_context = {
        "repositorySnapshotId": first["repositorySnapshotId"],
        "buildContextId": first["buildContextId"],
        "analysisArtifactSetId": first["analysisArtifactSetId"],
        "graphNodeIds": second["ids"]["sourceGraphNodeIds"],
        "evidenceSnippetIds": second["ids"]["evidenceSnippetIds"],
        "richIrArtifactIds": second["ids"]["richIrArtifactIds"],
    }

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    source_kg = answer["evidence"]["sourceCodeKg"]
    diagnostics = source_kg["contextResolution"]["diagnostics"]
    assert answer["verdict"] == "affected"
    assert answer["status"] == "degraded_quality"
    assert source_kg["graphNodes"] == []
    assert source_kg["evidenceSnippets"] == []
    assert source_kg["richIrArtifacts"] == []
    assert {item["field"] for item in diagnostics if item["code"] == "SOURCE_KG_CONTEXT_INCONSISTENT"} >= {
        "graphNodeIds",
        "evidenceSnippetIds",
        "richIrArtifactIds",
    }
    assert source_kg["contextResolution"]["graphNodes"]["missingIds"] == second["ids"]["sourceGraphNodeIds"]
    assert source_kg["contextResolution"]["evidenceSnippets"]["missingIds"] == second["ids"]["evidenceSnippetIds"]
    assert source_kg["contextResolution"]["richIrArtifacts"]["missingIds"] == second["ids"]["richIrArtifactIds"]
    assert validate_judge_answer(answer) == []


def test_judge_redacts_explicit_source_kg_rows_when_requested_container_is_missing(tmp_path):
    repo = _repo(tmp_path)
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(_source_payload())).model_dump(by_alias=True)
    source_context = {
        "repositorySnapshotId": "missing-repository",
        "analysisArtifactSetId": "missing-analysis",
        "graphNodeIds": result["ids"]["sourceGraphNodeIds"],
        "evidenceSnippetIds": result["ids"]["evidenceSnippetIds"],
        "richIrArtifactIds": result["ids"]["richIrArtifactIds"],
    }

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    source_kg = answer["evidence"]["sourceCodeKg"]
    assert answer["verdict"] == "affected"
    assert answer["status"] == "degraded_quality"
    assert source_kg["graphNodes"] == []
    assert source_kg["evidenceSnippets"] == []
    assert source_kg["richIrArtifacts"] == []
    assert source_kg["contextResolution"]["graphNodes"]["missingIds"] == result["ids"]["sourceGraphNodeIds"]
    assert source_kg["contextResolution"]["evidenceSnippets"]["missingIds"] == result["ids"]["evidenceSnippetIds"]
    assert source_kg["contextResolution"]["richIrArtifacts"]["missingIds"] == result["ids"]["richIrArtifactIds"]
    assert validate_judge_answer(answer) == []


def test_judge_source_kg_context_truncates_large_rich_ir_payloads(tmp_path):
    repo = _repo(tmp_path)
    payload = _source_payload()
    payload["richIrArtifacts"][0]["richIrArtifactId"] = "rich-ir-large"
    payload["richIrArtifacts"][0]["payload"] = {"largeIr": "x" * 5000}
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)
    source_context = {
        "repositorySnapshotId": result["repositorySnapshotId"],
        "buildContextId": result["buildContextId"],
        "analysisArtifactSetId": result["analysisArtifactSetId"],
        "richIrArtifactIds": result["ids"]["richIrArtifactIds"],
    }

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    rich_ir = answer["evidence"]["sourceCodeKg"]["richIrArtifacts"][0]
    assert rich_ir["richIrArtifactId"] == "rich-ir-large"
    assert rich_ir["payload"] is None
    assert rich_ir["payloadTruncated"] is True
    assert rich_ir["payloadRedacted"] is True
    assert rich_ir["payloadByteLength"] > rich_ir["payloadMaxInlineBytes"]
    assert "x" * 100 not in str(answer)
    assert answer["status"] == "degraded_quality"
    assert answer["qualityGate"]["gate"] == "accepted_with_caveats"
    assert any(
        diagnostic["code"] == "SOURCE_KG_CONTEXT_REDACTED"
        for diagnostic in answer["qualityGate"]["diagnostics"]
    )
    assert any(
        item["stage"] == "source_code_kg_context"
        and item["silent"] is False
        and item["fallback"] == "partial_context_resolution"
        for item in answer["fallbackTrace"]
    )
    assert validate_judge_answer(answer) == []


def test_judge_source_kg_context_truncates_large_evidence_snippet_text(tmp_path):
    repo = _repo(tmp_path)
    payload = _source_payload()
    payload["evidenceSnippets"][0]["snippetText"] = "void f() {\n" + ("x" * 5000) + "\nsecret_tail();\n}"
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)
    source_context = {
        "repositorySnapshotId": result["repositorySnapshotId"],
        "buildContextId": result["buildContextId"],
        "analysisArtifactSetId": result["analysisArtifactSetId"],
        "evidenceSnippetIds": result["ids"]["evidenceSnippetIds"],
    }

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    snippet = answer["evidence"]["sourceCodeKg"]["evidenceSnippets"][0]
    assert snippet["evidenceSnippetId"] == result["ids"]["evidenceSnippetIds"][0]
    assert snippet["snippetTextTruncated"] is True
    assert snippet["snippetTextByteLength"] > snippet["snippetTextMaxInlineBytes"]
    assert len(snippet["snippetText"].encode("utf-8")) <= snippet["snippetTextMaxInlineBytes"]
    assert "secret_tail" not in str(answer)
    assert answer["status"] == "degraded_quality"
    assert answer["qualityGate"]["gate"] == "accepted_with_caveats"
    assert any(
        diagnostic["code"] == "SOURCE_KG_CONTEXT_TRUNCATED"
        for diagnostic in answer["qualityGate"]["diagnostics"]
    )
    assert any(
        item["stage"] == "source_code_kg_context"
        and item["silent"] is False
        and item["fallback"] == "partial_context_resolution"
        for item in answer["fallbackTrace"]
    )
    assert validate_judge_answer(answer) == []


def test_judge_source_kg_context_redacts_large_nested_metadata_projection(tmp_path):
    repo = _repo(tmp_path)
    payload = _source_payload()
    secret = "secret-judge-nested-" + ("x" * 5000)
    payload["graphNodes"][0]["metadata"] = {"large": secret}
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)
    source_context = {
        "repositorySnapshotId": result["repositorySnapshotId"],
        "buildContextId": result["buildContextId"],
        "analysisArtifactSetId": result["analysisArtifactSetId"],
        "graphNodeIds": result["ids"]["sourceGraphNodeIds"],
    }

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    node = answer["evidence"]["sourceCodeKg"]["graphNodes"][0]
    assert node["metadata"] is None
    assert node["metadataTruncated"] is True
    assert node["metadataRedacted"] is True
    assert node["metadataByteLength"] > node["metadataMaxInlineBytes"]
    assert secret not in str(answer)
    assert answer["status"] == "degraded_quality"
    assert any(
        diagnostic["code"] == "SOURCE_KG_CONTEXT_REDACTED"
        for diagnostic in answer["qualityGate"]["diagnostics"]
    )
    assert any(
        item["stage"] == "source_code_kg_context"
        and item["silent"] is False
        and item["fallback"] == "partial_context_resolution"
        for item in answer["fallbackTrace"]
    )
    assert "complete_or_consistent_source_code_kg_context" in answer["uncertainty"]["requiredInputs"]
    assert validate_judge_answer(answer) == []


def test_judge_source_kg_context_includes_compile_commands_source_artifact(tmp_path):
    repo = _repo(tmp_path)
    payload = _source_payload()
    artifact_uri = "https://artifact_user:artifact_password@artifacts.example.com/compile_commands.json?token=artifact-secret"
    payload["sourceArtifacts"][0]["sourceRepositoryArtifactId"] = "artifact-judge-compile-commands"
    payload["sourceArtifacts"][0]["artifactUri"] = artifact_uri
    payload["sourceArtifacts"][0]["mediaType"] = "application/json"
    payload["buildContext"]["compileCommandsArtifactId"] = "artifact-judge-compile-commands"
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)
    source_context = {
        "repositorySnapshotId": result["repositorySnapshotId"],
        "buildContextId": result["buildContextId"],
        "analysisArtifactSetId": result["analysisArtifactSetId"],
    }

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    artifact = answer["evidence"]["sourceCodeKg"]["sourceArtifacts"][0]
    assert artifact["sourceRepositoryArtifactId"] == "artifact-judge-compile-commands"
    assert artifact["artifactUri"] == (
        "https://***:***@artifacts.example.com/compile_commands.json?token=***"
    )
    assert answer["evidence"]["sourceCodeKg"]["buildContext"]["compileCommandsArtifactId"] == (
        "artifact-judge-compile-commands"
    )
    assert answer["evidence"]["sourceCodeKg"]["contextResolution"]["sourceArtifacts"] == {
        "requestedIds": ["artifact-judge-compile-commands"],
        "resolvedIds": ["artifact-judge-compile-commands"],
        "missingIds": [],
    }
    assert "artifact_user" not in str(answer)
    assert "artifact_password" not in str(answer)
    assert "artifact-secret" not in str(answer)
    assert validate_judge_answer(answer) == []

    missing_artifact = deepcopy(answer)
    missing_artifact["evidence"]["sourceCodeKg"]["sourceArtifacts"] = []
    assert any(
        issue["code"] == "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID"
        and issue["buildContextId"] == result["buildContextId"]
        for issue in validate_judge_answer(missing_artifact)
    )

    missing_resolution = deepcopy(answer)
    missing_resolution["evidence"]["sourceCodeKg"]["contextResolution"].pop("sourceArtifacts")
    assert any(
        issue["code"] == "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID"
        and "source_artifact_resolution_missing" in issue["reasons"]
        for issue in validate_judge_answer(missing_resolution)
    )

    mismatched_resolution = deepcopy(answer)
    mismatched_resolution["evidence"]["sourceCodeKg"]["contextResolution"]["sourceArtifacts"]["resolvedIds"] = []
    assert any(
        issue["code"] == "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID"
        and "compile_commands_artifact_not_resolved" in issue["reasons"]
        for issue in validate_judge_answer(mismatched_resolution)
    )

    malformed_compile_artifact_id = deepcopy(answer)
    malformed_compile_artifact_id["evidence"]["sourceCodeKg"]["buildContext"]["compileCommandsArtifactId"] = {
        "not": "a-string"
    }
    assert any(
        issue["code"] == "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID"
        and "compile_commands_artifact_id_invalid" in issue["reasons"]
        for issue in validate_judge_answer(malformed_compile_artifact_id)
    )

    leaky_compile_artifact_id = deepcopy(answer)
    leaky_compile_artifact_id["evidence"]["sourceCodeKg"]["buildContext"]["compileCommandsArtifactId"] = (
        "https://compile_user:compile_password@ids.example/compile_commands.json?token=compile-secret"
    )
    compile_issues = validate_judge_answer(leaky_compile_artifact_id)
    assert any(
        issue["code"] == "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID"
        for issue in compile_issues
    )
    assert "compile_user" not in str(compile_issues)
    assert "compile_password" not in str(compile_issues)
    assert "compile-secret" not in str(compile_issues)

    leaky_build_context_id = deepcopy(answer)
    leaky_build_context_id["evidence"]["sourceCodeKg"]["buildContext"]["buildContextId"] = (
        "https://build_user:build_password@ids.example/build-context?token=build-secret"
    )
    leaky_build_context_id["evidence"]["sourceCodeKg"]["buildContext"]["compileCommandsArtifactId"] = {
        "not": "a-string"
    }
    build_context_issues = validate_judge_answer(leaky_build_context_id)
    assert any(
        issue["code"] == "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID"
        for issue in build_context_issues
    )
    assert "build_user" not in str(build_context_issues)
    assert "build_password" not in str(build_context_issues)
    assert "build-secret" not in str(build_context_issues)

    oversized_compile_artifact_id = deepcopy(answer)
    oversized_compile_artifact_id["evidence"]["sourceCodeKg"]["buildContext"]["compileCommandsArtifactId"] = (
        "artifact-" + "x" * 600
    )
    oversized_compile_issues = validate_judge_answer(oversized_compile_artifact_id)
    assert any(
        issue["code"] == "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID"
        for issue in oversized_compile_issues
    )
    assert "x" * 600 not in str(oversized_compile_issues)
    assert any(
        issue.get("compileCommandsArtifactId") == {"redacted": True, "type": "str", "length": 609}
        for issue in oversized_compile_issues
    )


def test_judge_source_kg_context_does_not_expose_unrequested_analysis_edges(tmp_path):
    repo = _repo(tmp_path)
    payload = _source_payload()
    payload["graphNodes"][0]["sourceGraphNodeId"] = "node-curl-call"
    payload["graphNodes"].extend(
        [
            {
                "sourceGraphNodeId": "node-unrelated-source",
                "nodeKind": "function",
                "stableId": "func:unrelated_source",
                "displayName": "unrelated_source",
                "filePath": "src/unrelated.cpp",
                "lineStart": 10,
                "lineEnd": 20,
                "metadata": {"component": "other"},
            },
            {
                "sourceGraphNodeId": "node-unrelated-target",
                "nodeKind": "function",
                "stableId": "func:unrelated_target",
                "displayName": "unrelated_target",
                "filePath": "src/unrelated.cpp",
                "lineStart": 30,
                "lineEnd": 40,
                "metadata": {"component": "other"},
            },
        ]
    )
    payload["graphEdges"] = [
        {
            "sourceGraphEdgeId": "edge-unrelated",
            "edgeKind": "calls",
            "sourceGraphNodeId": "node-unrelated-source",
            "targetGraphNodeId": "node-unrelated-target",
            "evidence": {"pathKind": "call"},
            "metadata": {"confidence": 1.0},
        }
    ]
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)
    source_context = {
        "repositorySnapshotId": result["repositorySnapshotId"],
        "buildContextId": result["buildContextId"],
        "analysisArtifactSetId": result["analysisArtifactSetId"],
        "graphNodeIds": ["node-curl-call"],
    }

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    source_kg = answer["evidence"]["sourceCodeKg"]
    assert [node["sourceGraphNodeId"] for node in source_kg["graphNodes"]] == ["node-curl-call"]
    assert source_kg["graphEdges"] == []
    assert validate_judge_answer(answer) == []


def test_judge_preserves_source_kg_explicit_collection_request_order(tmp_path):
    repo = _repo(tmp_path)
    payload = _source_payload()
    payload["evidenceSnippets"][0]["evidenceSnippetId"] = "snippet-zeta"
    payload["evidenceSnippets"].append(
        {
            "evidenceSnippetId": "snippet-alpha",
            "filePath": "src/alpha.cpp",
            "lineStart": 10,
            "lineEnd": 12,
            "language": "cpp",
            "snippetText": "alpha();",
        }
    )
    payload["graphNodes"][0]["sourceGraphNodeId"] = "node-zeta"
    payload["graphNodes"][0]["evidenceSnippetId"] = "snippet-zeta"
    payload["graphNodes"].append(
        {
            "sourceGraphNodeId": "node-alpha",
            "nodeKind": "function",
            "stableId": "func:alpha",
            "displayName": "alpha",
            "filePath": "src/alpha.cpp",
            "lineStart": 10,
            "lineEnd": 20,
            "metadata": {"component": "curl", "reachable": True},
            "evidenceSnippetId": "snippet-alpha",
        }
    )
    payload["richIrArtifacts"][0]["richIrArtifactId"] = "rich-zeta"
    payload["richIrArtifacts"].append(
        {
            "richIrArtifactId": "rich-alpha",
            "artifactKind": "callgraph",
            "mediaType": "application/json",
            "uri": "file:///fixtures/alpha-callgraph.json",
            "checksumSha256": "sha256:" + "1" * 64,
            "payload": {"symbols": ["alpha"]},
        }
    )
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)
    requested_nodes = ["node-zeta", "node-alpha"]
    requested_snippets = ["snippet-zeta", "snippet-alpha"]
    requested_rich_ir = ["rich-zeta", "rich-alpha"]
    source_context = {
        "repositorySnapshotId": result["repositorySnapshotId"],
        "buildContextId": result["buildContextId"],
        "analysisArtifactSetId": result["analysisArtifactSetId"],
        "graphNodeIds": requested_nodes,
        "evidenceSnippetIds": requested_snippets,
        "richIrArtifactIds": requested_rich_ir,
    }

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    source_kg = answer["evidence"]["sourceCodeKg"]
    resolution = source_kg["contextResolution"]
    assert [item["sourceGraphNodeId"] for item in source_kg["graphNodes"]] == requested_nodes
    assert [item["evidenceSnippetId"] for item in source_kg["evidenceSnippets"]] == requested_snippets
    assert [item["richIrArtifactId"] for item in source_kg["richIrArtifacts"]] == requested_rich_ir
    assert resolution["graphNodes"]["resolvedIds"] == requested_nodes
    assert resolution["evidenceSnippets"]["resolvedIds"] == requested_snippets
    assert resolution["richIrArtifacts"]["resolvedIds"] == requested_rich_ir
    assert validate_judge_answer(answer) == []


def test_judge_exposes_partial_source_kg_context_without_silent_drop(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    source_context["graphNodeIds"] = [source_context["graphNodeIds"][0], "missing-node"]

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    source_kg = answer["evidence"]["sourceCodeKg"]
    resolution = source_kg["contextResolution"]
    assert answer["verdict"] == "affected"
    assert answer["status"] == "degraded_quality"
    assert source_kg["resolved"] is True
    assert resolution["partial"] is True
    assert resolution["graphNodes"]["missingIds"] == ["missing-node"]
    assert any(item["fallback"] == "partial_context_resolution" and item["silent"] is False for item in answer["fallbackTrace"])
    assert any(item["code"] == "SOURCE_KG_CONTEXT_PARTIAL" for item in answer["qualityGate"]["diagnostics"])
    assert validate_judge_answer(answer) == []


def test_judge_degrades_status_when_requested_source_context_unresolved_despite_affectedness(tmp_path):
    repo = _repo(tmp_path)
    source_context = {"repositorySnapshotId": "missing", "buildContextId": "missing", "analysisArtifactSetId": "missing"}

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )

    assert answer["verdict"] == "affected"
    assert answer["status"] == "degraded_quality"
    assert answer["qualityGate"]["gate"] == "accepted_with_caveats"
    assert any(item["fallback"] == "unresolved_context" and item["silent"] is False for item in answer["fallbackTrace"])
    assert answer["uncertainty"]["requiredInputs"] == ["complete_or_consistent_source_code_kg_context"]
    assert any(item["requestKind"] == "source_context_enrichment" for item in answer["followUpAffordances"])
    assert validate_judge_answer(answer) == []


def test_judge_reports_patched_not_affected_without_turning_it_into_clean_pass(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.1.0", "purl": "pkg:generic/curl@8.1.0"}, source_context),
    )

    assert answer["verdict"] == "not_affected"
    assert answer["status"] == "complete"
    assert "s5_clean_pass" in answer["forbiddenInferences"]
    assert "s5_accepted_claim" in answer["forbiddenInferences"]
    assert validate_judge_answer(answer) == []


def test_grounded_unknown_for_missing_version_routes_followup_to_s4(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)

    answer = build_judge_answer(repo, _judge_request({"name": "curl", "purl": "pkg:generic/curl"}, source_context))

    assert answer["verdict"] == "unknown"
    assert answer["status"] == "requires_requery"
    assert answer["qualityGate"]["gate"] == "accepted_with_caveats"
    assert answer["qualityGate"]["scorePolicy"]["phase"] == "serving"
    assert answer["qualityGate"]["scorePolicy"]["failedThresholds"]
    assert "component.version" in answer["uncertainty"]["requiredInputs"]
    assert any(item["ownerLane"] == "S4" and item["requestKind"] == "library_version_lookup" for item in answer["followUpAffordances"])
    assert any(item["requestKind"] == "source_diff_or_vendored_patch_check" for item in answer["followUpAffordances"])
    assert validate_judge_answer(answer) == []


def test_grounded_unknown_with_partial_source_context_requires_source_context_enrichment(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    source_context["graphNodeIds"] = [source_context["graphNodeIds"][0], "missing-node"]

    answer = build_judge_answer(repo, _judge_request({"name": "curl", "purl": "pkg:generic/curl"}, source_context))

    assert answer["verdict"] == "unknown"
    assert answer["status"] == "requires_requery"
    assert "component.version" in answer["uncertainty"]["requiredInputs"]
    assert "complete_or_consistent_source_code_kg_context" in answer["uncertainty"]["requiredInputs"]
    assert any(item["fallback"] == "partial_context_resolution" and item["silent"] is False for item in answer["fallbackTrace"])
    assert any(item["requestKind"] == "library_version_lookup" for item in answer["followUpAffordances"])
    assert any(item["requestKind"] == "source_context_enrichment" for item in answer["followUpAffordances"])
    assert any(item["code"] == "SOURCE_KG_CONTEXT_PARTIAL" for item in answer["qualityGate"]["diagnostics"])
    assert validate_judge_answer(answer) == []

    malformed_followups = deepcopy(answer)
    malformed_followups["followUpAffordances"] = ["bad"]
    issues = validate_judge_answer(malformed_followups)
    assert any(issue["code"] == "FOLLOW_UP_AFFORDANCE_INVALID" for issue in issues)
    assert any(issue["code"] == "SOURCE_KG_CONTEXT_FOLLOWUP_MISSING" for issue in issues)

    malformed_required_inputs = deepcopy(answer)
    malformed_required_inputs["uncertainty"]["requiredInputs"] = 123
    issues = validate_judge_answer(malformed_required_inputs)
    assert any(issue["code"] == "UNCERTAINTY_FIELD_MISSING" for issue in issues)
    assert any(issue["code"] == "SOURCE_KG_CONTEXT_REQUIRED_INPUT_MISSING" for issue in issues)

    malformed_evidence_gaps = deepcopy(answer)
    malformed_evidence_gaps["uncertainty"]["evidenceGaps"] = 123
    issues = validate_judge_answer(malformed_evidence_gaps)
    assert any(issue["code"] == "UNCERTAINTY_FIELD_INVALID" for issue in issues)

    malformed_conflicts = deepcopy(answer)
    malformed_conflicts["uncertainty"]["conflicts"] = 123
    issues = validate_judge_answer(malformed_conflicts)
    assert any(issue["code"] == "UNCERTAINTY_FIELD_INVALID" for issue in issues)


def test_judge_exclude_control_prevents_excluded_cve_resurrection(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)

    answer = build_judge_answer(
        repo,
        _judge_request(
            {"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"},
            source_context,
            controls={"exclude": ["CVE-2026-0001"]},
        ),
    )

    assert answer["verdict"] == "unknown"
    assert answer["status"] == "requires_requery"
    assert answer["evidence"]["affectedness"] == []
    assert answer["evidence"]["suppressedAffectedness"]
    assert answer["controlEffects"][0]["control"] == "exclude"
    assert "CVE-2026-0001" in answer["controlEffects"][0]["suppressedExternalIds"]
    assert validate_judge_answer(answer) == []


def test_judge_validator_rejects_malformed_control_effects(tmp_path):
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    answer = build_judge_answer(
        repo,
        _judge_request(
            {"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"},
            source_context,
            controls={"exclude": ["CVE-2026-0001"]},
        ),
    )

    non_list_effects = deepcopy(answer)
    non_list_effects["controlEffects"] = {"control": "exclude"}
    assert any(issue["code"] == "CONTROL_EFFECTS_INVALID" for issue in validate_judge_answer(non_list_effects))

    non_dict_entry = deepcopy(answer)
    non_dict_entry["controlEffects"][0] = "exclude"
    assert any(issue["code"] == "CONTROL_EFFECT_ENTRY_INVALID" for issue in validate_judge_answer(non_dict_entry))

    missing_control = deepcopy(answer)
    missing_control["controlEffects"][0].pop("control")
    assert any(issue["code"] == "CONTROL_EFFECT_FIELD_MISSING" for issue in validate_judge_answer(missing_control))

    unknown_control = deepcopy(answer)
    unknown_control["controlEffects"][0]["control"] = "prefer"
    assert any(issue["code"] == "CONTROL_EFFECT_CONTROL_UNKNOWN" for issue in validate_judge_answer(unknown_control))

    missing_suppression_fields = deepcopy(answer)
    missing_suppression_fields["controlEffects"][0].pop("suppressedExternalIds")
    assert any(issue["code"] == "CONTROL_EFFECT_FIELD_MISSING" for issue in validate_judge_answer(missing_suppression_fields))

    non_list_suppressed_advisory_ids = deepcopy(answer)
    non_list_suppressed_advisory_ids["controlEffects"][0]["suppressedAdvisoryIds"] = 123
    non_list_advisory_issues = validate_judge_answer(non_list_suppressed_advisory_ids)
    assert any(issue["code"] == "CONTROL_EFFECT_FIELD_MISSING" for issue in non_list_advisory_issues)
    assert any(issue["code"] == "CONTROL_EFFECT_SUPPRESSED_AFFECTEDNESS_MISMATCH" for issue in non_list_advisory_issues)

    non_list_suppressed_external_ids = deepcopy(answer)
    non_list_suppressed_external_ids["controlEffects"][0]["suppressedExternalIds"] = 123
    non_list_external_issues = validate_judge_answer(non_list_suppressed_external_ids)
    assert any(issue["code"] == "CONTROL_EFFECT_FIELD_MISSING" for issue in non_list_external_issues)
    assert any(issue["code"] == "CONTROL_EFFECT_SUPPRESSED_AFFECTEDNESS_MISMATCH" for issue in non_list_external_issues)

    missing_effect_for_suppression = deepcopy(answer)
    missing_effect_for_suppression["controlEffects"] = []
    assert any(issue["code"] == "CONTROL_EFFECT_SUPPRESSION_TRACE_MISSING" for issue in validate_judge_answer(missing_effect_for_suppression))

    missing_top_level_effects = deepcopy(answer)
    missing_top_level_effects.pop("controlEffects")
    assert any(issue["code"] == "CONTROL_EFFECT_SUPPRESSION_TRACE_MISSING" for issue in validate_judge_answer(missing_top_level_effects))

    missing_suppressed_external_id = deepcopy(answer)
    missing_suppressed_external_id["controlEffects"][0]["suppressedExternalIds"] = []
    assert any(
        issue["code"] == "CONTROL_EFFECT_SUPPRESSED_AFFECTEDNESS_MISMATCH"
        for issue in validate_judge_answer(missing_suppressed_external_id)
    )

    extra_suppressed_advisory_id = deepcopy(answer)
    extra_suppressed_advisory_id["controlEffects"][0]["suppressedAdvisoryIds"].append("advisory:NVD_CVE:CVE-2999-9999")
    assert any(
        issue["code"] == "CONTROL_EFFECT_SUPPRESSED_AFFECTEDNESS_MISMATCH"
        for issue in validate_judge_answer(extra_suppressed_advisory_id)
    )

    missing_accepted_exclude = deepcopy(answer)
    missing_accepted_exclude["appliedControls"]["accepted"]["exclude"] = []
    assert any(
        issue["code"] == "CONTROL_EFFECT_ACCEPTED_CONTROL_MISMATCH"
        for issue in validate_judge_answer(missing_accepted_exclude)
    )

    unrelated_accepted_exclude = deepcopy(answer)
    unrelated_accepted_exclude["appliedControls"]["accepted"]["exclude"] = ["CVE-2999-9999"]
    assert any(
        issue["code"] == "CONTROL_EFFECT_ACCEPTED_CONTROL_MISMATCH"
        for issue in validate_judge_answer(unrelated_accepted_exclude)
    )

    risk_signal_only_accepted_exclude = deepcopy(answer)
    risk_signal_only_accepted_exclude["evidence"]["suppressedAffectedness"][0]["advisoryExternalId"] = (
        "GHSA-does-not-match-control"
    )
    risk_signal_only_accepted_exclude["controlEffects"][0]["suppressedExternalIds"] = sorted(
        {
            item["advisoryExternalId"]
            for item in risk_signal_only_accepted_exclude["evidence"]["suppressedAffectedness"]
        }
    )
    risk_signal_only_accepted_exclude["appliedControls"]["accepted"]["exclude"] = ["CVE-2026-0001"]
    risk_signal_only_issues = validate_judge_answer(risk_signal_only_accepted_exclude)
    assert not any(
        issue["code"] == "CONTROL_EFFECT_ACCEPTED_CONTROL_MISMATCH"
        for issue in risk_signal_only_issues
    )
    assert not any(
        issue["code"] == "CONTROL_EFFECT_SUPPRESSED_AFFECTEDNESS_MISMATCH"
        for issue in risk_signal_only_issues
    )

    malformed_risk_signal_entry = deepcopy(risk_signal_only_accepted_exclude)
    malformed_risk_signal_entry["evidence"]["suppressedAffectedness"][0]["riskSignals"] = ["bad"]
    assert any(
        issue["code"] == "CONTROL_EFFECT_ACCEPTED_CONTROL_MISMATCH"
        for issue in validate_judge_answer(malformed_risk_signal_entry)
    )

    malformed_risk_signal_payload = deepcopy(risk_signal_only_accepted_exclude)
    malformed_risk_signal_payload["evidence"]["suppressedAffectedness"][0]["riskSignals"][1:] = []
    malformed_risk_signal_payload["evidence"]["suppressedAffectedness"][0]["riskSignals"][0]["payload"] = ["bad"]
    assert any(
        issue["code"] == "CONTROL_EFFECT_ACCEPTED_CONTROL_MISMATCH"
        for issue in validate_judge_answer(malformed_risk_signal_payload)
    )

    suppressed_clean_pass = deepcopy(answer)
    suppressed_clean_pass["verdict"] = "not_affected"
    suppressed_clean_pass["status"] = "complete"
    assert any(issue["code"] == "CONTROL_EFFECT_SUPPRESSION_VERDICT_INVALID" for issue in validate_judge_answer(suppressed_clean_pass))


def test_judge_validator_rejects_lazy_unknown_and_source_context_ignored(tmp_path):
    lazy = {
        "schemaVersion": "s5-judge-answer-v1",
        "verdictAuthority": "s5_evidence_grounded_knowledge_verdict_not_s3_final_security_verdict",
        "verdict": "unknown",
        "status": "requires_requery",
        "forbiddenInferences": [
            "s5_final_security_verdict",
            "s5_clean_pass",
            "s5_accepted_claim",
            "s5_exploitability_judgment",
            "complete_project_safety",
        ],
        "uncertainty": {},
        "followUpAffordances": [],
        "queryContext": {},
        "evidence": {},
    }
    assert any(issue["code"] == "LAZY_UNKNOWN" for issue in validate_judge_answer(lazy))

    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    unknown_answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "purl": "pkg:generic/curl"}, source_context),
    )

    missing_uncertainty_field = deepcopy(unknown_answer)
    missing_uncertainty_field["uncertainty"].pop("requiredInputs")
    assert any(
        issue["code"] == "UNCERTAINTY_FIELD_MISSING"
        for issue in validate_judge_answer(missing_uncertainty_field)
    )

    malformed_cache_trace = deepcopy(unknown_answer)
    malformed_cache_trace["cacheTrace"] = ["bad"]
    assert any(
        issue["code"] == "JUDGE_ANSWER_FIELD_INVALID" and issue["field"] == "cacheTrace"
        for issue in validate_judge_answer(malformed_cache_trace)
    )
    empty_list_cache_trace = deepcopy(unknown_answer)
    empty_list_cache_trace["cacheTrace"] = []
    assert any(
        issue["code"] == "JUDGE_ANSWER_FIELD_INVALID" and issue["field"] == "cacheTrace"
        for issue in validate_judge_answer(empty_list_cache_trace)
    )
    empty_string_cache_trace = deepcopy(unknown_answer)
    empty_string_cache_trace["cacheTrace"] = ""
    assert any(
        issue["code"] == "JUDGE_ANSWER_FIELD_INVALID" and issue["field"] == "cacheTrace"
        for issue in validate_judge_answer(empty_string_cache_trace)
    )
    empty_dict_cache_trace = deepcopy(unknown_answer)
    empty_dict_cache_trace["cacheTrace"] = {}
    empty_dict_cache_trace_issues = validate_judge_answer(empty_dict_cache_trace)
    assert any(issue["code"] == "DECISION_CACHE_TRACE_SCOPE_MISSING" for issue in empty_dict_cache_trace_issues)
    assert any(issue["code"] == "DECISION_CACHE_TRACE_REVISION_MISSING" for issue in empty_dict_cache_trace_issues)

    malformed_query_context = deepcopy(unknown_answer)
    malformed_query_context["queryContext"] = ["bad"]
    assert any(
        issue["code"] == "JUDGE_ANSWER_FIELD_INVALID" and issue["field"] == "queryContext"
        for issue in validate_judge_answer(malformed_query_context)
    )

    malformed_evidence = deepcopy(unknown_answer)
    malformed_evidence["evidence"] = ["bad"]
    assert any(
        issue["code"] == "JUDGE_ANSWER_FIELD_INVALID" and issue["field"] == "evidence"
        for issue in validate_judge_answer(malformed_evidence)
    )

    malformed_source_kg = deepcopy(unknown_answer)
    malformed_source_kg["evidence"]["sourceCodeKg"] = ["bad"]
    assert any(
        issue["code"] == "JUDGE_ANSWER_FIELD_INVALID" and issue["field"] == "evidence.sourceCodeKg"
        for issue in validate_judge_answer(malformed_source_kg)
    )

    non_dict_uncertainty = deepcopy(unknown_answer)
    non_dict_uncertainty["uncertainty"] = ["bad"]
    assert any(
        issue["code"] == "UNCERTAINTY_FIELD_MISSING"
        for issue in validate_judge_answer(non_dict_uncertainty)
    )

    missing_uncertainty_reason = deepcopy(unknown_answer)
    missing_uncertainty_reason["uncertainty"]["reason"] = ""
    assert any(
        issue["code"] == "UNCERTAINTY_REASON_MISSING"
        for issue in validate_judge_answer(missing_uncertainty_reason)
    )

    invalid_evidence_gaps = deepcopy(unknown_answer)
    invalid_evidence_gaps["uncertainty"]["evidenceGaps"] = "component.version"
    assert any(
        issue["code"] == "UNCERTAINTY_FIELD_INVALID"
        for issue in validate_judge_answer(invalid_evidence_gaps)
    )

    invalid_conflicts = deepcopy(unknown_answer)
    invalid_conflicts["uncertainty"]["conflicts"] = ["conflicting"]
    assert any(
        issue["code"] == "UNCERTAINTY_FIELD_INVALID"
        for issue in validate_judge_answer(invalid_conflicts)
    )

    conflict_answer = deepcopy(unknown_answer)
    conflict_answer["qualityGate"]["gate"] = "rejected"
    conflict_answer["qualityGate"]["diagnostics"] = [{"conflictRecordId": "conflict:test"}]
    conflict_answer["uncertainty"]["conflicts"] = [
        {
            "conflictRecordId": "conflict:test",
            "consumerPolicy": "conflicting_evidence_not_negative_evidence",
            "negativeEvidenceAllowed": False,
            "forbiddenEffects": ["negative_evidence"],
            "conflictingValues": [{"value": "affected"}, {"value": "not_affected"}],
            "conflictingValueCount": 2,
            "conflictingValuesTruncated": False,
            "severity": "hard",
        }
    ]
    malformed_conflict_diagnostics = deepcopy(conflict_answer)
    malformed_conflict_diagnostics["qualityGate"]["diagnostics"] = ["bad"]
    assert any(
        issue["code"] == "CONFLICT_DIAGNOSTIC_SILENT"
        for issue in validate_judge_answer(malformed_conflict_diagnostics)
    )

    malformed_conflicting_values = deepcopy(conflict_answer)
    malformed_conflicting_values["uncertainty"]["conflicts"][0]["conflictingValues"] = 123
    assert any(
        issue["code"] == "CONFLICT_VALUES_MISSING"
        for issue in validate_judge_answer(malformed_conflicting_values)
    )

    malformed_forbidden_effects = deepcopy(conflict_answer)
    malformed_forbidden_effects["uncertainty"]["conflicts"][0]["forbiddenEffects"] = 123
    assert any(
        issue["code"] == "CONFLICT_FORBIDDEN_EFFECTS_INCOMPLETE"
        for issue in validate_judge_answer(malformed_forbidden_effects)
    )

    malformed_quality_gate = deepcopy(conflict_answer)
    malformed_quality_gate["qualityGate"] = ["bad"]
    assert any(
        issue["code"] == "CONFLICT_DIAGNOSTIC_SILENT"
        for issue in validate_judge_answer(malformed_quality_gate)
    )

    suppressed_answer = build_judge_answer(
        repo,
        _judge_request(
            {"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"},
            source_context,
            controls={"exclude": ["CVE-2026-0001"]},
        ),
    )
    malformed_applied_controls = deepcopy(suppressed_answer)
    malformed_applied_controls["appliedControls"] = ["bad"]
    assert any(
        issue["code"] == "JUDGE_ANSWER_FIELD_INVALID" and issue["field"] == "appliedControls"
        for issue in validate_judge_answer(malformed_applied_controls)
    )

    unknown_required_input = deepcopy(unknown_answer)
    unknown_required_input["uncertainty"]["requiredInputs"] = ["infer_component_safety"]
    assert any(
        issue["code"] == "UNCERTAINTY_REQUIRED_INPUT_UNKNOWN"
        for issue in validate_judge_answer(unknown_required_input)
    )

    malformed_required_input_entry = deepcopy(unknown_answer)
    malformed_required_input_entry["uncertainty"]["requiredInputs"] = [{"bad": 1}]
    assert any(
        issue["code"] == "UNCERTAINTY_REQUIRED_INPUT_UNKNOWN"
        for issue in validate_judge_answer(malformed_required_input_entry)
    )

    invalid_followup_entry = deepcopy(unknown_answer)
    invalid_followup_entry["followUpAffordances"][0] = "library_version_lookup"
    assert any(
        issue["code"] == "FOLLOW_UP_AFFORDANCE_INVALID"
        for issue in validate_judge_answer(invalid_followup_entry)
    )

    unknown_followup_kind = deepcopy(unknown_answer)
    unknown_followup_kind["followUpAffordances"][0]["requestKind"] = "derive_final_verdict"
    assert any(
        issue["code"] == "FOLLOW_UP_REQUEST_KIND_UNKNOWN"
        for issue in validate_judge_answer(unknown_followup_kind)
    )

    malformed_followup_kind = deepcopy(unknown_answer)
    malformed_followup_kind["followUpAffordances"][0]["requestKind"] = {"bad": 1}
    assert any(
        issue["code"] == "FOLLOW_UP_REQUEST_KIND_UNKNOWN"
        for issue in validate_judge_answer(malformed_followup_kind)
    )

    unknown_followup_owner = deepcopy(unknown_answer)
    unknown_followup_owner["followUpAffordances"][0]["ownerLane"] = "S5"
    assert any(
        issue["code"] == "FOLLOW_UP_OWNER_LANE_UNKNOWN"
        for issue in validate_judge_answer(unknown_followup_owner)
    )

    malformed_followup_owner = deepcopy(unknown_answer)
    malformed_followup_owner["followUpAffordances"][0]["ownerLane"] = {"bad": 1}
    assert any(
        issue["code"] == "FOLLOW_UP_OWNER_LANE_UNKNOWN"
        for issue in validate_judge_answer(malformed_followup_owner)
    )

    missing_followup_reason = deepcopy(unknown_answer)
    missing_followup_reason["followUpAffordances"][0].pop("reason")
    assert any(
        issue["code"] == "FOLLOW_UP_REASON_MISSING"
        for issue in validate_judge_answer(missing_followup_reason)
    )

    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )
    ignored = deepcopy(answer)
    ignored["evidence"]["sourceCodeKg"] = {"resolved": False}
    assert any(issue["code"] == "SOURCE_KG_CONTEXT_IGNORED" for issue in validate_judge_answer(ignored))

    missing_cache_scope = deepcopy(answer)
    missing_cache_scope["cacheTrace"].pop("cacheScopeHash")
    assert any(issue["code"] == "DECISION_CACHE_TRACE_SCOPE_MISSING" for issue in validate_judge_answer(missing_cache_scope))

    missing_cache_revision = deepcopy(answer)
    missing_cache_revision["cacheTrace"].pop("cacheRevisionHash")
    assert any(issue["code"] == "DECISION_CACHE_TRACE_REVISION_MISSING" for issue in validate_judge_answer(missing_cache_revision))

    leaked_rich_ir_payload = deepcopy(answer)
    rich_ir = leaked_rich_ir_payload["evidence"]["sourceCodeKg"]["richIrArtifacts"][0]
    rich_ir["richIrArtifactId"] = "https://ir_id_user:ir_id_password@ids.example/rich-ir?token=ir-id-secret"
    rich_ir["payload"] = {"largeIr": "x" * 5000}
    rich_ir["payloadByteLength"] = 5014
    rich_ir["payloadMaxInlineBytes"] = 2048
    rich_ir["payloadTruncated"] = True
    rich_ir["payloadRedacted"] = True
    rich_ir_issues = validate_judge_answer(leaked_rich_ir_payload)
    assert any(
        issue["code"] == "SOURCE_KG_RICH_IR_PAYLOAD_REDACTION_INVALID"
        for issue in rich_ir_issues
    )
    assert "ir_id_user" not in str(rich_ir_issues)
    assert "ir_id_password" not in str(rich_ir_issues)
    assert "ir-id-secret" not in str(rich_ir_issues)

    unredacted_rich_ir_metadata = deepcopy(answer)
    rich_ir = unredacted_rich_ir_metadata["evidence"]["sourceCodeKg"]["richIrArtifacts"][0]
    rich_ir["payload"] = None
    rich_ir["payloadByteLength"] = 5014
    rich_ir["payloadMaxInlineBytes"] = 2048
    rich_ir["payloadTruncated"] = True
    rich_ir["payloadRedacted"] = False
    assert any(
        issue["code"] == "SOURCE_KG_RICH_IR_PAYLOAD_REDACTION_INVALID"
        for issue in validate_judge_answer(unredacted_rich_ir_metadata)
    )

    leaked_large_snippet = deepcopy(answer)
    snippet = leaked_large_snippet["evidence"]["sourceCodeKg"]["evidenceSnippets"][0]
    snippet["evidenceSnippetId"] = "https://snippet_user:snippet_password@ids.example/snippet?token=snippet-secret"
    snippet["snippetText"] = "x" * 5000
    snippet["snippetTextByteLength"] = 5000
    snippet["snippetTextMaxInlineBytes"] = 2048
    snippet["snippetTextTruncated"] = True
    snippet_issues = validate_judge_answer(leaked_large_snippet)
    assert any(
        issue["code"] == "SOURCE_KG_SNIPPET_TEXT_TRUNCATION_INVALID"
        for issue in snippet_issues
    )
    assert "snippet_user" not in str(snippet_issues)
    assert "snippet_password" not in str(snippet_issues)
    assert "snippet-secret" not in str(snippet_issues)

    unredacted_repository_url = deepcopy(answer)
    unredacted_repository_url["evidence"]["sourceCodeKg"]["repositorySnapshot"]["repositoryUrl"] = (
        "https://repo_user:repo_password@git.example.com/curl.git?access_token=repo-token"
    )
    assert any(
        issue["code"] == "SOURCE_KG_URL_REDACTION_INVALID"
        and issue["field"] == "repositorySnapshot.repositoryUrl"
        for issue in validate_judge_answer(unredacted_repository_url)
    )

    unredacted_artifact_uri = deepcopy(answer)
    unredacted_artifact_uri["evidence"]["sourceCodeKg"]["sourceArtifacts"] = [
        {
            "sourceRepositoryArtifactId": "artifact-leaky",
            "artifactUri": "https://artifact_user:artifact_password@artifacts.example.com/source.tar?api_key=artifact-secret",
        }
    ]
    assert any(
        issue["code"] == "SOURCE_KG_URL_REDACTION_INVALID"
        and issue["field"] == "sourceArtifacts[].artifactUri"
        for issue in validate_judge_answer(unredacted_artifact_uri)
    )

    unredacted_rich_ir_uri = deepcopy(answer)
    unredacted_rich_ir_uri["evidence"]["sourceCodeKg"]["richIrArtifacts"][0]["uri"] = (
        "https://ir_user:ir_password@artifacts.example.com/ir.json?token=ir-secret"
    )
    assert any(
        issue["code"] == "SOURCE_KG_URL_REDACTION_INVALID"
        and issue["field"] == "richIrArtifacts[].uri"
        for issue in validate_judge_answer(unredacted_rich_ir_uri)
    )

    leaked_nested_metadata = deepcopy(answer)
    node = leaked_nested_metadata["evidence"]["sourceCodeKg"]["graphNodes"][0]
    node["sourceGraphNodeId"] = {
        "leaky": "https://nested_id_user:nested_id_password@ids.example/node?token=nested-id-secret"
    }
    node["metadata"] = {"large": "x" * 5000}
    node["metadataByteLength"] = 5012
    node["metadataMaxInlineBytes"] = 2048
    node["metadataTruncated"] = True
    node["metadataRedacted"] = True
    nested_issues = validate_judge_answer(leaked_nested_metadata)
    assert any(
        issue["code"] == "SOURCE_KG_NESTED_OBJECT_REDACTION_INVALID"
        for issue in nested_issues
    )
    assert "nested_id_user" not in str(nested_issues)
    assert "nested_id_password" not in str(nested_issues)
    assert "nested-id-secret" not in str(nested_issues)

    unredacted_nested_metadata = deepcopy(answer)
    node = unredacted_nested_metadata["evidence"]["sourceCodeKg"]["graphNodes"][0]
    node["metadata"] = None
    node["metadataByteLength"] = 5012
    node["metadataMaxInlineBytes"] = 2048
    node["metadataTruncated"] = True
    node["metadataRedacted"] = False
    assert any(
        issue["code"] == "SOURCE_KG_NESTED_OBJECT_REDACTION_INVALID"
        for issue in validate_judge_answer(unredacted_nested_metadata)
    )

    unredacted_nested_url_value = deepcopy(answer)
    node = unredacted_nested_url_value["evidence"]["sourceCodeKg"]["graphNodes"][0]
    node["metadata"] = {
        "debugUrl": "https://nested_user:nested_password@metadata.example.com/context.json?api_key=nested-secret"
    }
    node["metadataByteLength"] = 120
    node["metadataMaxInlineBytes"] = 2048
    node["metadataTruncated"] = False
    node["metadataRedacted"] = False
    assert any(
        issue["code"] == "SOURCE_KG_URL_REDACTION_INVALID"
        and issue["field"] == "graphNodes[].metadata"
        for issue in validate_judge_answer(unredacted_nested_url_value)
    )

    unredacted_nested_url_key = deepcopy(answer)
    node = unredacted_nested_url_key["evidence"]["sourceCodeKg"]["graphNodes"][0]
    node["metadata"] = {
        "https://key_user:key_password@metadata.example.com/key?token=key-secret": "value"
    }
    node["metadataByteLength"] = 100
    node["metadataMaxInlineBytes"] = 2048
    node["metadataTruncated"] = False
    node["metadataRedacted"] = False
    assert any(
        issue["code"] == "SOURCE_KG_URL_REDACTION_INVALID"
        and issue["field"] == "graphNodes[].metadata"
        for issue in validate_judge_answer(unredacted_nested_url_key)
    )

    nested_url_issue_with_leaky_id = deepcopy(answer)
    node = nested_url_issue_with_leaky_id["evidence"]["sourceCodeKg"]["graphNodes"][0]
    node["sourceGraphNodeId"] = "https://id_user:id_password@ids.example/graph-node?token=id-secret"
    node["metadata"] = {
        "debugUrl": "https://nested_user:nested_password@metadata.example.com/context.json?api_key=nested-secret"
    }
    node["metadataByteLength"] = 120
    node["metadataMaxInlineBytes"] = 2048
    node["metadataTruncated"] = False
    node["metadataRedacted"] = False
    nested_url_issue = next(
        issue
        for issue in validate_judge_answer(nested_url_issue_with_leaky_id)
        if issue["code"] == "SOURCE_KG_URL_REDACTION_INVALID"
        and issue["field"] == "graphNodes[].metadata"
    )
    nested_url_issue_json = json.dumps(nested_url_issue, sort_keys=True)
    assert "id_user" not in nested_url_issue_json
    assert "id_password" not in nested_url_issue_json
    assert "id-secret" not in nested_url_issue_json
    assert nested_url_issue["sourceGraphNodeId"] == "https://***:***@ids.example/graph-node?token=***"

    nested_url_issue_with_structured_leaky_id = deepcopy(answer)
    node = nested_url_issue_with_structured_leaky_id["evidence"]["sourceCodeKg"]["graphNodes"][0]
    node["sourceGraphNodeId"] = {
        "leaky": "https://id_user:id_password@ids.example/graph-node?token=id-secret"
    }
    node["metadata"] = {
        "debugUrl": "https://nested_user:nested_password@metadata.example.com/context.json?api_key=nested-secret"
    }
    node["metadataByteLength"] = 120
    node["metadataMaxInlineBytes"] = 2048
    node["metadataTruncated"] = False
    node["metadataRedacted"] = False
    structured_id_issue = next(
        issue
        for issue in validate_judge_answer(nested_url_issue_with_structured_leaky_id)
        if issue["code"] == "SOURCE_KG_URL_REDACTION_INVALID"
        and issue["field"] == "graphNodes[].metadata"
    )
    structured_id_issue_json = json.dumps(structured_id_issue, sort_keys=True)
    assert "id_user" not in structured_id_issue_json
    assert "id_password" not in structured_id_issue_json
    assert "id-secret" not in structured_id_issue_json
    assert structured_id_issue["sourceGraphNodeId"] == {
        "leaky": "https://***:***@ids.example/graph-node?token=***"
    }

    nested_url_issue_with_oversized_structured_id = deepcopy(answer)
    node = nested_url_issue_with_oversized_structured_id["evidence"]["sourceCodeKg"]["graphNodes"][0]
    node["sourceGraphNodeId"] = {"oversized": "node-" + "y" * 600}
    node["metadata"] = {
        "debugUrl": "https://nested_user:nested_password@metadata.example.com/context.json?api_key=nested-secret"
    }
    node["metadataByteLength"] = 120
    node["metadataMaxInlineBytes"] = 2048
    node["metadataTruncated"] = False
    node["metadataRedacted"] = False
    oversized_structured_id_issue = next(
        issue
        for issue in validate_judge_answer(nested_url_issue_with_oversized_structured_id)
        if issue["code"] == "SOURCE_KG_URL_REDACTION_INVALID"
        and issue["field"] == "graphNodes[].metadata"
    )
    assert "y" * 600 not in json.dumps(oversized_structured_id_issue, sort_keys=True)
    assert oversized_structured_id_issue["sourceGraphNodeId"] == {
        "oversized": {"redacted": True, "type": "str", "length": 605}
    }

    mismatched_repository_resolution = deepcopy(answer)
    mismatched_repository_resolution["evidence"]["sourceCodeKg"]["contextResolution"]["repositorySnapshot"]["resolvedId"] = (
        "wrong-repository-snapshot"
    )
    assert any(
        issue["code"] == "SOURCE_KG_CONTEXT_RESOLUTION_INVALID"
        and issue["field"] == "repositorySnapshot.resolvedId"
        for issue in validate_judge_answer(mismatched_repository_resolution)
    )

    mismatched_graph_node_resolution = deepcopy(answer)
    mismatched_graph_node_resolution["evidence"]["sourceCodeKg"]["contextResolution"]["graphNodes"]["resolvedIds"] = [
        "wrong-graph-node"
    ]
    assert any(
        issue["code"] == "SOURCE_KG_CONTEXT_RESOLUTION_INVALID"
        and issue["field"] == "graphNodes.resolvedIds"
        for issue in validate_judge_answer(mismatched_graph_node_resolution)
    )

    malformed_graph_missing_ids = deepcopy(answer)
    malformed_graph_missing_ids["evidence"]["sourceCodeKg"]["contextResolution"]["graphNodes"]["missingIds"] = {
        "not": "a-list"
    }
    assert any(
        issue["code"] == "SOURCE_KG_CONTEXT_RESOLUTION_INVALID"
        and issue["field"] == "graphNodes.missingIds"
        and "missing_ids_invalid" in issue["reasons"]
        for issue in validate_judge_answer(malformed_graph_missing_ids)
    )

    malformed_repository_requested_id = deepcopy(answer)
    malformed_repository_requested_id["evidence"]["sourceCodeKg"]["contextResolution"]["repositorySnapshot"][
        "requestedId"
    ] = {"not": "a-string"}
    assert any(
        issue["code"] == "SOURCE_KG_CONTEXT_RESOLUTION_INVALID"
        and issue["field"] == "repositorySnapshot.requestedId"
        and "requested_id_invalid" in issue["reasons"]
        for issue in validate_judge_answer(malformed_repository_requested_id)
    )

    leaky_resolution_id = deepcopy(answer)
    leaky_resolution_id["evidence"]["sourceCodeKg"]["contextResolution"]["graphNodes"]["resolvedIds"] = [
        "https://node_user:node_password@ids.example/graph-node?token=node-secret"
    ]
    issues = validate_judge_answer(leaky_resolution_id)
    assert any(
        issue["code"] == "SOURCE_KG_CONTEXT_RESOLUTION_INVALID"
        and issue["field"] == "graphNodes.resolvedIds"
        for issue in issues
    )
    assert "node_user" not in str(issues)
    assert "node_password" not in str(issues)
    assert "node-secret" not in str(issues)
