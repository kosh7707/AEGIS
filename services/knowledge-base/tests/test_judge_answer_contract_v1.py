from __future__ import annotations

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
                "checksumSha256": "sha256:curlsource",
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
                "checksumSha256": "sha256:curlsymbols",
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
    answer = build_judge_answer(
        repo,
        _judge_request({"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"}, source_context),
    )
    ignored = deepcopy(answer)
    ignored["evidence"]["sourceCodeKg"] = {"resolved": False}
    assert any(issue["code"] == "SOURCE_KG_CONTEXT_IGNORED" for issue in validate_judge_answer(ignored))
