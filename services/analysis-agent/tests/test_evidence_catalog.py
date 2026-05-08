from __future__ import annotations

from app.agent_runtime.schemas.agent import ToolCallRequest, ToolResult
from typing import get_args

from app.core.evidence_catalog import EvidenceCatalog, EvidenceCatalogEntry, EvidenceClass, _extract_cwe
from app.core.phase_one_types import Phase1Result
from app.schemas.request import EvidenceRef, TaskRequest, Context
from app.types import TaskType


def test_catalog_indexes_request_and_phase1_sast_metadata():
    catalog = EvidenceCatalog()
    catalog.ingest_phase1_result(Phase1Result(
        sast_findings=[{
            "ruleId": "static-tool:rule-1",
            "message": "Potential issue (CWE-120).",
            "location": {"file": "src/main.c", "line": 12},
            "metadata": {"cweId": "CWE-120", "name": "buffer"},
        }],
    ))

    entry = catalog.get("eref-sast-static-tool:rule-1")

    assert entry is not None
    assert entry.category == "sast"
    assert entry.file == "src/main.c"
    assert entry.line == 12
    assert entry.cwe_id == "CWE-120"


def test_catalog_ingests_tool_result_semantics_without_bundle_decision_api():
    catalog = EvidenceCatalog()
    call = ToolCallRequest(
        id="tc1",
        name="code_graph.callers",
        arguments={"function_name": "dangerous_call"},
    )
    result = ToolResult(
        tool_call_id="tc1",
        name="code_graph.callers",
        success=True,
        content="- caller (src/main.c:29)",
        new_evidence_refs=["eref-caller-dangerous_call"],
    )

    catalog.ingest_tool_result(call, result)
    entry = catalog.get("eref-caller-dangerous_call")

    assert entry is not None
    assert entry.category == "caller"
    assert entry.function == "dangerous_call"
    assert entry.file == "src/main.c"
    assert entry.line == 29
    assert not hasattr(catalog, "command_injection_bundle")
    assert not hasattr(catalog, "has_command_injection_signal")


def test_catalog_renders_evidence_refs_from_metadata_entries():
    catalog = EvidenceCatalog()
    catalog.ingest_tool_result(
        ToolCallRequest(id="read1", name="code.read_file", arguments={"path": "src/main.c"}),
        ToolResult(
            tool_call_id="read1",
            name="code.read_file",
            success=True,
            content="int main(void) { return 0; } // src/main.c:1",
            new_evidence_refs=["eref-file-main"],
        ),
    )

    refs = catalog.as_evidence_refs()

    assert refs == [{
        "refId": "eref-file-main",
        "artifactType": "source",
        "locator": {"file": "src/main.c", "line": 1},
    }]


def test_history_preserves_duplicate_ref_id_entries():
    catalog = EvidenceCatalog()
    catalog.add(EvidenceCatalogEntry(
        ref_id="eref-duplicate",
        evidence_class="local",
        summary="first",
    ))
    catalog.add(EvidenceCatalogEntry(
        ref_id="eref-duplicate",
        evidence_class="knowledge",
        summary="second",
    ))

    assert [entry.summary for entry in catalog.history()] == ["first", "second"]
    assert len(catalog.history()) == 2


def test_entries_preserve_support_capable_entry_on_later_downgrade():
    catalog = EvidenceCatalog()
    catalog.add(EvidenceCatalogEntry(
        ref_id="eref-duplicate",
        evidence_class="local",
        summary="first",
    ))
    catalog.add(EvidenceCatalogEntry(
        ref_id="eref-duplicate",
        evidence_class="knowledge",
        summary="second",
    ))

    assert catalog.get("eref-duplicate").summary == "first"  # type: ignore[union-attr]
    assert [(entry.ref_id, entry.summary) for entry in catalog.entries()] == [
        ("eref-duplicate", "first")
    ]


def test_local_operational_collision_does_not_hide_final_support():
    catalog = EvidenceCatalog()
    catalog.add(EvidenceCatalogEntry(
        ref_id="eref-collision",
        evidence_class="local",
        roles=("source_location",),
        summary="source support",
    ))
    catalog.add(EvidenceCatalogEntry(
        ref_id="eref-collision",
        evidence_class="operational",
        roles=("operational_status",),
        operational_status="timeout",
        summary="timeout",
    ))

    assert catalog.get("eref-collision").evidence_class == "local"  # type: ignore[union-attr]
    assert "eref-collision" in catalog.final_ref_ids()
    assert [entry.evidence_class for entry in catalog.history()] == ["local", "operational"]


def test_negative_evidence_class_literal_preserves_existing_values():
    assert set(get_args(EvidenceClass)) == {
        "local",
        "knowledge",
        "derived",
        "operational",
        "unclassified",
        "negative",
    }


def test_as_evidence_refs_excludes_negative_and_operational_entries():
    catalog = EvidenceCatalog()
    catalog.add(EvidenceCatalogEntry(
        ref_id="eref-local-main",
        category="source",
        artifact_type="source",
        file="src/main.c",
        line=7,
        evidence_class="local",
    ))
    catalog.add(EvidenceCatalogEntry(
        ref_id="eref-negative-no-hit",
        category="unknown",
        artifact_type="negative-attempt",
        evidence_class="negative",
        source_tool="knowledge.search",
        summary="no hit",
    ))
    catalog.add(EvidenceCatalogEntry(
        ref_id="eref-operational-timeout",
        category="metadata",
        artifact_type="operational-diagnostic",
        evidence_class="operational",
        source_tool="knowledge.search",
        summary="timeout",
    ))

    assert catalog.negative_ref_ids() == {"eref-negative-no-hit"}
    assert catalog.operational_ref_ids() == {"eref-operational-timeout"}
    assert catalog.final_ref_ids() == {"eref-local-main"}
    assert catalog.as_evidence_refs() == [{
        "refId": "eref-local-main",
        "artifactType": "source",
        "locator": {"file": "src/main.c", "line": 7},
    }]


def test_empty_ref_id_logs_warning(caplog):
    catalog = EvidenceCatalog()

    with caplog.at_level("WARNING", logger="app.core.evidence_catalog"):
        catalog.add(EvidenceCatalogEntry(ref_id="", evidence_class="local", summary="empty"))

    assert catalog.history() == []
    assert any("empty evidence ref_id skipped" in record.message for record in caplog.records)


def test_sast_zero_findings_emits_negative_catalog_entry():
    catalog = EvidenceCatalog()

    catalog.ingest_phase1_result(Phase1Result(
        sast_findings=[],
        sast_scan_attempted=True,
        sast_scan_completed=True,
    ))

    negative_refs = catalog.negative_ref_ids()
    assert len(negative_refs) == 1
    entry = catalog.get(next(iter(negative_refs)))
    assert entry is not None
    assert entry.source_tool == "sast"
    assert entry.tool_arguments == {"phase": "phase1", "findingCount": 0}
    assert entry.evidence_class == "negative"
    assert "sast_no_findings" in entry.roles
    assert entry.ref_id not in catalog.final_ref_ids()
    assert entry.ref_id not in {ref["refId"] for ref in catalog.as_evidence_refs()}


def test_sast_failure_emits_operational_not_no_findings():
    catalog = EvidenceCatalog()

    catalog.ingest_phase1_result(Phase1Result(
        sast_findings=[],
        sast_scan_attempted=True,
        sast_scan_completed=False,
        sast_failure_detail={
            "code": "SDK_NOT_FOUND",
            "message": "Unknown SDK profile",
            "statusCode": 400,
        },
    ))

    assert catalog.negative_ref_ids() == set()
    operational_refs = catalog.operational_ref_ids()
    assert len(operational_refs) == 1
    entry = catalog.get(next(iter(operational_refs)))
    assert entry is not None
    assert entry.source_tool == "sast"
    assert entry.tool_arguments == {
        "phase": "phase1",
        "findingCount": 0,
        "failureCode": "SDK_NOT_FOUND",
        "statusCode": 400,
    }
    assert entry.evidence_class == "operational"
    assert "sast_scan_failed" in entry.roles
    assert "sast_contract_failure" in entry.roles
    assert entry.ref_id not in catalog.final_ref_ids()
    assert entry.ref_id not in {ref["refId"] for ref in catalog.as_evidence_refs()}


def test_knowledge_no_hit_tool_result_emits_negative_entry():
    catalog = EvidenceCatalog()
    call = ToolCallRequest(
        id="k-no-hit",
        name="knowledge.search",
        arguments={"query": "CWE-9999", "top_k": 5},
    )
    result = ToolResult(
        tool_call_id="k-no-hit",
        name="knowledge.search",
        success=True,
        content='{"hits": []}',
        new_evidence_refs=[],
    )

    catalog.ingest_tool_result(call, result)

    negative_refs = catalog.negative_ref_ids()
    assert len(negative_refs) == 1
    entry = catalog.get(next(iter(negative_refs)))
    assert entry is not None
    assert entry.source_tool == "knowledge.search"
    assert entry.tool_arguments == {"query": "CWE-9999", "top_k": 5}
    assert entry.summary == "knowledge.search: no_hits"
    assert entry.ref_id not in catalog.final_ref_ids()
    assert entry.ref_id not in {ref["refId"] for ref in catalog.as_evidence_refs()}


def test_kb_timeout_tool_result_emits_operational_not_negative_entry():
    catalog = EvidenceCatalog()
    call = ToolCallRequest(
        id="k-timeout",
        name="knowledge.search",
        arguments={"query": "CWE-78"},
    )
    result = ToolResult(
        tool_call_id="k-timeout",
        name="knowledge.search",
        success=False,
        content='{"error": "TIMEOUT"}',
        error="TIMEOUT",
    )

    catalog.ingest_tool_result(call, result)

    assert catalog.negative_ref_ids() == set()
    operational_refs = catalog.operational_ref_ids()
    assert len(operational_refs) == 1
    entry = catalog.get(next(iter(operational_refs)))
    assert entry is not None
    assert entry.source_tool == "knowledge.search"
    assert entry.operational_status == "timeout"
    assert entry.ref_id not in catalog.final_ref_ids()


def test_extract_cwe_matches_real_cwe_ids():
    assert _extract_cwe("Potential command injection CWE-78 in src/main.c") == "CWE-78"
    assert _extract_cwe("no CWE identifier here") is None


def test_catalog_classifies_knowledge_refs_as_contextual_not_final_support():
    catalog = EvidenceCatalog()
    catalog.ingest_tool_result(
        ToolCallRequest(id="k1", name="knowledge.search", arguments={"query": "CWE-78"}),
        ToolResult(
            tool_call_id="k1",
            name="knowledge.search",
            success=True,
            content="CWE-78 command injection background",
            new_evidence_refs=["eref-knowledge-CWE-78"],
        ),
    )

    entry = catalog.get("eref-knowledge-CWE-78")

    assert entry is not None
    assert entry.evidence_class == "knowledge"
    assert entry.roles == ("knowledge_context",)
    assert "eref-knowledge-CWE-78" in catalog.contextual_ref_ids()
    assert "eref-knowledge-CWE-78" not in catalog.final_ref_ids()


def test_catalog_inferrs_request_source_refs_as_local_and_objectives_as_operational():
    request = TaskRequest(
        taskType=TaskType.DEEP_ANALYZE,
        taskId="catalog-request",
        context=Context(trusted={}),
        evidenceRefs=[
            EvidenceRef(
                refId="eref-source-main",
                artifactId="src",
                artifactType="source",
                locatorType="lineRange",
                locator={"file": "src/main.c", "line": 7},
            ),
            EvidenceRef(
                refId="eref-objective",
                artifactId="obj",
                artifactType="request-objective",
                locatorType="jsonPointer",
                locator={"path": "/context/trusted/objective"},
            ),
        ],
    )
    catalog = EvidenceCatalog()
    catalog.ingest_request(request)

    assert catalog.get("eref-source-main").evidence_class == "local"  # type: ignore[union-attr]
    assert catalog.get("eref-objective").evidence_class == "operational"  # type: ignore[union-attr]
    assert "eref-source-main" in catalog.final_ref_ids()
    assert "eref-objective" not in catalog.final_ref_ids()
