from app.core.source_code_kg import (
    SOURCE_CODE_KG_CONTRACT_VERSION,
    SOURCE_CODE_KG_INGEST_PATH,
    build_source_code_kg_payload,
    validate_source_code_kg_contract,
)


def _function(**overrides):
    func = {
        "name": "handle_request",
        "file": "src/server.c",
        "line": 42,
        "calls": ["popen"],
        "origin": "project",
    }
    func.update(overrides)
    return func


def test_build_payload_requires_repository_commit_hash():
    payload, diagnostics = build_source_code_kg_payload(
        project_id="proj-1",
        code_functions=[_function()],
        revision_hint=None,
        provenance={"repositoryUrl": "https://example.invalid/repo.git"},
    )

    assert payload == {}
    assert diagnostics["ready"] is False
    assert "REPOSITORY_COMMIT_HASH_MISSING" in diagnostics["reasonCodes"]


def test_build_payload_maps_all_contract_families_and_deterministic_edges():
    payload, diagnostics = build_source_code_kg_payload(
        project_id="proj-1",
        code_functions=[_function(), _function(name="popen", file="lib/stdio.c", line=7)],
        revision_hint="abc123def456",
        provenance={"repositoryUrl": "https://example.invalid/repo.git"},
        build_target="gateway-webserver",
        build_profile={"targetArch": "arm64"},
        build_environment={"CC": "gcc"},
        compile_commands_path="/uploads/proj/build/compile_commands.json",
    )

    assert diagnostics["ready"] is True
    assert payload["schemaVersion"] == "s5-source-code-kg-ingest-request-v1"
    assert payload["repositorySnapshot"]["commitHash"] == "abc123def456"
    assert payload["repositorySnapshot"]["repositoryUrl"] == "https://example.invalid/repo.git"
    assert payload["buildContext"]["buildTarget"] == "gateway-webserver"
    assert payload["buildContext"]["compileCommandsArtifactId"]
    assert payload["analysisArtifactSet"]["analyzerName"].startswith("aegis-s3")
    assert len(payload["graphNodes"]) == 2
    assert payload["graphEdges"][0]["edgeKind"] == "calls"
    assert payload["graphEdges"][0]["sourceStableId"]
    assert payload["graphEdges"][0]["targetStableId"]
    assert payload["evidenceSnippets"] == []
    assert payload["sourceArtifacts"] == []
    assert payload["richIrArtifacts"][0]["artifactKind"] == "compile_commands"
    assert "EVIDENCE_SNIPPETS_NOT_PRODUCED" in diagnostics["reasonCodes"]
    assert "SOURCE_ARTIFACTS_NOT_PRODUCED" in diagnostics["reasonCodes"]

    payload_again, _ = build_source_code_kg_payload(
        project_id="proj-1",
        code_functions=[_function(), _function(name="popen", file="lib/stdio.c", line=7)],
        revision_hint="abc123def456",
        provenance={"repositoryUrl": "https://example.invalid/repo.git"},
        build_target="gateway-webserver",
        compile_commands_path="/uploads/proj/build/compile_commands.json",
    )
    assert payload_again["graphNodes"] == payload["graphNodes"]
    assert payload_again["graphEdges"] == payload["graphEdges"]


def test_contract_validation_requires_expected_version_and_path():
    valid = validate_source_code_kg_contract({
        "sourceCodeKgContractVersion": SOURCE_CODE_KG_CONTRACT_VERSION,
        "endpoint": {"path": SOURCE_CODE_KG_INGEST_PATH},
    })
    assert valid["ready"] is True

    invalid = validate_source_code_kg_contract({
        "sourceCodeKgContractVersion": "source-code-kg-ingest-v0",
        "endpoint": {"path": "/wrong"},
    })
    assert invalid["ready"] is False
    assert "SOURCE_CODE_KG_CONTRACT_VERSION_MISMATCH:source-code-kg-ingest-v0" in invalid["reasonCodes"]
    assert "SOURCE_CODE_KG_CONTRACT_PATH_MISMATCH:/wrong" in invalid["reasonCodes"]


def test_payload_marks_producer_coverage_incomplete_separately_from_schema_readiness():
    payload, diagnostics = build_source_code_kg_payload(
        project_id="proj-1",
        code_functions=[_function()],
        revision_hint="abc123def456",
    )

    assert payload
    assert diagnostics["ready"] is True
    assert diagnostics["coverageComplete"] is False
    assert "EVIDENCE_SNIPPETS_NOT_PRODUCED" in diagnostics["reasonCodes"]
    assert "SOURCE_ARTIFACTS_NOT_PRODUCED" in diagnostics["reasonCodes"]


def test_duplicate_function_names_keep_distinct_nodes_and_document_name_only_edge_resolution():
    payload, diagnostics = build_source_code_kg_payload(
        project_id="proj-1",
        code_functions=[
            _function(name="parse", file="src/a.c", line=10, calls=["sanitize"]),
            _function(name="parse", file="src/b.c", line=20, calls=[]),
            _function(name="sanitize", file="src/safe.c", line=30, calls=[]),
        ],
        revision_hint="abc123def456",
    )

    parse_nodes = [node for node in payload["graphNodes"] if node.get("displayName") == "parse"]
    assert diagnostics["ready"] is True
    assert len(parse_nodes) == 2
    assert parse_nodes[0]["stableId"] != parse_nodes[1]["stableId"]
    # S4 currently provides `calls` as bare names, so target resolution is intentionally name-based.
    assert payload["graphEdges"][0]["metadata"] == {"callee": "sanitize"}


def test_duplicate_second_caller_uses_occurrence_stable_id_as_edge_source():
    payload, diagnostics = build_source_code_kg_payload(
        project_id="proj-1",
        code_functions=[
            _function(name="parse", file="src/a.c", line=10, calls=[]),
            _function(name="parse", file="src/b.c", line=20, calls=["sink"]),
            _function(name="sink", file="src/sink.c", line=30, calls=[]),
        ],
        revision_hint="abc123def456",
    )

    assert diagnostics["ready"] is True
    parse_nodes = [node for node in payload["graphNodes"] if node.get("displayName") == "parse"]
    second_parse = next(node for node in parse_nodes if node.get("filePath") == "src/b.c")
    assert payload["graphEdges"][0]["sourceStableId"] == second_parse["stableId"]


def test_build_payload_rejects_malformed_code_functions_without_exception():
    payload, diagnostics = build_source_code_kg_payload(
        project_id="proj-1",
        code_functions="not-a-list",  # type: ignore[arg-type]
        revision_hint="abc123def456",
    )

    assert payload == {}
    assert diagnostics["ready"] is False
    assert diagnostics["functionCount"] == 0
    assert "GRAPH_FUNCTIONS_MALFORMED" in diagnostics["reasonCodes"]
    assert "GRAPH_FUNCTIONS_MISSING" in diagnostics["reasonCodes"]


def test_dict_shaped_call_entries_are_preserved_when_allowlisted():
    payload, diagnostics = build_source_code_kg_payload(
        project_id="proj-1",
        code_functions=[
            _function(name="handler", file="src/handler.c", line=10, calls=[
                {"name": "sanitize"},
                {"callee": "audit_log"},
                {"functionName": "sink"},
                {"displayName": "not-allowlisted"},
                {"name": ""},
            ]),
            _function(name="sanitize", file="src/sanitize.c", line=20, calls=[]),
        ],
        revision_hint="abc123def456",
    )

    assert diagnostics["ready"] is True
    callees = [edge["metadata"]["callee"] for edge in payload["graphEdges"]]
    assert callees == ["sanitize", "audit_log", "sink"]
    assert "not-allowlisted" not in {node.get("displayName") for node in payload["graphNodes"]}
