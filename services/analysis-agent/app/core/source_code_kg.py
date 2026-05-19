"""S5 Source Code KG producer adapter for S3 Phase 1 facts."""

from __future__ import annotations

import hashlib
import json
from typing import Any


SOURCE_CODE_KG_CONTRACT_VERSION = "source-code-kg-ingest-v1"
SOURCE_CODE_KG_SCHEMA_VERSION = "s5-source-code-kg-ingest-request-v1"
SOURCE_CODE_KG_INGEST_PATH = "/v1/source-code-kg/ingest"


def validate_source_code_kg_contract(contract: Any) -> dict:
    """Validate the live S5 producer contract before S3 posts Source KG data."""
    if not isinstance(contract, dict) or not contract:
        return {
            "ready": False,
            "reasonCodes": ["SOURCE_CODE_KG_CONTRACT_MISSING"],
            "contractVersion": None,
            "endpointPath": None,
        }
    version = contract.get("sourceCodeKgContractVersion")
    endpoint = contract.get("endpoint") if isinstance(contract.get("endpoint"), dict) else {}
    path = endpoint.get("path")
    reasons: list[str] = []
    if version != SOURCE_CODE_KG_CONTRACT_VERSION:
        reasons.append(f"SOURCE_CODE_KG_CONTRACT_VERSION_MISMATCH:{version or 'missing'}")
    if path != SOURCE_CODE_KG_INGEST_PATH:
        reasons.append(f"SOURCE_CODE_KG_CONTRACT_PATH_MISMATCH:{path or 'missing'}")
    return {
        "ready": not reasons,
        "reasonCodes": reasons,
        "contractVersion": version,
        "endpointPath": path,
    }


def build_source_code_kg_payload(
    *,
    project_id: str,
    code_functions: list[dict],
    revision_hint: str | None = None,
    provenance: dict | None = None,
    build_target: str | None = None,
    build_profile: dict | None = None,
    build_environment: dict | None = None,
    compile_commands_path: str | None = None,
    source_artifacts: list[dict] | None = None,
    evidence_snippets: list[dict] | None = None,
) -> tuple[dict, dict]:
    """Map S3/S4 Phase 1 facts into the S5 Source Code KG ingest contract."""
    provenance_dict = provenance if isinstance(provenance, dict) else {}
    functions_malformed = not isinstance(code_functions, (list, tuple))
    raw_functions = code_functions if isinstance(code_functions, (list, tuple)) else []
    functions = [func for func in raw_functions if isinstance(func, dict)]
    commit_hash = _commit_hash(revision_hint, provenance_dict)
    diagnostics = {
        "ready": False,
        "reasonCodes": [],
        "schemaVersion": SOURCE_CODE_KG_SCHEMA_VERSION,
        "functionCount": len(functions),
    }
    reasons: list[str] = diagnostics["reasonCodes"]

    if not commit_hash:
        reasons.append("REPOSITORY_COMMIT_HASH_MISSING")
    if functions_malformed:
        reasons.append("GRAPH_FUNCTIONS_MALFORMED")
    if not functions:
        reasons.append("GRAPH_FUNCTIONS_MISSING")

    if reasons:
        return {}, diagnostics

    graph_nodes, graph_edges = _graph_facts(
        project_id=project_id,
        commit_hash=commit_hash,
        functions=functions,
    )
    snippets = _evidence_snippets(evidence_snippets, functions)
    artifacts = _source_artifacts(source_artifacts)
    rich_ir = _rich_ir_artifacts(compile_commands_path)

    if not snippets:
        reasons.append("EVIDENCE_SNIPPETS_NOT_PRODUCED")
    if not artifacts:
        reasons.append("SOURCE_ARTIFACTS_NOT_PRODUCED")
    if not rich_ir:
        reasons.append("RICH_IR_ARTIFACTS_NOT_PRODUCED")
    coverage_complete = bool(snippets and artifacts and rich_ir)

    payload = {
        "schemaVersion": SOURCE_CODE_KG_SCHEMA_VERSION,
        "repositorySnapshot": _repository_snapshot(project_id, commit_hash, provenance_dict),
        "sourceArtifacts": artifacts,
        "buildContext": _build_context(
            project_id=project_id,
            build_target=build_target,
            build_profile=build_profile,
            build_environment=build_environment,
            compile_commands_path=compile_commands_path,
            provenance=provenance_dict,
        ),
        "analysisArtifactSet": _analysis_artifact_set(
            functions=functions,
            build_profile=build_profile,
            compile_commands_path=compile_commands_path,
            provenance=provenance_dict,
        ),
        "evidenceSnippets": snippets,
        "graphNodes": graph_nodes,
        "graphEdges": graph_edges,
        "richIrArtifacts": rich_ir,
    }
    diagnostics.update({
        "ready": True,
        "coverageComplete": coverage_complete,
        "graphNodeCount": len(graph_nodes),
        "graphEdgeCount": len(graph_edges),
        "evidenceSnippetCount": len(snippets),
        "sourceArtifactCount": len(artifacts),
        "richIrArtifactCount": len(rich_ir),
    })
    return payload, diagnostics


def _commit_hash(revision_hint: str | None, provenance: dict) -> str | None:
    snapshot = provenance.get("repositorySnapshot")
    candidates: list[Any] = []
    if isinstance(snapshot, dict):
        candidates.extend([
            snapshot.get("commitHash"),
            snapshot.get("commitSha"),
            snapshot.get("revision"),
        ])
    candidates.extend([
        provenance.get("commitHash"),
        provenance.get("commitSha"),
        provenance.get("repositoryCommit"),
        provenance.get("sourceRevision"),
        revision_hint,
    ])
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def _repository_snapshot(project_id: str, commit_hash: str, provenance: dict) -> dict:
    snapshot = provenance.get("repositorySnapshot") if isinstance(provenance.get("repositorySnapshot"), dict) else {}
    result = {
        "repositoryId": _first_str(snapshot.get("repositoryId"), provenance.get("repositoryId"), project_id),
        "repositoryUrl": _first_str(snapshot.get("repositoryUrl"), provenance.get("repositoryUrl"), provenance.get("sourceRepositoryUrl")),
        "commitHash": commit_hash,
        "treeHash": _first_str(snapshot.get("treeHash"), provenance.get("treeHash")),
        "submoduleHashes": snapshot.get("submoduleHashes") if isinstance(snapshot.get("submoduleHashes"), dict) else {},
        "provenance": provenance,
    }
    return _strip_empty(result)


def _build_context(
    *,
    project_id: str,
    build_target: str | None,
    build_profile: dict | None,
    build_environment: dict | None,
    compile_commands_path: str | None,
    provenance: dict,
) -> dict:
    build_profile_dict = build_profile if isinstance(build_profile, dict) else {}
    build_env_dict = build_environment if isinstance(build_environment, dict) else {}
    toolchain = {
        "compiler": _first_str(build_profile_dict.get("compiler"), build_env_dict.get("CC"), build_env_dict.get("CXX")),
        "targetArch": _first_str(build_profile_dict.get("targetArch"), build_profile_dict.get("arch")),
        "toolchainTriplet": _first_str(build_profile_dict.get("toolchainTriplet"), build_env_dict.get("TOOLCHAIN_TRIPLET")),
    }
    context = {
        "projectId": project_id,
        "targetId": _first_str(provenance.get("targetId"), build_target, project_id),
        "buildTarget": build_target,
        "toolchain": _strip_empty(toolchain),
        "compileCommandsArtifactId": _artifact_id("compile_commands", compile_commands_path) if compile_commands_path else None,
        "dependencyGraph": {},
        "buildMetadata": _strip_empty({
            "buildProfile": build_profile_dict,
            "buildEnvironmentKeys": sorted(build_env_dict),
            "compileCommandsPath": compile_commands_path,
        }),
        "provenance": provenance,
    }
    return _strip_empty(context)


def _analysis_artifact_set(
    *,
    functions: list[dict],
    build_profile: dict | None,
    compile_commands_path: str | None,
    provenance: dict,
) -> dict:
    return _strip_empty({
        "analyzerName": "aegis-s3-analysis-agent+s4-sast-runner",
        "analysisConfig": {
            "producer": "s3-phase1",
            "source": "s4-codegraph",
            "buildProfilePresent": isinstance(build_profile, dict) and bool(build_profile),
            "compileCommandsPresent": bool(compile_commands_path),
        },
        "artifactHashes": {
            "codeFunctionsSha256": _sha256_json(functions),
            "compileCommandsPathSha256": _sha256_text(compile_commands_path) if compile_commands_path else None,
        },
        "provenance": provenance,
    })


def _graph_facts(*, project_id: str, commit_hash: str, functions: list[dict]) -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    node_by_name: dict[str, str] = {}
    node_ids_by_index: dict[int, str] = {}
    for index, func in enumerate(functions):
        name = _first_str(func.get("name"), func.get("function"), f"function-{index}") or f"function-{index}"
        file_path = _first_str(func.get("file"), func.get("filePath"))
        line = _int_or_none(func.get("line") or func.get("lineStart"))
        stable_id = _stable_id("function", project_id, commit_hash, file_path or "", name, str(line or ""))
        node_ids_by_index[index] = stable_id
        node_by_name.setdefault(name, stable_id)
        nodes.append(_strip_empty({
            "nodeKind": "function",
            "stableId": stable_id,
            "displayName": name,
            "filePath": file_path,
            "lineStart": line,
            "symbol": {"name": name},
            "metadata": _strip_empty({
                "origin": func.get("origin"),
                "originalLib": func.get("originalLib") or func.get("original_lib"),
                "originalVersion": func.get("originalVersion") or func.get("original_version"),
            }),
        }))

    edges: list[dict] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for index, func in enumerate(functions):
        name = _first_str(func.get("name"), func.get("function"), f"function-{index}") or f"function-{index}"
        source_id = node_ids_by_index.get(index)
        if not source_id:
            continue
        calls = func.get("calls")
        if not isinstance(calls, list):
            continue
        for callee in calls:
            callee_name = _callee_name(callee)
            if not callee_name:
                continue
            target_id = node_by_name.get(callee_name)
            if not target_id:
                target_id = _stable_id("external-function", project_id, commit_hash, callee_name)
                node_by_name[callee_name] = target_id
                nodes.append({
                    "nodeKind": "external_function",
                    "stableId": target_id,
                    "displayName": callee_name,
                    "symbol": {"name": callee_name},
                    "metadata": {"inferredFromCallEdge": True},
                })
            key = (source_id, target_id, "calls")
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append({
                "edgeKind": "calls",
                "sourceStableId": source_id,
                "targetStableId": target_id,
                "metadata": {"callee": callee_name},
            })
    return nodes, edges


def _evidence_snippets(explicit: list[dict] | None, functions: list[dict]) -> list[dict]:
    snippets = _valid_snippets(explicit)
    for func in functions:
        if not isinstance(func, dict):
            continue
        snippet_text = _first_str(func.get("snippetText"), func.get("sourceSnippet"))
        file_path = _first_str(func.get("file"), func.get("filePath"))
        if snippet_text and file_path:
            snippets.append(_strip_empty({
                "filePath": file_path,
                "lineStart": _int_or_none(func.get("line") or func.get("lineStart")),
                "snippetText": snippet_text,
                "checksumSha256": _sha256_text(snippet_text),
            }))
    return snippets


def _valid_snippets(explicit: list[dict] | None) -> list[dict]:
    result: list[dict] = []
    for item in explicit or []:
        if isinstance(item, dict) and item.get("filePath") and item.get("snippetText"):
            result.append(dict(item))
    return result


def _source_artifacts(explicit: list[dict] | None) -> list[dict]:
    result: list[dict] = []
    for item in explicit or []:
        if isinstance(item, dict) and item.get("artifactUri") and item.get("checksumSha256"):
            result.append(dict(item))
    return result


def _callee_name(value: Any) -> str | None:
    if isinstance(value, str):
        return _first_str(value)
    if isinstance(value, dict):
        return _first_str(value.get("name"), value.get("callee"), value.get("functionName"))
    return None


def _rich_ir_artifacts(compile_commands_path: str | None) -> list[dict]:
    if not compile_commands_path:
        return []
    return [{
        "artifactKind": "compile_commands",
        "artifactUri": compile_commands_path,
        "checksumSha256": _sha256_text(f"compile_commands:{compile_commands_path}"),
        "metadata": {"path": compile_commands_path, "contentStored": False},
    }]


def _first_str(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _strip_empty(value: dict) -> dict:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _artifact_id(kind: str, value: str | None) -> str:
    return f"{kind}:{_sha256_text(value or '')[:16]}"


def _stable_id(kind: str, *parts: str) -> str:
    return f"{kind}:{_sha256_text('|'.join(parts))[:24]}"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_text(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
