from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REQUIRED_LAYERS = (
    "contractOracles",
    "toolCapabilityOracles",
    "evidenceBundleCorpus",
    "vulnerabilityFamilyCanaries",
)
REQUIRED_SCHEMA_VERSION = "s4-golden-corpus-v1"


def load_manifest(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def validate_manifest(manifest: dict[str, Any], *, repo_root: str | Path) -> dict[str, Any]:
    repo = Path(repo_root)
    errors: list[str] = []
    layers = manifest.get("layers")

    if manifest.get("schemaVersion") != REQUIRED_SCHEMA_VERSION:
        errors.append("schemaVersion must be s4-golden-corpus-v1")
    if not isinstance(layers, dict):
        errors.append("layers must be an object")
        layers = {}

    layer_reports = []
    for layer_name in REQUIRED_LAYERS:
        cases = layers.get(layer_name)
        if not isinstance(cases, list) or not cases:
            errors.append(f"{layer_name} must have at least one executable case")
            layer_reports.append({"layer": layer_name, "status": "fail", "caseCount": 0})
            continue
        case_errors = []
        for case in cases:
            case_errors.extend(_validate_case(case, repo=repo, layer_name=layer_name))
        errors.extend(case_errors)
        layer_reports.append({
            "layer": layer_name,
            "status": "pass" if not case_errors else "fail",
            "caseCount": len(cases),
            "executableCount": sum(1 for case in cases if case.get("executable")),
        })

    expansion = manifest.get("expansionCriteria")
    if not isinstance(expansion, list) or len(expansion) < 4:
        errors.append("expansionCriteria must document pre-governance expansion rules")

    return {
        "schemaVersion": manifest.get("schemaVersion"),
        "analysisProfile": manifest.get("analysisProfile"),
        "status": "pass" if not errors else "fail",
        "layers": layer_reports,
        "errors": errors,
    }


def _validate_case(case: Any, *, repo: Path, layer_name: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(case, dict):
        return [f"{layer_name} case must be an object"]
    case_id = case.get("id") or case.get("toolId") or "<unknown>"
    executable = case.get("executable")
    if not executable:
        errors.append(f"{layer_name}:{case_id} missing executable")
    elif "::" not in str(executable):
        errors.append(f"{layer_name}:{case_id} executable must be pytest node id")
    fixture = case.get("fixture")
    if fixture and not (repo / str(fixture)).is_file():
        errors.append(f"{layer_name}:{case_id} fixture missing: {fixture}")
    asserts = case.get("asserts")
    if layer_name != "toolCapabilityOracles" and (not isinstance(asserts, list) or not asserts):
        errors.append(f"{layer_name}:{case_id} must document asserted behavior")
    if layer_name == "toolCapabilityOracles":
        if not case.get("toolId"):
            errors.append(f"{layer_name}:{case_id} missing toolId")
        if not case.get("primaryEvidence"):
            errors.append(f"{layer_name}:{case_id} missing primaryEvidence")
        if not case.get("knownLimits"):
            errors.append(f"{layer_name}:{case_id} missing knownLimits")
    return errors
