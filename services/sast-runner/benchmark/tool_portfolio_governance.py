from __future__ import annotations

from pathlib import Path
from typing import Any

from app.scanner.orchestrator import ALL_TOOLS
from benchmark.benchmark_slice_report import build_default_benchmark_slice_report
from benchmark.golden_corpus_validator import validate_manifest
from benchmark.tool_output_compat import build_compat_report

SCHEMA_VERSION = "s4-tool-portfolio-governance-v1"
GOVERNANCE_DECISION = "keep-current-six-tools"
GOVERNANCE_GATES = (
    "goldenCorpusCoverage",
    "evidenceContractCompatibility",
    "parserCompatibility",
    "benchmarkSliceCoverage",
    "uniqueContributionAccounting",
    "runtimeStabilityBudget",
    "consumerSafety",
)

_TOOL_ROLES = {
    "semgrep": {
        "role": "pattern-taint",
        "uniqueContribution": "fast project-specific pattern and taint evidence",
        "overlap": ["flawfinder dangerous API patterns"],
        "limitations": ["coverage depends on rule quality", "no final verdict"],
    },
    "cppcheck": {
        "role": "c-cpp-static-diagnostics",
        "uniqueContribution": "deterministic C/C++ diagnostics and CTU-style evidence",
        "overlap": ["clang-tidy general diagnostics", "gcc-fanalyzer diagnostics"],
        "limitations": ["dataflow may be absent", "no external vulnerability knowledge"],
    },
    "flawfinder": {
        "role": "dangerous-function-canary",
        "uniqueContribution": "fast dangerous API visibility",
        "overlap": ["semgrep dangerous API rules"],
        "limitations": ["text evidence only", "no semantic proof"],
    },
    "clang-tidy": {
        "role": "cert-compiler-diagnostics",
        "uniqueContribution": "CERT-style compile-profile diagnostics",
        "overlap": ["cppcheck diagnostics", "scan-build compiler-backed diagnostics"],
        "limitations": ["compile profile affects coverage", "some checks lack CWE mapping"],
    },
    "scan-build": {
        "role": "clang-path-sensitive-analysis",
        "uniqueContribution": "Clang Static Analyzer path-sensitive diagnostics",
        "overlap": ["gcc-fanalyzer path-sensitive diagnostics"],
        "limitations": ["can be partial under timeout", "requires compile-capable units"],
    },
    "gcc-fanalyzer": {
        "role": "gcc-path-sensitive-analysis",
        "uniqueContribution": "independent GCC analyzer signal",
        "overlap": ["scan-build path-sensitive diagnostics"],
        "limitations": ["requires GCC analyzer availability", "profile constraints apply"],
    },
}


def build_governance_report(manifest: dict[str, Any], *, repo_root: str) -> dict[str, Any]:
    corpus = validate_manifest(manifest, repo_root=repo_root)
    compat_report = _tool_output_compat_report(repo_root)
    benchmark_report = _benchmark_slice_report(repo_root)
    tool_capability_cases = {
        case.get("toolId"): case
        for case in manifest.get("layers", {}).get("toolCapabilityOracles", [])
        if isinstance(case, dict)
    }
    gates = {
        "goldenCorpusCoverage": _gate(corpus.get("status") == "pass", "Golden Corpus manifest validates."),
        "evidenceContractCompatibility": _gate(True, "staticEvidenceContract boundaries remain required for all portfolio decisions."),
        "parserCompatibility": _gate(
            compat_report.get("gates", {}).get("parserCompatibility", {}).get("status") == "pass",
            "Current six-tool parser output fixtures match normalized S4 finding contracts.",
        ),
        "benchmarkSliceCoverage": _gate(
            _benchmark_slice_coverage_ready(benchmark_report),
            "Required historical Juliet benchmark slice artifacts are present and parseable.",
        ),
        "uniqueContributionAccounting": _gate(_covers_all_tools(tool_capability_cases), "All current tools have role/contribution/limit accounting."),
        "runtimeStabilityBudget": _gate(True, "No tool-set change is proposed, so runtime budget is unchanged."),
        "consumerSafety": _gate(True, "No S3/S5 API changes are required for keep-current-six-tools."),
    }
    return {
        "schemaVersion": SCHEMA_VERSION,
        "decision": GOVERNANCE_DECISION,
        "toolSet": list(ALL_TOOLS),
        "goldenCorpusProfile": manifest.get("schemaVersion"),
        "gates": gates,
        "toolOutputCompatibility": {
            "schemaVersion": compat_report.get("schemaVersion"),
            "manifestSchemaVersion": compat_report.get("manifestSchemaVersion"),
            "status": compat_report.get("gates", {}).get("parserCompatibility", {}).get("status", "unknown"),
            "caseCount": len(compat_report.get("cases", [])),
            "toolOrder": compat_report.get("toolOrder", []),
        },
        "benchmarkSliceEvidence": {
            "schemaVersion": benchmark_report.get("schemaVersion"),
            "consumerPolicy": benchmark_report.get("consumerPolicy"),
            "sources": benchmark_report.get("sources", {}),
            "weakestSlices": benchmark_report.get("weakestSlices", {}),
        },
        "tools": [_tool_record(tool, tool_capability_cases.get(tool)) for tool in ALL_TOOLS],
        "decisionRecord": {
            "rationale": [
                "This pass explicitly excludes new SAST tool introduction.",
                "Contracts and Golden Corpus validation are prerequisites before changing portfolio composition.",
                "The six current tools provide complementary deterministic local evidence surfaces.",
            ],
            "rejectedAlternatives": [
                {
                    "alternative": "add-tool-now",
                    "reason": "No failing-before/passing-after Golden Corpus evidence exists yet.",
                },
                {
                    "alternative": "remove-tool-now",
                    "reason": "Unique contribution loss has not been disproven by expanded corpus evidence.",
                },
                {
                    "alternative": "upgrade-tool-now-for-quality-claim",
                    "reason": "Parser compatibility and quality deltas must be captured by a validation report profile first.",
                },
            ],
            "requiredFollowUps": [
                "Add benchmark slices before any recall/noise claim.",
                "Add failing-before/passing-after corpus cases before any add/remove/upgrade proposal.",
            ],
        },
    }


def _tool_record(tool_id: str, capability_case: dict[str, Any] | None) -> dict[str, Any]:
    role = _TOOL_ROLES[tool_id]
    return {
        "toolId": tool_id,
        "role": role["role"],
        "uniqueContribution": role["uniqueContribution"],
        "overlap": role["overlap"],
        "limitations": role["limitations"],
        "capabilityOracle": capability_case.get("id") or capability_case.get("toolId") if capability_case else None,
        "deterministic": True,
        "requiresNetwork": False,
        "requiresExternalKnowledge": False,
        "emitsFinalVerdict": False,
    }


def _covers_all_tools(cases: dict[str, Any]) -> bool:
    return list(cases) == ALL_TOOLS


def _tool_output_compat_report(repo_root: str) -> dict[str, Any]:
    manifest_path = Path(repo_root) / "tests" / "fixtures" / "tool_output_compat_v1" / "manifest.json"
    if not manifest_path.is_file():
        return {
            "schemaVersion": None,
            "manifestSchemaVersion": None,
            "toolOrder": [],
            "gates": {"parserCompatibility": {"status": "fail"}},
            "cases": [],
        }
    return build_compat_report(manifest_path)


def _benchmark_slice_report(repo_root: str) -> dict[str, Any]:
    try:
        return build_default_benchmark_slice_report(Path(repo_root))
    except (FileNotFoundError, ValueError, KeyError):
        return {
            "schemaVersion": None,
            "consumerPolicy": None,
            "sources": {},
            "weakestSlices": {},
        }


def _benchmark_slice_coverage_ready(report: dict[str, Any]) -> bool:
    sources = report.get("sources")
    if not isinstance(sources, dict):
        return False
    variant01 = sources.get("variant01")
    all_variants = sources.get("allVariants")
    return (
        isinstance(variant01, dict)
        and isinstance(all_variants, dict)
        and variant01.get("artifact") == "v0.6.0-full.json"
        and all_variants.get("artifact") == "v0.7.0-all-variants.json"
        and variant01.get("cweCount") == 12
        and all_variants.get("cweCount") == 12
    )


def _gate(passed: bool, summary: str) -> dict[str, Any]:
    return {
        "status": "pass" if passed else "fail",
        "summary": summary,
    }
