"""Deterministic Semgrep effective-coverage metadata.

This module intentionally does not call Semgrep.  It describes whether the
configured Semgrep rule surface can be proven to cover the target language mix.
That makes "tool process is alive" distinct from "quality coverage is proven".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


C_EXTENSIONS = {".c"}
CPP_EXTENSIONS = {".cc", ".cpp", ".cxx", ".c++"}
C_HEADER_EXTENSIONS = {".h"}
CPP_HEADER_EXTENSIONS = {".hh", ".hpp", ".hxx", ".h++", ".ipp", ".txx"}
C_CPP_INCLUDE_EXTENSIONS = [
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".c++",
        ".hh",
        ".hpp",
        ".hxx",
        ".h++",
        ".ipp",
        ".txx",
]

_BRACKET_LANG_RE = re.compile(r"^\s*languages\s*:\s*\[([^\]]*)\]", re.MULTILINE)
_BLOCK_LANG_RE = re.compile(r"^\s*languages\s*:\s*\n((?:\s*-\s*[A-Za-z0-9_+#-]+\s*\n?)+)", re.MULTILINE)


def resolve_semgrep_custom_rules_dir(configured: str | Path | None) -> Path | None:
    """Resolve S4's Semgrep custom rules path using semgrep_runner's convention."""
    if configured is None or str(configured).strip() == "":
        return None
    path = Path(configured)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[2] / path
    return path if path.is_dir() else None


def build_semgrep_effective_coverage(
    *,
    source_files: list[str],
    rulesets: list[str],
    custom_rules_dir: str | Path | None,
    include_extensions: list[str] | None,
) -> dict[str, Any]:
    """Return public-safe Semgrep effective-coverage metadata.

    The result is a quality signal, not a tool-liveness/system-stability signal.
    Raw file paths are intentionally not emitted.
    """
    target_counts = _target_language_counts(source_files)
    local_rule_counts = _local_rule_language_counts(custom_rules_dir)
    registry_hints = _registry_rule_language_hints(rulesets)
    include_summary = _include_filter_summary(include_extensions)

    quality_reasons: list[str] = []
    if _has_cpp_targets(target_counts):
        if include_extensions is not None and not _includes_any_cpp_extension(include_extensions):
            quality_reasons.append("SEMGREP_CPP_TARGETS_EXCLUDED_BY_EXTENSION_FILTER")
        if local_rule_counts["cpp"] <= 0 and local_rule_counts["generic"] <= 0:
            quality_reasons.append("SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN")

    if _has_c_targets(target_counts):
        c_registry_proven = registry_hints["c"] > 0
        c_local_proven = local_rule_counts["c"] > 0 or local_rule_counts["generic"] > 0
        if not c_registry_proven and not c_local_proven:
            quality_reasons.append("SEMGREP_C_EFFECTIVE_COVERAGE_UNPROVEN")

    if not _has_c_targets(target_counts) and not _has_cpp_targets(target_counts):
        quality_status = "not_applicable"
        if target_counts["total"] == 0:
            quality_reasons.append("SEMGREP_NO_SOURCE_FILES_REPORTED")
        else:
            quality_reasons.append("SEMGREP_NO_C_OR_CPP_TARGETS_REPORTED")
    else:
        quality_status = "degraded" if quality_reasons else "ok"

    custom_rule_files = int(local_rule_counts.pop("_files", 0))
    return {
        "coverageKind": "semgrep-effective-coverage-v1",
        "coverageStatus": quality_status,
        "coverageReasons": sorted(dict.fromkeys(quality_reasons)),
        "targetLanguageCounts": target_counts,
        "localRuleLanguageCounts": local_rule_counts,
        "registryRuleLanguageHints": registry_hints,
        "includeFilter": include_summary,
        "rulesetCount": len(rulesets),
        "customRuleFiles": custom_rule_files,
    }


def _target_language_counts(source_files: list[str]) -> dict[str, int]:
    counts = {"c": 0, "cpp": 0, "header": 0, "other": 0, "total": 0}
    for value in source_files:
        counts["total"] += 1
        suffix = Path(value).suffix.lower()
        if suffix in C_EXTENSIONS:
            counts["c"] += 1
        elif suffix in CPP_EXTENSIONS:
            counts["cpp"] += 1
        elif suffix in C_HEADER_EXTENSIONS or suffix in CPP_HEADER_EXTENSIONS:
            counts["header"] += 1
        else:
            counts["other"] += 1
    return counts


def _local_rule_language_counts(custom_rules_dir: str | Path | None) -> dict[str, int]:
    counts = {"c": 0, "cpp": 0, "generic": 0, "unknown": 0, "_files": 0}
    if custom_rules_dir is None:
        return counts
    root = Path(custom_rules_dir)
    if not root.is_dir():
        return counts
    for path in sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml")):
        counts["_files"] += 1
        languages = _extract_semgrep_languages(path.read_text(encoding="utf-8", errors="ignore"))
        if not languages:
            counts["unknown"] += 1
            continue
        for language in languages:
            normalized = _normalize_language(language)
            counts[normalized] = counts.get(normalized, 0) + 1
    return counts


def _extract_semgrep_languages(text: str) -> list[str]:
    values: list[str] = []
    for match in _BRACKET_LANG_RE.finditer(text):
        values.extend(token.strip().strip("'\"") for token in match.group(1).split(",") if token.strip())
    for match in _BLOCK_LANG_RE.finditer(text):
        block = match.group(1)
        values.extend(
            line.split("-", 1)[1].strip().strip("'\"")
            for line in block.splitlines()
            if "-" in line
        )
    return values


def _normalize_language(language: str) -> str:
    normalized = language.strip().lower()
    if normalized in {"c"}:
        return "c"
    if normalized in {"cpp", "c++"}:
        return "cpp"
    if normalized in {"generic"}:
        return "generic"
    return "unknown"


def _registry_rule_language_hints(rulesets: list[str]) -> dict[str, int]:
    counts = {"c": 0, "cpp": 0, "generic": 0, "unknown": 0}
    for ruleset in rulesets:
        if ruleset == "p/c":
            counts["c"] += 1
        elif ruleset in {"p/generic"}:
            counts["generic"] += 1
        else:
            counts["unknown"] += 1
    return counts


def _include_filter_summary(include_extensions: list[str] | None) -> dict[str, Any]:
    if include_extensions is None:
        return {"mode": "all", "extensions": []}
    return {"mode": "allowlist", "extensions": sorted(dict.fromkeys(include_extensions))}


def _includes_any_cpp_extension(include_extensions: list[str]) -> bool:
    return any(ext.lower() in CPP_EXTENSIONS | CPP_HEADER_EXTENSIONS for ext in include_extensions)


def _has_c_targets(counts: dict[str, int]) -> bool:
    return counts.get("c", 0) > 0


def _has_cpp_targets(counts: dict[str, int]) -> bool:
    return counts.get("cpp", 0) > 0
