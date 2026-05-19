"""SARIF JSON → SastFinding[] 변환기."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.errors import SarifParseError
from app.scanner.path_utils import normalize_path
from app.schemas.response import SastDataFlowStep, SastFinding, SastFindingLocation

logger = logging.getLogger("aegis-sast-runner")


def parse_sarif(
    sarif: dict[str, Any],
    base_dir: Path,
) -> tuple[list[SastFinding], int]:
    """SARIF JSON을 SastFinding 리스트로 변환한다.

    Returns:
        (findings, rules_run) 튜플.
    """
    try:
        runs = sarif.get("runs", [])
        if not runs:
            return [], 0

        run = runs[0]
        rules_map = _build_rules_map(run)
        rules_run = len(rules_map)
        raw_results = run.get("results", [])

        findings: list[SastFinding] = []
        for result in raw_results:
            finding = _convert_result(result, rules_map, base_dir)
            if finding is not None:
                findings.append(finding)

        return findings, rules_run

    except (KeyError, TypeError, IndexError, AttributeError):
        raise SarifParseError("Failed to parse SARIF output") from None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_rules_map(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """driver.rules 배열을 ruleId → rule dict 맵으로 변환."""
    driver = run.get("tool", {}).get("driver", {})
    rules = driver.get("rules", [])
    return {r["id"]: r for r in rules if "id" in r}


def _convert_result(
    result: dict[str, Any],
    rules_map: dict[str, dict[str, Any]],
    base_dir: Path,
) -> SastFinding | None:
    """단일 SARIF result → SastFinding."""
    rule_id = result.get("ruleId")
    if not rule_id:
        return None

    location = _extract_location(result, base_dir)
    if location is None:
        return None

    severity = result.get("level", "warning")
    message = result.get("message", {}).get("text", "")

    data_flow = _extract_data_flow(result, base_dir)
    metadata = _extract_metadata(rule_id, rules_map)

    return SastFinding(
        toolId="semgrep",
        ruleId=f"semgrep:{rule_id}",
        severity=severity,
        message=message,
        location=location,
        dataFlow=data_flow if data_flow else None,
        metadata=metadata if metadata else None,
    )


def _extract_location(
    result: dict[str, Any],
    base_dir: Path,
) -> SastFindingLocation | None:
    """result.locations[0].physicalLocation → SastFindingLocation."""
    locations = result.get("locations", [])
    if not locations:
        return None

    phys = locations[0].get("physicalLocation", {})
    uri = phys.get("artifactLocation", {}).get("uri", "")
    region = phys.get("region", {})

    if not uri or not region.get("startLine"):
        return None

    file_path = normalize_path(uri.removeprefix("file://"), base_dir)

    return SastFindingLocation(
        file=file_path,
        line=region["startLine"],
        column=region.get("startColumn"),
        endLine=region.get("endLine"),
        endColumn=region.get("endColumn"),
    )


def _extract_data_flow(
    result: dict[str, Any],
    base_dir: Path,
) -> list[SastDataFlowStep]:
    """result.codeFlows[*].threadFlows[*].locations[*] → SastDataFlowStep[]."""
    steps: list[SastDataFlowStep] = []

    for code_flow in result.get("codeFlows", []):
        for thread_flow in code_flow.get("threadFlows", []):
            for loc_wrapper in thread_flow.get("locations", []):
                loc = loc_wrapper.get("location", {})
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                snippet = phys.get("region", {}).get("snippet", {}).get("text")

                if uri and region.get("startLine"):
                    steps.append(SastDataFlowStep(
                        file=normalize_path(uri.removeprefix("file://"), base_dir),
                        line=region["startLine"],
                        content=snippet,
                    ))

    return steps


def _extract_metadata(
    rule_id: str,
    rules_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """rule metadata에서 CWE, references 등 추출."""
    meta: dict[str, Any] = {}
    rule = rules_map.get(rule_id, {})
    props = rule.get("properties", {})

    if "tags" in props:
        cwe_tags = [t for t in props["tags"] if t.startswith("CWE-")]
        if cwe_tags:
            meta["cwe"] = cwe_tags
            meta["cweId"] = cwe_tags[0]

    if "references" in props:
        meta["references"] = props["references"]

    meta["semgrepRuleId"] = rule_id

    short_desc = rule.get("shortDescription", {}).get("text")
    if short_desc:
        meta["shortDescription"] = short_desc

    return meta

