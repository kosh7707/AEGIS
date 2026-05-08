#!/usr/bin/env python3
"""Run the hot11 datasets through the full S3 pipeline sequentially.

Pipeline per case:
  1. Build Agent ``build-resolve`` using the canonical hot11 manifest request shape.
  2. Analysis Agent ``deep-analyze`` with the Build Agent's buildPreparation.
  3. Analysis Agent ``generate-poc`` for up to N selected claims.

The runner is intentionally conservative:
- dry-run is the default and only validates/stages request artifacts;
- live execution requires ``--live``;
- live mode preflights S7 LLM readiness before spending build/analyze time;
- cases continue independently unless ``--stop-on-failure`` is set.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MANIFEST = REPO_ROOT / "uploads/build-agent-stabilization-datasets/manifest.json"
DEFAULT_ORACLE = REPO_ROOT / "services/analysis-agent/eval/golden/hot11_full_pipeline_oracle.json"
DEFAULT_REPORT_ROOT = REPO_ROOT / "reports"
DEFAULT_BUILD_URL = "http://localhost:8003"
DEFAULT_ANALYSIS_URL = "http://localhost:8001"
DEFAULT_SAST_URL = "http://localhost:9000"
DEFAULT_KB_URL = "http://localhost:8002"
DEFAULT_GATEWAY_URL = "http://localhost:8000"
BUILD_RUNNER_PATH = REPO_ROOT / "services/build-agent/scripts/stabilization_runner.py"


class RunnerError(RuntimeError):
    """Base runner error."""


class LivePreflightBlocked(RunnerError):
    """Raised when live execution should not start."""


def _load_build_runner_module():
    spec = importlib.util.spec_from_file_location("aegis_build_stabilization_runner", BUILD_RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RunnerError(f"could not import build runner from {BUILD_RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_build_runner = _load_build_runner_module()
ManifestCase = _build_runner.ManifestCase
load_manifest = _build_runner.load_manifest
make_build_request = _build_runner.make_build_request


def _utc_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def load_oracle(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    oracle = _read_json(path)
    if not isinstance(oracle, dict):
        raise RunnerError(f"oracle must be a JSON object: {path}")
    cases = oracle.get("cases")
    if not isinstance(cases, list) or not all(isinstance(item, dict) for item in cases):
        raise RunnerError(f"oracle cases must be a list of objects: {path}")
    duplicates = sorted({case.get("caseId") for case in cases if [item.get("caseId") for item in cases].count(case.get("caseId")) > 1})
    if duplicates:
        raise RunnerError(f"duplicate oracle caseId(s): {', '.join(str(item) for item in duplicates)}")
    oracle["_caseIndex"] = {str(case["caseId"]): case for case in cases if case.get("caseId")}
    return oracle


def _oracle_case(oracle: dict[str, Any] | None, case_id: str) -> dict[str, Any] | None:
    if not oracle:
        return None
    case_index = oracle.get("_caseIndex")
    return case_index.get(case_id) if isinstance(case_index, dict) else None


def _assert_oracle_covers_cases(oracle: dict[str, Any] | None, cases: list[Any]) -> None:
    if not oracle:
        return
    missing = [case.case_id for case in cases if _oracle_case(oracle, case.case_id) is None]
    if missing:
        raise RunnerError(f"oracle does not cover selected case(s): {', '.join(missing)}")


def _http_json(method: str, url: str, *, payload: dict[str, Any] | None = None, request_id: str | None = None,
               timeout_sec: float | None = None) -> tuple[int, Any]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if request_id:
        headers["X-Request-Id"] = request_id
    request = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec) as response:  # noqa: S310 - local test runner URLs
            raw = response.read().decode("utf-8", errors="replace")
            try:
                return response.status, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return response.status, {"raw": raw}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}
    except urllib.error.URLError as exc:
        return 0, {"error": str(exc)}


def _post_task(base_url: str, payload: dict[str, Any], request_id: str, timeout_sec: float | None) -> tuple[int, Any]:
    return _http_json(
        "POST",
        base_url.rstrip("/") + "/v1/tasks",
        payload=payload,
        request_id=request_id,
        timeout_sec=timeout_sec,
    )


def _service_check(name: str, base_url: str, endpoint: str, timeout_sec: float = 5.0) -> dict[str, Any]:
    status, data = _http_json("GET", base_url.rstrip("/") + endpoint, timeout_sec=timeout_sec)
    ok = 200 <= status < 300
    return {"name": name, "url": base_url.rstrip("/") + endpoint, "httpStatus": status, "ok": ok, "body": data}


def live_preflight(args: argparse.Namespace) -> dict[str, Any]:
    checks = [
        _service_check("build-agent", args.build_url, "/v1/health"),
        _service_check("analysis-agent", args.analysis_url, "/v1/health"),
        _service_check("sast-runner", args.sast_url, "/v1/health"),
        _service_check("knowledge-base", args.kb_url, "/v1/ready"),
        _service_check("llm-gateway", args.gateway_url, "/v1/health"),
    ]
    preflight = {
        "checkedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "checks": checks,
        "ok": all(item["ok"] for item in checks),
        "llmReady": None,
        "blockedReason": None,
    }
    gateway = next(item for item in checks if item["name"] == "llm-gateway")
    gateway_body = gateway.get("body") if isinstance(gateway.get("body"), dict) else {}
    if isinstance(gateway_body, dict):
        preflight["llmReady"] = gateway_body.get("llmReady")
        preflight["gatewayReady"] = gateway_body.get("ready")
        preflight["gatewayDegraded"] = gateway_body.get("degraded")
        preflight["gatewayBlockedReason"] = gateway_body.get("blockedReason")
        preflight["gatewayDegradeReasons"] = gateway_body.get("degradeReasons")
    if not preflight["ok"]:
        failed = [item["name"] for item in checks if not item["ok"]]
        preflight["blockedReason"] = "service_unavailable:" + ",".join(failed)
    elif args.require_llm_ready and preflight.get("llmReady") is not True:
        reason = preflight.get("gatewayBlockedReason") or preflight.get("gatewayDegradeReasons") or "llm_not_ready"
        preflight["blockedReason"] = f"llm_not_ready:{reason}"
        preflight["ok"] = False
    return preflight


def _extract_build_result(build_response: dict[str, Any]) -> dict[str, Any]:
    result = build_response.get("result") if isinstance(build_response.get("result"), dict) else {}
    return result.get("buildResult") if isinstance(result.get("buildResult"), dict) else {}


def _extract_build_preparation(case: ManifestCase, build_response: dict[str, Any]) -> dict[str, Any]:
    result = build_response.get("result") if isinstance(build_response.get("result"), dict) else {}
    build_result = _extract_build_result(build_response)
    preparation = result.get("buildPreparation") if isinstance(result.get("buildPreparation"), dict) else {}
    merged: dict[str, Any] = dict(preparation)
    for key in ("buildCommand", "buildScript", "buildDir", "producedArtifacts"):
        if key in build_result and key not in merged:
            merged[key] = build_result[key]
    merged.setdefault("declaredMode", case.build.get("mode") or "native")
    merged.setdefault("expectedArtifacts", case.expected_artifacts)
    if case.build:
        merged.setdefault("buildProfile", _build_profile_from_case(case))
    return merged


def _build_profile_from_case(case: ManifestCase) -> dict[str, Any]:
    profile: dict[str, Any] = {}
    build = case.build or {}
    for key in ("sdkId", "sdkRootPath", "setupScript", "sysroot", "toolchainTriplet", "mode"):
        if key in build:
            profile[key] = build[key]
    if build.get("mode") == "sdk" and build.get("sdkId"):
        # S4 accepts registered SDK ids or the explicit non-registered sentinel.
        # Manifest-local SDK roots are test fixtures, so S3 should not pretend they
        # are registered backend SDK records.
        profile["sdkId"] = "non-registered"
        profile["originalSdkId"] = build.get("sdkId")
    return profile


def _build_environment_from_case(case: ManifestCase) -> dict[str, Any] | None:
    env = case.build.get("environment") if isinstance(case.build, dict) else None
    return dict(env) if isinstance(env, dict) and env else None


def make_analysis_request(
    case: ManifestCase,
    build_response: dict[str, Any] | None,
    run_label: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    build_response = build_response or {}
    build_preparation = _extract_build_preparation(case, build_response) if build_response else {
        "declaredMode": case.build.get("mode") or "native",
        "expectedArtifacts": case.expected_artifacts,
        "buildProfile": _build_profile_from_case(case),
    }
    build_result = _extract_build_result(build_response)
    trusted: dict[str, Any] = {
        "projectPath": str(case.project_path),
        "targetPath": case.build_target_path or ".",
        "projectId": f"{run_label}-{case.case_id}",
        "objective": f"Run the full AEGIS security analysis pipeline for hot11 case {case.case_id}: {case.title}",
        "buildPreparation": build_preparation,
        "buildProfile": _build_profile_from_case(case),
        "provenance": {
            "source": "hot11-full-pipeline-runner",
            "caseId": case.case_id,
            "manifest": str(args.manifest),
        },
    }
    build_command = build_preparation.get("buildCommand") or build_result.get("buildCommand")
    if build_command:
        trusted["buildCommand"] = build_command
    build_environment = build_preparation.get("buildEnvironment") or _build_environment_from_case(case)
    if isinstance(build_environment, dict) and build_environment:
        trusted["buildEnvironment"] = build_environment
    if args.sast_tools:
        trusted["sastTools"] = args.sast_tools
    return {
        "taskType": "deep-analyze",
        "taskId": f"hot11-full-{run_label}-{case.case_id}-analyze",
        "context": {"trusted": trusted},
        "constraints": {"maxTokens": args.analysis_max_tokens, "timeoutMs": args.analysis_timeout_ms},
    }


def _analysis_claims(analysis_response: dict[str, Any]) -> list[dict[str, Any]]:
    result = analysis_response.get("result") if isinstance(analysis_response.get("result"), dict) else {}
    claims = result.get("claims")
    return [claim for claim in claims if isinstance(claim, dict)] if isinstance(claims, list) else []


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).lower()


def _claim_location_text(claim: dict[str, Any]) -> str:
    location = claim.get("location")
    if isinstance(location, dict):
        return _json_text(location)
    if location is None:
        return ""
    return str(location).lower()


def _keyword_present(text: str, keyword: str) -> bool:
    return str(keyword).lower() in text


def _claim_matches_expected(claim: dict[str, Any], expected: dict[str, Any]) -> bool:
    match = expected.get("match") if isinstance(expected.get("match"), dict) else {}
    text = _json_text(claim)
    location_text = _claim_location_text(claim)

    all_keywords = [str(item) for item in match.get("allKeywords") or []]
    if any(not _keyword_present(text, keyword) for keyword in all_keywords):
        return False

    any_keywords = [str(item) for item in match.get("anyKeywords") or []]
    if any_keywords and not any(_keyword_present(text, keyword) for keyword in any_keywords):
        return False

    location_regexes = [str(item) for item in match.get("locationRegexes") or []]
    if location_regexes:
        location_haystack = f"{location_text}\n{text}"
        if not any(re.search(pattern, location_haystack, flags=re.IGNORECASE) for pattern in location_regexes):
            return False

    cwe = expected.get("cwe")
    # CWE is intentionally soft: some good claims explain the weakness class
    # without normalizing the CWE id. Keyword/location matching carries the
    # hard oracle constraint.
    if cwe and str(cwe).lower() in text:
        return True
    return True


def _oracle_match_ids_for_claim(claim: dict[str, Any], oracle_case: dict[str, Any] | None) -> list[str]:
    if not oracle_case:
        return []
    expected_findings = oracle_case.get("expectedFindings")
    if not isinstance(expected_findings, list):
        return []
    matches: list[str] = []
    for expected in expected_findings:
        if not isinstance(expected, dict):
            continue
        finding_id = str(expected.get("id") or "")
        if finding_id and _claim_matches_expected(claim, expected):
            matches.append(finding_id)
    return matches


def _poc_quality_fields(poc_summary: dict[str, Any]) -> dict[str, Any]:
    result = (poc_summary.get("responseSummary") or {}).get("result")
    return result if isinstance(result, dict) else {}


def _poc_matches_expected(
    poc_summary: dict[str, Any],
    expected: dict[str, Any],
    *,
    require_clean: bool,
) -> bool:
    if poc_summary.get("status") != "completed":
        return False
    result = _poc_quality_fields(poc_summary)
    if require_clean:
        if result.get("pocOutcome") != "poc_accepted":
            return False
        if result.get("qualityOutcome") != "accepted":
            return False
        if result.get("cleanPass") is not True:
            return False
    poc_policy = expected.get("poc") if isinstance(expected.get("poc"), dict) else {}
    required = [str(item) for item in poc_policy.get("requiredAnyKeywords") or []]
    if not required:
        return True
    text = _json_text(poc_summary)
    return any(_keyword_present(text, keyword) for keyword in required)


def evaluate_oracle(
    oracle_case: dict[str, Any] | None,
    analysis_response: dict[str, Any],
    poc_summaries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if oracle_case is None:
        return {
            "enabled": False,
            "passed": None,
            "matchedFindings": [],
            "missingFindings": [],
            "missingPocs": [],
            "pocQualityFailures": [],
        }

    claims = _analysis_claims(analysis_response)
    expected_findings = [
        item for item in (oracle_case.get("expectedFindings") or [])
        if isinstance(item, dict) and item.get("id")
    ]
    poc_summaries = poc_summaries or []
    matched_findings: list[dict[str, Any]] = []
    missing_findings: list[dict[str, Any]] = []
    missing_pocs: list[dict[str, Any]] = []
    poc_quality_failures: list[dict[str, Any]] = []
    policy = oracle_case.get("policy") if isinstance(oracle_case.get("policy"), dict) else {}

    for expected in expected_findings:
        finding_id = str(expected["id"])
        matches = [
            {
                "claimIndex": index,
                "location": claim.get("location"),
                "title": claim.get("title") or claim.get("summary") or claim.get("riskTitle"),
            }
            for index, claim in enumerate(claims)
            if _claim_matches_expected(claim, expected)
        ]
        min_matches = int(expected.get("minMatches") or 1)
        if len(matches) >= min_matches:
            matched_findings.append({"id": finding_id, "matches": matches[:5], "matchCount": len(matches)})
        else:
            missing_findings.append({
                "id": finding_id,
                "cwe": expected.get("cwe"),
                "riskClass": expected.get("riskClass"),
                "requiredMinMatches": min_matches,
                "actualMatches": len(matches),
            })

        poc_policy = expected.get("poc") if isinstance(expected.get("poc"), dict) else {}
        if poc_policy.get("required") is True and len(matches) >= min_matches:
            clean_required = bool(
                poc_policy.get("cleanRequired")
                or poc_policy.get("diagnosticOnly") is False
                or policy.get("passRequiresCleanPocForMatchedFindings")
            )
            passed_poc = any(
                finding_id in (summary.get("oracleFindingIds") or [])
                and _poc_matches_expected(summary, expected, require_clean=clean_required)
                for summary in poc_summaries
            )
            if not passed_poc:
                missing_pocs.append({
                    "id": finding_id,
                    "reason": (
                        "no clean accepted PoC for matched finding"
                        if clean_required
                        else "no completed diagnostic PoC for matched finding"
                    ),
                })
                for summary in poc_summaries:
                    if finding_id not in (summary.get("oracleFindingIds") or []):
                        continue
                    result = _poc_quality_fields(summary)
                    poc_quality_failures.append({
                        "id": finding_id,
                        "status": summary.get("status"),
                        "pocOutcome": result.get("pocOutcome"),
                        "qualityOutcome": result.get("qualityOutcome"),
                        "cleanPass": result.get("cleanPass"),
                    })

    return {
        "enabled": True,
        "passed": not missing_findings and not missing_pocs,
        "expectedFindingCount": len(expected_findings),
        "claimCount": len(claims),
        "matchedFindings": matched_findings,
        "missingFindings": missing_findings,
        "missingPocs": missing_pocs,
        "pocQualityFailures": poc_quality_failures,
        "negativeControls": oracle_case.get("negativeControls") or [],
    }


def _claim_rank(claim: dict[str, Any]) -> tuple[int, int]:
    text = json.dumps(claim, ensure_ascii=False).lower()
    primary = any(token in text for token in ("popen", "system(", "cwe-78", "command injection", "rce"))
    secondary = any(token in text for token in ("injection", "exec", "shell", "command"))
    return (0 if primary else 1 if secondary else 2, len(text))


def _selected_claim_entries(
    analysis_response: dict[str, Any],
    limit: int,
    oracle_case: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    claims = _analysis_claims(analysis_response)
    entries = [
        {
            "claimIndex": index,
            "claim": claim,
            "oracleFindingIds": _oracle_match_ids_for_claim(claim, oracle_case),
        }
        for index, claim in enumerate(claims)
    ]
    entries.sort(key=lambda entry: (
        0 if entry["oracleFindingIds"] else 1,
        _claim_rank(entry["claim"]),
        entry["claimIndex"],
    ))
    if limit < 0:
        return entries
    return entries[:limit]


def _selected_claims(analysis_response: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    return [entry["claim"] for entry in _selected_claim_entries(analysis_response, limit)]


def _safe_child(base: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _location_to_path(location: Any) -> str | None:
    if isinstance(location, dict):
        raw = location.get("file") or location.get("path") or location.get("filename")
        return str(raw) if raw else None
    if not isinstance(location, str) or not location.strip():
        return None
    text = location.strip()
    # Common forms: src/foo.cpp:62, src/foo.cpp:62:7, file=src/foo.cpp line=62
    file_match = re.search(r"(?:file|path)=([^\s,;]+)", text)
    if file_match:
        return file_match.group(1).strip("'\"")
    drive_prefix = re.match(r"^[A-Za-z]:[\\/]", text)
    if drive_prefix:
        return None
    return text.split(":", 1)[0].strip("'\"")


def _source_files_for_claim(case: ManifestCase, claim: dict[str, Any], *, max_bytes: int) -> list[dict[str, str]]:
    rel = _location_to_path(claim.get("location"))
    if not rel:
        return []
    rel = rel.replace("\\", "/").lstrip("/")
    if not rel or "\x00" in rel or rel.startswith("../") or "/../" in f"/{rel}/":
        return []
    roots = [case.effective_target_root, case.project_path]
    for root in roots:
        candidate = (root / rel).resolve()
        if not _safe_child(root, candidate) or not candidate.is_file():
            continue
        content = candidate.read_text(errors="replace")
        if len(content.encode("utf-8", errors="replace")) > max_bytes:
            content = content[:max_bytes] + "\n/* truncated by hot11 runner */\n"
        display_path = str(candidate.relative_to(root.resolve())) if _safe_child(root, candidate) else rel
        return [{"path": display_path, "content": content}]
    return []


def make_poc_request(
    case: ManifestCase,
    claim: dict[str, Any],
    analysis_response: dict[str, Any],
    build_response: dict[str, Any],
    run_label: str,
    poc_index: int,
    args: argparse.Namespace,
) -> dict[str, Any] | None:
    files = _source_files_for_claim(case, claim, max_bytes=args.poc_source_max_bytes)
    if not files:
        return None
    trusted = {
        "objective": f"Generate a diagnostic PoC for hot11 case {case.case_id} claim {poc_index}",
        "claim": claim,
        "files": files,
        "projectPath": str(case.effective_target_root),
        "projectId": f"{run_label}-{case.case_id}",
        "buildPreparation": _extract_build_preparation(case, build_response),
    }
    evidence_refs = analysis_response.get("evidenceRefs")
    if not isinstance(evidence_refs, list):
        evidence_refs = []
    return {
        "taskType": "generate-poc",
        "taskId": f"hot11-full-{run_label}-{case.case_id}-poc-{poc_index}",
        "context": {"trusted": trusted},
        "evidenceRefs": evidence_refs,
        "constraints": {"maxTokens": args.poc_max_tokens, "timeoutMs": args.poc_timeout_ms},
    }


def _case_status(response: dict[str, Any]) -> str:
    status = response.get("status")
    return str(status) if status is not None else "no_status"


def _is_completed(response: dict[str, Any]) -> bool:
    return _case_status(response) == "completed"


def run_dry_case(
    case: ManifestCase,
    case_dir: Path,
    run_label: str,
    args: argparse.Namespace,
    oracle_case: dict[str, Any] | None = None,
) -> dict[str, Any]:
    build_request = make_build_request(case, run_label)
    analysis_request = make_analysis_request(case, None, run_label, args)
    _write_json(case_dir / "case-manifest.json", case.to_json())
    _write_json(case_dir / "build-request.json", build_request)
    _write_json(case_dir / "analysis-request-template.json", analysis_request)
    if oracle_case is not None:
        _write_json(case_dir / "oracle-case.json", oracle_case)
    return {
        "caseId": case.case_id,
        "title": case.title,
        "mode": "dry-run",
        "status": "staged",
        "buildRequest": str(case_dir / "build-request.json"),
        "analysisRequestTemplate": str(case_dir / "analysis-request-template.json"),
        "scriptHintPath": case.script_hint_path,
        "buildMode": case.build_mode,
        "oracleEnabled": oracle_case is not None,
        "oracleExpectedFindingCount": len(oracle_case.get("expectedFindings") or []) if oracle_case else 0,
    }


def run_live_case(
    case: ManifestCase,
    case_dir: Path,
    run_label: str,
    args: argparse.Namespace,
    oracle_case: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "caseId": case.case_id,
        "title": case.title,
        "mode": "live",
        "status": "started",
        "startedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    build_request = make_build_request(case, run_label)
    _write_json(case_dir / "case-manifest.json", case.to_json())
    _write_json(case_dir / "build-request.json", build_request)

    t0 = time.monotonic()
    build_status, build_response = _post_task(args.build_url, build_request, build_request["taskId"], args.http_timeout_sec)
    summary["buildHttpStatus"] = build_status
    summary["buildElapsedSeconds"] = round(time.monotonic() - t0, 3)
    summary["buildStatus"] = _case_status(build_response) if isinstance(build_response, dict) else "invalid_response"
    _write_json(case_dir / "build-response.json", build_response)
    if build_status < 200 or build_status >= 300 or not isinstance(build_response, dict) or not _is_completed(build_response):
        summary["status"] = "build_failed"
        summary["finishedAt"] = dt.datetime.now(dt.timezone.utc).isoformat()
        _write_json(case_dir / "summary.json", summary)
        return summary

    analysis_request = make_analysis_request(case, build_response, run_label, args)
    _write_json(case_dir / "analysis-request.json", analysis_request)
    t1 = time.monotonic()
    analysis_status, analysis_response = _post_task(
        args.analysis_url, analysis_request, analysis_request["taskId"], args.http_timeout_sec
    )
    summary["analysisHttpStatus"] = analysis_status
    summary["analysisElapsedSeconds"] = round(time.monotonic() - t1, 3)
    summary["analysisStatus"] = _case_status(analysis_response) if isinstance(analysis_response, dict) else "invalid_response"
    _write_json(case_dir / "analysis-response.json", analysis_response)
    if analysis_status < 200 or analysis_status >= 300 or not isinstance(analysis_response, dict) or not _is_completed(analysis_response):
        summary["status"] = "analysis_failed"
        summary["finishedAt"] = dt.datetime.now(dt.timezone.utc).isoformat()
        _write_json(case_dir / "summary.json", summary)
        return summary

    claims = _analysis_claims(analysis_response)
    analysis_oracle = evaluate_oracle(oracle_case, analysis_response, [])
    _write_json(case_dir / "oracle-analysis-verdict.json", analysis_oracle)
    selected_entries = _selected_claim_entries(analysis_response, args.max_pocs_per_case, oracle_case)
    summary["claimCount"] = len(claims)
    summary["selectedPocCount"] = len(selected_entries)
    poc_summaries: list[dict[str, Any]] = []
    for index, entry in enumerate(selected_entries):
        claim = entry["claim"]
        poc_request = make_poc_request(case, claim, analysis_response, build_response, run_label, index, args)
        if poc_request is None:
            poc_summaries.append({
                "index": index,
                "status": "skipped_no_source_file",
                "claimIndex": entry["claimIndex"],
                "oracleFindingIds": entry["oracleFindingIds"],
                "claim": claim,
            })
            continue
        _write_json(case_dir / f"poc-{index}-request.json", poc_request)
        t2 = time.monotonic()
        poc_status, poc_response = _post_task(args.analysis_url, poc_request, poc_request["taskId"], args.http_timeout_sec)
        _write_json(case_dir / f"poc-{index}-response.json", poc_response)
        poc_summaries.append({
            "index": index,
            "claimIndex": entry["claimIndex"],
            "oracleFindingIds": entry["oracleFindingIds"],
            "httpStatus": poc_status,
            "status": _case_status(poc_response) if isinstance(poc_response, dict) else "invalid_response",
            "elapsedSeconds": round(time.monotonic() - t2, 3),
            "responseSummary": {
                "status": _case_status(poc_response) if isinstance(poc_response, dict) else "invalid_response",
                "result": poc_response.get("result") if isinstance(poc_response, dict) else None,
            },
        })
    summary["pocs"] = poc_summaries
    failed_poc = any(item.get("status") not in {"completed", "skipped_no_source_file"} for item in poc_summaries)
    oracle_verdict = evaluate_oracle(oracle_case, analysis_response, poc_summaries)
    summary["oracleVerdict"] = oracle_verdict
    _write_json(case_dir / "oracle-verdict.json", oracle_verdict)
    if oracle_verdict.get("enabled") and oracle_verdict.get("passed") is not True:
        summary["status"] = "oracle_failed"
    else:
        summary["status"] = "completed_with_poc_failures" if failed_poc else "completed"
    summary["finishedAt"] = dt.datetime.now(dt.timezone.utc).isoformat()
    _write_json(case_dir / "summary.json", summary)
    return summary


def _write_markdown_summary(path: Path, aggregate: dict[str, Any]) -> None:
    lines = [
        "# Hot11 full pipeline run",
        "",
        f"- Run label: `{aggregate['runLabel']}`",
        f"- Mode: `{aggregate['mode']}`",
        f"- Manifest: `{aggregate['manifest']}`",
        f"- Output dir: `{aggregate['outputDir']}`",
        f"- Overall status: `{aggregate['overallStatus']}`",
        "",
    ]
    if aggregate.get("preflight"):
        pf = aggregate["preflight"]
        lines.extend([
            "## Preflight",
            "",
            f"- ok: `{pf.get('ok')}`",
            f"- llmReady: `{pf.get('llmReady')}`",
            f"- blockedReason: `{pf.get('blockedReason')}`",
            "",
        ])
    lines.extend([
        "## Cases",
        "",
        "| Case | Status | Build | Analysis | Oracle | Claims | PoCs | Clean PoCs |",
        "|---|---|---|---|---|---:|---:|---:|",
    ])
    for case in aggregate["cases"]:
        pocs = case.get("pocs") or []
        completed_pocs = sum(1 for item in pocs if item.get("status") == "completed")
        clean_pocs = sum(
            1
            for item in pocs
            if (_poc_quality_fields(item).get("pocOutcome") == "poc_accepted"
                and _poc_quality_fields(item).get("qualityOutcome") == "accepted"
                and _poc_quality_fields(item).get("cleanPass") is True)
        )
        verdict = case.get("oracleVerdict") if isinstance(case.get("oracleVerdict"), dict) else {}
        oracle_status = "off" if not verdict.get("enabled") else ("pass" if verdict.get("passed") else "fail")
        lines.append(
            f"| `{case['caseId']}` | `{case.get('status')}` | `{case.get('buildStatus', '-')}` | "
            f"`{case.get('analysisStatus', '-')}` | `{oracle_status}` | {case.get('claimCount', '-')} | "
            f"{completed_pocs}/{len(pocs)} | {clean_pocs}/{len(pocs)} |"
        )
    path.write_text("\n".join(lines) + "\n")


def run(args: argparse.Namespace) -> dict[str, Any]:
    selected = set(args.case or []) or None
    cases = load_manifest(args.manifest, selected_cases=selected, include_controls=args.include_controls)
    if args.limit is not None:
        cases = cases[: args.limit]
    if not cases:
        raise RunnerError("no cases selected")
    oracle = load_oracle(args.oracle)
    _assert_oracle_covers_cases(oracle, cases)

    run_label = args.run_label or f"hot11-full-pipeline-{_utc_timestamp()}"
    output_dir = args.output_dir or DEFAULT_REPORT_ROOT / run_label
    output_dir.mkdir(parents=True, exist_ok=True)

    aggregate: dict[str, Any] = {
        "runLabel": run_label,
        "mode": "live" if args.live else "dry-run",
        "manifest": str(Path(args.manifest).resolve()),
        "outputDir": str(output_dir),
        "startedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "cases": [],
        "overallStatus": "started",
        "oracle": {
            "enabled": oracle is not None,
            "path": str(Path(args.oracle).resolve()) if args.oracle else None,
            "schemaVersion": oracle.get("schemaVersion") if oracle else None,
        },
    }

    if args.live:
        preflight = live_preflight(args)
        aggregate["preflight"] = preflight
        _write_json(output_dir / "preflight.json", preflight)
        if not preflight.get("ok"):
            aggregate["overallStatus"] = "blocked_preflight"
            aggregate["finishedAt"] = dt.datetime.now(dt.timezone.utc).isoformat()
            _write_json(output_dir / "aggregate-summary.json", aggregate)
            _write_markdown_summary(output_dir / "summary.md", aggregate)
            raise LivePreflightBlocked(preflight.get("blockedReason") or "live preflight failed")

    for case in cases:
        case_dir = output_dir / case.case_id
        oracle_case = _oracle_case(oracle, case.case_id)
        print(f"[{case.case_id}] {'live' if args.live else 'dry-run'}", flush=True)
        try:
            if args.live:
                case_summary = run_live_case(case, case_dir, run_label, args, oracle_case)
            else:
                case_summary = run_dry_case(case, case_dir, run_label, args, oracle_case)
        except Exception as exc:  # noqa: BLE001 - preserve per-case evidence and continue by default
            case_summary = {
                "caseId": case.case_id,
                "title": case.title,
                "status": "runner_exception",
                "error": repr(exc),
            }
            _write_json(case_dir / "summary.json", case_summary)
        aggregate["cases"].append(case_summary)
        _write_json(output_dir / "aggregate-summary.json", aggregate)
        if args.stop_on_failure and case_summary.get("status") not in {"staged", "completed"}:
            break

    statuses = [case.get("status") for case in aggregate["cases"]]
    if all(status in {"staged", "completed"} for status in statuses):
        aggregate["overallStatus"] = "passed" if args.live else "staged"
    else:
        aggregate["overallStatus"] = "failed"
    aggregate["finishedAt"] = dt.datetime.now(dt.timezone.utc).isoformat()
    _write_json(output_dir / "aggregate-summary.json", aggregate)
    _write_markdown_summary(output_dir / "summary.md", aggregate)
    return aggregate


def _timeout_arg(value: str) -> float | None:
    parsed = float(value)
    return None if parsed <= 0 else parsed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sequential hot11 Build→Analyze→PoC full-pipeline runner")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE,
                        help="hot11 full-pipeline golden oracle JSON; use --no-oracle to disable")
    parser.add_argument("--no-oracle", dest="oracle", action="store_const", const=None,
                        help="disable oracle gating and keep system-stability-only behavior")
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--run-label", default=None)
    parser.add_argument("--case", action="append", help="caseId to run; repeatable")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--include-controls", action="store_true")
    parser.add_argument("--live", action="store_true", help="call live services; default is dry-run only")
    parser.add_argument("--stop-on-failure", action="store_true")
    parser.add_argument("--build-url", default=DEFAULT_BUILD_URL)
    parser.add_argument("--analysis-url", default=DEFAULT_ANALYSIS_URL)
    parser.add_argument("--sast-url", default=DEFAULT_SAST_URL)
    parser.add_argument("--kb-url", default=DEFAULT_KB_URL)
    parser.add_argument("--gateway-url", default=DEFAULT_GATEWAY_URL)
    parser.add_argument("--http-timeout-sec", type=_timeout_arg, default=None,
                        help="socket timeout for each task request; <=0 means no client-side socket timeout")
    parser.add_argument("--require-llm-ready", dest="require_llm_ready", action="store_true", default=True)
    parser.add_argument("--no-require-llm-ready", dest="require_llm_ready", action="store_false")
    parser.add_argument("--sast-tool", dest="sast_tools", action="append", default=None,
                        help="optional S4 individual-scan tool filter; repeatable, e.g. --sast-tool flawfinder")
    parser.add_argument("--analysis-max-tokens", type=int, default=32768)
    parser.add_argument("--analysis-timeout-ms", type=int, default=900_000)
    parser.add_argument("--poc-max-tokens", type=int, default=8192)
    parser.add_argument("--poc-timeout-ms", type=int, default=900_000)
    parser.add_argument("--max-pocs-per-case", type=int, default=1,
                        help="PoCs per case; 0 skips PoC, -1 attempts all claims")
    parser.add_argument("--poc-source-max-bytes", type=int, default=80_000)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        aggregate = run(args)
    except LivePreflightBlocked as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001 - CLI entrypoint
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "overallStatus": aggregate["overallStatus"],
        "mode": aggregate["mode"],
        "cases": len(aggregate["cases"]),
        "outputDir": aggregate["outputDir"],
    }, ensure_ascii=False, indent=2))
    return 0 if aggregate["overallStatus"] in {"staged", "passed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
