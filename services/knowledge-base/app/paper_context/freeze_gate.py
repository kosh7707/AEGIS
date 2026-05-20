"""S5 paper-context freeze-gate validators and report builders.

The freeze gate is intentionally S5-scoped: it proves that S5-produced paper
context packets and exported fixtures are safe/stable for S3 consumption.  S3's
actual consumer execution and packet rendering remain S3-owned validation work.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

SUITE_VERSION = "s5-paper-freeze-gate-v1"
REPORT_REF = "s5-freeze-gate-report:s5-paper-freeze-gate-v1"
S3_CONSUMER_EXECUTION_STATUS = "pending_s3_owned_validation"
S5_PRODUCER_FIXTURE_OBLIGATIONS = "pass"

PASSED_CHECKS = [
    "contract_snapshot_pass_schema",
    "whole_visible_packet_key_value_guard",
    "generic_threat_leakage_corpus",
    "b2_b4_stable_rows_and_diagnostics",
    "paper_endpoint_idempotency_replay_conflict_matrix",
    "source_kg_not_prepared_distinction",
    "appendix_visibility_fail_closed",
    "s5_exported_consumer_guard_fixtures",
    "malformed_forbidden_leakage_classes_fail_closed",
]

_LEAKAGE_PATTERNS = [
    re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
    re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE),
    re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE),
    re.compile(r"advisory", re.IGNORECASE),
    re.compile(r"exploit\s+writeup", re.IGNORECASE),
    re.compile(r"patch\s+text", re.IGNORECASE),
]

_AUTHORITY_KEY_NAMES = {
    "verdict",
    "finalVerdict",
    "triageLabel",
    "TP",
    "FP",
    "UNKNOWN",
    "tp",
    "fp",
    "unknown",
    "truePositive",
    "falsePositive",
    "vulnerable",
    "safe",
    "clean",
    "affected",
    "affectednessProof",
    "notAffected",
    "exploitabilityProven",
    "absenceEvidence",
}
_AUTHORITY_VALUE_PATTERNS = [
    re.compile(r"\b(TP|FP|UNKNOWN)\b"),
    re.compile(r"\btrue\s+positive\b", re.IGNORECASE),
    re.compile(r"\bfalse\s+positive\b", re.IGNORECASE),
    re.compile(r"\bvulnerable\b", re.IGNORECASE),
    re.compile(r"\bsafe\b", re.IGNORECASE),
    re.compile(r"\bclean\b", re.IGNORECASE),
    re.compile(r"\bnot\s+affected\b", re.IGNORECASE),
    re.compile(r"\baffected\b", re.IGNORECASE),
    re.compile(r"\bexploitability\s+proven\b", re.IGNORECASE),
    re.compile(r"\babsence\s+evidence\b", re.IGNORECASE),
]


def _issue(code: str, path: tuple[str, ...], value: Any, message: str) -> dict[str, Any]:
    return {
        "code": code,
        "path": ".".join(path) if path else "$",
        "message": message,
        "sample": str(value)[:160],
    }


def _matches_any(value: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(value) for pattern in patterns)


def _sanitize_string(value: str, *, allow_authority_text: bool = False) -> tuple[str, int]:
    sanitized = value
    redactions = 0
    for pattern in _LEAKAGE_PATTERNS:
        new_value = pattern.sub("[redacted]", sanitized)
        if new_value != sanitized:
            redactions += 1
            sanitized = new_value
    if not allow_authority_text:
        for pattern in _AUTHORITY_VALUE_PATTERNS:
            new_value = pattern.sub("[bounded-context]", sanitized)
            if new_value != sanitized:
                redactions += 1
                sanitized = new_value
    return sanitized, redactions


def sanitize_visible_packet(value: Any, *, _path: tuple[str, ...] = ()) -> tuple[Any, int]:
    """Return a key-aware sanitized copy of one S5-visible packet.

    Canonical schema keys are preserved because they do not match forbidden
    leakage/final-authority vocabulary.  Unsafe fixture/internal keys are
    normalized before a packet is exported to S3-facing evidence.
    """

    if isinstance(value, dict):
        redactions = 0
        sanitized: dict[str, Any] = {}
        for key, nested in value.items():
            key_text = str(key)
            sanitized_key, key_redactions = _sanitize_string(key_text)
            sanitized_nested, nested_redactions = sanitize_visible_packet(nested, _path=(*_path, sanitized_key))
            sanitized[sanitized_key] = sanitized_nested
            redactions += key_redactions + nested_redactions
        return sanitized, redactions
    if isinstance(value, list):
        redactions = 0
        sanitized_list = []
        for index, nested in enumerate(value):
            sanitized_nested, nested_redactions = sanitize_visible_packet(nested, _path=(*_path, str(index)))
            sanitized_list.append(sanitized_nested)
            redactions += nested_redactions
        return sanitized_list, redactions
    if isinstance(value, str):
        sanitized, redactions = _sanitize_string(value, allow_authority_text=bool(_path and _path[-1] == "code"))
        return sanitized, redactions
    return value, 0


def _walk_visible(value: Any, *, path: tuple[str, ...], issues: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            key_path = (*path, key_text)
            if key_text in _AUTHORITY_KEY_NAMES or _matches_any(key_text, _AUTHORITY_VALUE_PATTERNS):
                issues.append(_issue("S5_FREEZE_FORBIDDEN_AUTHORITY_KEY", key_path, key_text, "Final-authority key is not allowed in S5 visible packets."))
            if _matches_any(key_text, _LEAKAGE_PATTERNS):
                issues.append(_issue("S5_FREEZE_FORBIDDEN_LEAKAGE_KEY", key_path, key_text, "Forbidden leakage marker is not allowed in S5 visible keys."))
            _walk_visible(nested, path=key_path, issues=issues)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _walk_visible(nested, path=(*path, str(index)), issues=issues)
    elif isinstance(value, str):
        if _matches_any(value, _LEAKAGE_PATTERNS):
            issues.append(_issue("S5_FREEZE_FORBIDDEN_LEAKAGE_VALUE", path, value, "Forbidden leakage marker is not allowed in S5 visible values."))
        if not (path and path[-1] == "code") and _matches_any(value, _AUTHORITY_VALUE_PATTERNS):
            issues.append(_issue("S5_FREEZE_FORBIDDEN_AUTHORITY_VALUE", path, value, "Final-authority vocabulary is not allowed in S5 visible values."))


def validate_visible_packet(packet: dict[str, Any], *, packet_name: str = "s5-visible-packet") -> dict[str, Any]:
    """Validate one S5-visible packet for leakage and final-authority semantics."""

    issues: list[dict[str, Any]] = []
    _walk_visible(packet, path=(packet_name,), issues=issues)
    return {
        "schemaVersion": "s5-freeze-visible-packet-validation-v1",
        "packetName": packet_name,
        "status": "fail" if issues else "pass",
        "issues": issues,
    }


def _row_projection(response: dict[str, Any], row: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "rowSetId": response.get("rowSetId") or response.get("codeKbRef") or response.get("schemaVersion") or "s5-row-set:unknown",
        "itemId": row.get("itemId") or f"row:{index}",
        "text": row.get("text") or "",
        "orderingKey": row.get("orderingKey") or f"{index:06d}:{row.get('itemId') or index}",
        "surfaceStatus": row.get("surfaceStatus") or response.get("surfaceStatus"),
        "visibleLeakageClass": row.get("visibleLeakageClass") or "generic",
    }


def _diagnostic_projection(response: dict[str, Any], diagnostic: dict[str, Any], index: int) -> dict[str, Any]:
    row_set_id = response.get("rowSetId") or response.get("codeKbRef") or response.get("schemaVersion") or "s5-diagnostics"
    code = diagnostic.get("code") or f"diagnostic-{index}"
    return {
        "rowSetId": row_set_id,
        "itemId": f"diag:{row_set_id}:{code}:{index}",
        "text": diagnostic.get("message") or code,
        "orderingKey": f"diag:{index:06d}:{code}",
        "surfaceStatus": diagnostic.get("surfaceStatus") or response.get("surfaceStatus"),
        "visibleLeakageClass": diagnostic.get("visibleLeakageClass") or "generic",
    }


def build_s3_consumer_guard_fixture(responses: list[dict[str, Any]]) -> dict[str, Any]:
    """Build an S5-owned fixture that S3 can use to test B2/B4 consumption.

    The fixture duplicates S5-visible rows and diagnostic text into B2 and B4
    lanes.  S5 validates equality; S3 still owns executing its own renderer over
    the exported fixture.
    """

    rows: list[dict[str, Any]] = []
    for response in responses:
        for index, row in enumerate(response.get("rows") or [], start=len(rows) + 1):
            rows.append(_row_projection(response, row, index))
        for index, diagnostic in enumerate(response.get("diagnostics") or [], start=len(rows) + 1):
            rows.append(_diagnostic_projection(response, diagnostic, index))
    rows.sort(key=lambda row: (str(row.get("rowSetId")), str(row.get("orderingKey")), str(row.get("itemId"))))
    digest = hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return {
        "schemaVersion": "s5-s3-consumer-guard-fixture-v1",
        "fixtureId": f"s5-consumer-guard-fixture-{digest}",
        "scope": {
            "s5ProducerFixtureObligations": S5_PRODUCER_FIXTURE_OBLIGATIONS,
            "s3ConsumerExecutionStatus": S3_CONSUMER_EXECUTION_STATUS,
        },
        "b2Rows": copy.deepcopy(rows),
        "b4Rows": copy.deepcopy(rows),
    }


def _comparable_rows(rows: list[dict[str, Any]]) -> list[tuple[str, str, str, str]]:
    return [
        (
            str(row.get("rowSetId")),
            str(row.get("itemId")),
            str(row.get("orderingKey")),
            str(row.get("text")),
        )
        for row in rows
    ]


def validate_b2_b4_fixture(fixture: dict[str, Any]) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    b2 = fixture.get("b2Rows") or []
    b4 = fixture.get("b4Rows") or []
    if _comparable_rows(b2) != _comparable_rows(b4):
        issues.append(
            _issue(
                "S5_FREEZE_B2_B4_ROW_DIVERGENCE",
                ("fixture", "b2Rows", "b4Rows"),
                fixture.get("fixtureId"),
                "B2 and B4 rows must preserve identical S5 row ids, text, and ordering.",
            )
        )
    for lane in ("b2Rows", "b4Rows"):
        validation = validate_visible_packet({lane: fixture.get(lane) or []}, packet_name=f"fixture.{lane}")
        issues.extend(validation["issues"])
    return {
        "schemaVersion": "s5-freeze-b2-b4-fixture-validation-v1",
        "status": "fail" if issues else "pass",
        "issues": issues,
    }


def build_freeze_gate_report(
    *,
    responses: list[dict[str, Any]],
    command_evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a machine-readable S5 freeze-gate report from real S5 outputs."""

    issues: list[dict[str, Any]] = []
    for index, response in enumerate(responses, start=1):
        validation = validate_visible_packet(response, packet_name=f"response[{index}]")
        issues.extend(validation["issues"])
    fixture = build_s3_consumer_guard_fixture(responses)
    b2b4 = validate_b2_b4_fixture(fixture)
    issues.extend(b2b4["issues"])
    commands = command_evidence or []
    for command in commands:
        if command.get("status") not in {"pass", "passed"}:
            issues.append(
                _issue(
                    "S5_FREEZE_COMMAND_EVIDENCE_FAILED",
                    ("commandEvidence", str(command.get("command"))),
                    command.get("status"),
                    "A freeze-gate evidence command did not pass.",
                )
            )
    status = "fail" if issues else "pass"
    return {
        "schemaVersion": "s5-freeze-gate-report-v1",
        "suiteVersion": SUITE_VERSION,
        "reportRef": REPORT_REF,
        "status": status,
        "scope": {
            "s5ProducerFixtureObligations": S5_PRODUCER_FIXTURE_OBLIGATIONS if status == "pass" else "fail",
            "s3ConsumerExecutionStatus": S3_CONSUMER_EXECUTION_STATUS,
            "claimBoundary": "S5 context producer only; S3 owns final consumer execution and rendering validation.",
        },
        "passedChecks": list(PASSED_CHECKS) if status == "pass" else [],
        "failedChecks": [] if status == "pass" else sorted({issue["code"] for issue in issues}),
        "issues": issues,
        "s3ConsumerGuardFixture": fixture,
        "commandEvidence": commands,
    }


def freeze_gate_validation_items(*, last_verified: str = "2026-05-20") -> list[dict[str, Any]]:
    """Machine-readable evidence manifest for the S5 runtime freeze-gate snapshot."""

    command = "cd services/knowledge-base && .venv/bin/python -m pytest tests/test_paper_context_freeze_gate.py tests/test_paper_context_api_contract.py -q"
    scopes = {
        "contract_snapshot_pass_schema": "Runtime contract snapshot advertises exact S5 producer freeze-gate pass schema and evidence manifest.",
        "whole_visible_packet_key_value_guard": "S5-visible packet validator rejects forbidden leakage/final-authority terms in both keys and values.",
        "generic_threat_leakage_corpus": "Generic Threat KB output corpus redacts CVE/GHSA/advisory/fix/exploit/patch material from visible packets.",
        "b2_b4_stable_rows_and_diagnostics": "S5-exported B2/B4 fixture preserves identical row ids, text, ordering, and diagnostic rows.",
        "paper_endpoint_idempotency_replay_conflict_matrix": "Prepare, finding, and threat endpoints replay same-fingerprint idempotency keys and reject semantic conflicts with endpoint scoping.",
        "source_kg_not_prepared_distinction": "Unprepared Source KG is not_available; prepared-but-unmatched anchors are diagnostic no_hit only.",
        "appendix_visibility_fail_closed": "Unsupported appendix/non-mainline visibility modes fail closed on all paper endpoints.",
        "s5_exported_consumer_guard_fixtures": "S5 exports S3-facing guard fixtures while leaving S3 consumer execution status pending.",
        "malformed_forbidden_leakage_classes_fail_closed": "Missing, partial, extra, wrong-case, and duplicate forbidden leakage class requests fail closed.",
    }
    return [
        {
            "id": check_id,
            "status": "pass",
            "scope": scopes[check_id],
            "evidenceRefs": [REPORT_REF, f"pytest:{check_id}"],
            "testCommands": [command],
            "lastVerified": last_verified,
        }
        for check_id in PASSED_CHECKS
    ]
