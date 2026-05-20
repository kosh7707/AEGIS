from __future__ import annotations

import importlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

from app.ledger.repository import SQLiteLedgerRepository

from test_paper_context_api_contract import (  # reuse hard-now fixtures intentionally
    FORBIDDEN_LEAKAGE_CLASSES,
    FORBIDDEN_LEAKAGE_PATTERNS,
    HEADERS,
    _assert_no_final_authority,
    _assert_no_forbidden_leakage,
    _base_prepare_payload,
    _finding_payload,
    _prepare_with_ingest_payload,
    _seed_prepare,
    _threat_payload,
    client,
    paper_repo,
)

EXPECTED_FREEZE_CHECKS = {
    "contract_snapshot_pass_schema",
    "whole_visible_packet_key_value_guard",
    "generic_threat_leakage_corpus",
    "b2_b4_stable_rows_and_diagnostics",
    "paper_endpoint_idempotency_replay_conflict_matrix",
    "source_kg_not_prepared_distinction",
    "appendix_visibility_fail_closed",
    "s5_exported_consumer_guard_fixtures",
    "malformed_forbidden_leakage_classes_fail_closed",
}


def _paper_context_api():
    return importlib.import_module("app.routers.paper_context_api")


def _visible_packet_strings(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _assert_redaction_diagnostic(body: dict[str, Any]) -> None:
    assert any(diag.get("code") == "S5_PAPER_FORBIDDEN_LEAKAGE_REDACTED" for diag in body.get("diagnostics", [])), body


def test_freeze_gate_contract_snapshot_advertises_pass_and_s5_owned_scope():
    resp = client.get("/v1/contracts/paper-context", headers={"X-Request-Id": "req-freeze-contract"})

    assert resp.status_code == 200, resp.text
    freeze = resp.json()["freezeGate"]
    assert freeze["s5FreezeGate"] == "pass"
    assert freeze["s5VisiblePacketSchemaFinalized"] is True
    assert freeze["validationSuiteVersion"] == "s5-paper-freeze-gate-v1"
    assert freeze["validationReportRef"].startswith("s5-freeze-gate-report:")
    assert freeze["appendixVisibilityPolicy"] == "fail_closed_unsupported"
    assert freeze["s5ProducerFixtureObligations"] == "pass"
    assert freeze["s3ConsumerExecutionStatus"] == "pending_s3_owned_validation"
    assert freeze["idempotencyDurability"] == "ledger_backed_all_paper_endpoints"
    assert set(freeze["passedChecks"]) == EXPECTED_FREEZE_CHECKS
    assert freeze["missingValidationItems"] == []
    validation_items = freeze["validationItems"]
    assert {item["id"] for item in validation_items} == EXPECTED_FREEZE_CHECKS
    for item in validation_items:
        assert item["status"] == "pass"
        assert item["scope"]
        assert item["evidenceRefs"]
        assert item["testCommands"]
        assert item["lastVerified"]


def test_unprepared_source_kg_is_not_available_while_prepared_anchor_miss_is_no_hit(paper_repo):
    unprepared_payload = _finding_payload(
        requestId="s3-s5-finding-context-unprepared",
        idempotencyKey="case-001:s4-finding-unprepared:s5:finding-context:v1",
        sourceKgRef="s5-source-kg:case-001:target-001:missing",
        codeKbRef="s5-code-kb:case-001:target-001:missing",
        findingId="s4-finding-unprepared",
    )
    unprepared_payload["finding"]["findingId"] = "s4-finding-unprepared"

    unprepared = client.post(
        "/v1/paper/finding-context/retrieve",
        json=unprepared_payload,
        headers={"X-Request-Id": "s3-s5-finding-context-unprepared"},
    )

    assert unprepared.status_code == 200, unprepared.text
    unprepared_body = unprepared.json()
    assert unprepared_body["surfaceStatus"] == "not_available"
    assert unprepared_body["rows"] == []
    assert unprepared_body["diagnostics"][0]["code"] == "S5_PAPER_SOURCE_KG_NOT_PREPARED"
    assert unprepared_body["diagnostics"][0]["negativeEvidenceAllowed"] is False

    _seed_prepare(paper_repo)
    no_hit_payload = _finding_payload(
        requestId="s3-s5-finding-context-prepared-no-hit",
        idempotencyKey="case-001:s4-finding-prepared-no-hit:s5:finding-context:v1",
        findingId="s4-finding-prepared-no-hit",
    )
    no_hit_payload["finding"] = {
        **no_hit_payload["finding"],
        "findingId": "s4-finding-prepared-no-hit",
        "sourceAnchors": [{"displayPath": "ssl/not-present.c", "symbolName": "not_present", "lineStart": 1, "lineEnd": 2}],
    }

    no_hit = client.post(
        "/v1/paper/finding-context/retrieve",
        json=no_hit_payload,
        headers={"X-Request-Id": "s3-s5-finding-context-prepared-no-hit"},
    )

    assert no_hit.status_code == 200, no_hit.text
    no_hit_body = no_hit.json()
    assert no_hit_body["surfaceStatus"] == "no_hit"
    assert no_hit_body["diagnostics"][0]["code"] == "S5_PAPER_CONTEXT_NO_HIT"
    _assert_no_final_authority(no_hit_body)


@pytest.mark.parametrize(
    "payload_fragment",
    [
        "CVE-2099-4242",
        "GHSA-abcd-efgh-ijkl",
        "0123456789abcdef0123456789abcdef01234567",
        "advisory",
        "exploit writeup",
        "patch text",
    ],
)
def test_generic_threat_leakage_corpus_is_redacted_from_live_outputs(paper_repo, payload_fragment: str):
    payload = _threat_payload(
        requestId=f"s3-s5-threat-freeze-{abs(hash(payload_fragment))}",
        idempotencyKey=f"case-001:s4-finding-001:s5:generic-threat:freeze:{abs(hash(payload_fragment))}",
        apiNames=["memcpy", payload_fragment],
        libraryIdentity={
            "name": f"openssl {payload_fragment}",
            "version": "1.0.1f",
            "confidence": "observed_by_s4",
            "repoUrl": f"https://example.invalid/{payload_fragment}",
        },
        topK=10,
    )

    resp = client.post(
        "/v1/paper/threat-context/generic",
        json=payload,
        headers={"X-Request-Id": payload["requestId"]},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["surfaceStatus"] in {"partial", "produced", "no_hit"}
    _assert_no_forbidden_leakage(body)
    _assert_no_final_authority(body)
    _assert_redaction_diagnostic(body)


def test_whole_visible_packet_validator_rejects_forbidden_keys_and_values():
    from app.paper_context.freeze_gate import validate_visible_packet

    malicious = {
        "schemaVersion": "s5-retrieve-generic-threat-context-response-v1",
        "CVE-2099-4242": "nested forbidden leakage key",
        "rows": [
            {
                "itemId": "row-1",
                "visibleLeakageClass": "generic",
                "text": "CVE-2099-4242 proves vulnerable affected code",
                "finalVerdict": "TP",
                "sourceEvidence": {
                    "advisoryRef": "GHSA-abcd-efgh-ijkl",
                    "displayRef": "patch text exploit writeup",
                    "risk": "affected",
                },
            }
        ],
        "retrievalTrace": {"patch text": "0123456789abcdef0123456789abcdef01234567"},
        "diagnostics": [{"code": "S5_PAPER_CONTEXT_NO_HIT", "message": "patch text exploit writeup", "metadata": {"safe": True}}],
    }

    report = validate_visible_packet(malicious, packet_name="malicious-freeze-fixture")

    assert report["status"] == "fail"
    assert {issue["code"] for issue in report["issues"]} >= {
        "S5_FREEZE_FORBIDDEN_LEAKAGE_VALUE",
        "S5_FREEZE_FORBIDDEN_LEAKAGE_KEY",
        "S5_FREEZE_FORBIDDEN_AUTHORITY_KEY",
        "S5_FREEZE_FORBIDDEN_AUTHORITY_VALUE",
    }


def test_whole_visible_packet_validator_rejects_uppercase_final_authority_keys():
    from app.paper_context.freeze_gate import validate_visible_packet

    report = validate_visible_packet(
        {
            "TP": "context only",
            "FP": "context only",
            "UNKNOWN": "context only",
        },
        packet_name="uppercase-authority-keys",
    )

    assert report["status"] == "fail"
    issues_by_path = {issue["path"]: issue["code"] for issue in report["issues"]}
    assert issues_by_path["uppercase-authority-keys.TP"] == "S5_FREEZE_FORBIDDEN_AUTHORITY_KEY"
    assert issues_by_path["uppercase-authority-keys.FP"] == "S5_FREEZE_FORBIDDEN_AUTHORITY_KEY"
    assert issues_by_path["uppercase-authority-keys.UNKNOWN"] == "S5_FREEZE_FORBIDDEN_AUTHORITY_KEY"


def test_visible_packet_sanitizer_is_key_aware_and_preserves_canonical_schema_keys():
    from app.paper_context.freeze_gate import sanitize_visible_packet, validate_visible_packet

    packet = {
        "schemaVersion": "s5-retrieve-generic-threat-context-response-v1",
        "surfaceStatus": "produced",
        "producerProvenance": {"component": "s5-knowledge-base", "patch text": "CVE-2099-4242"},
        "retrievalTrace": {"orderingPolicy": "s5-paper-stable-row-order-v1"},
        "rows": [
            {
                "itemId": "row-1",
                "sourceEvidence": {"displayRef": "ssl/CVE-2099-4242_patch.c", "safe": "TP"},
                "text": "GHSA-abcd-efgh-ijkl exploit writeup says vulnerable",
                "visibleLeakageClass": "generic",
            }
        ],
        "diagnostics": [{"code": "S5_PAPER_CONTEXT_NO_HIT", "metadata": {"advisory": "patch text"}}],
    }

    sanitized, redaction_count = sanitize_visible_packet(packet)

    assert redaction_count >= 1
    assert {"schemaVersion", "surfaceStatus", "producerProvenance", "retrievalTrace", "rows", "diagnostics"} <= set(sanitized)
    assert validate_visible_packet(sanitized, packet_name="sanitized")["status"] == "pass"
    rendered = _visible_packet_strings(sanitized)
    for pattern in FORBIDDEN_LEAKAGE_PATTERNS:
        assert pattern.search(rendered) is None


def test_b2_b4_fixture_validator_accepts_real_rows_and_rejects_divergence(paper_repo):
    from app.paper_context.freeze_gate import build_s3_consumer_guard_fixture, validate_b2_b4_fixture

    _seed_prepare(paper_repo)
    resp = client.post(
        "/v1/paper/finding-context/retrieve",
        json=_finding_payload(),
        headers={"X-Request-Id": "s3-s5-finding-context-001"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    fixture = build_s3_consumer_guard_fixture([body])
    assert validate_b2_b4_fixture(fixture)["status"] == "pass"

    divergent = deepcopy(fixture)
    divergent["b4Rows"] = list(reversed(divergent["b4Rows"]))
    if divergent["b4Rows"]:
        divergent["b4Rows"][0]["text"] = divergent["b4Rows"][0]["text"] + " extra B4-only context"

    divergence_report = validate_b2_b4_fixture(divergent)
    assert divergence_report["status"] == "fail"
    assert any(issue["code"] == "S5_FREEZE_B2_B4_ROW_DIVERGENCE" for issue in divergence_report["issues"])


@pytest.mark.parametrize(
    ("endpoint", "payload_factory", "mutate_semantic"),
    [
        (
            "/v1/paper/code-kb/prepare",
            _prepare_with_ingest_payload,
            lambda payload: payload["sourceContext"]["scope"]["includePaths"].append("crypto/"),
        ),
        (
            "/v1/paper/finding-context/retrieve",
            _finding_payload,
            lambda payload: payload.__setitem__("topK", 1),
        ),
        (
            "/v1/paper/threat-context/generic",
            _threat_payload,
            lambda payload: payload["apiNames"].append("strcpy"),
        ),
    ],
)
def test_ledger_backed_idempotency_survives_process_cache_reset_for_all_paper_endpoints(
    tmp_path,
    endpoint: str,
    payload_factory,
    mutate_semantic,
):
    paper_context_api = _paper_context_api()
    db_path = tmp_path / "s5-ledger.sqlite"
    repo = SQLiteLedgerRepository(f"sqlite:///{db_path}")
    repo.initialize()
    paper_context_api.reset_paper_context_state()
    paper_context_api.set_ledger_repository(repo)
    try:
        prep = client.post("/v1/paper/code-kb/prepare", json=_prepare_with_ingest_payload(), headers=HEADERS)
        assert prep.status_code == 200, prep.text

        payload = payload_factory()
        payload["requestId"] = f"{payload['requestId']}-ledger-001"
        payload["idempotencyKey"] = f"shared-ledger-key:{endpoint}:freeze"
        first = client.post(endpoint, json=payload, headers={"X-Request-Id": payload["requestId"]})
        assert first.status_code == 200, first.text

        paper_context_api.reset_paper_context_state()
        fresh_repo = SQLiteLedgerRepository(f"sqlite:///{db_path}")
        fresh_repo.initialize()
        paper_context_api.set_ledger_repository(fresh_repo)

        replay_payload = deepcopy(payload)
        replay_payload["requestId"] = f"{payload['requestId']}-replay-002"
        replay = client.post(endpoint, json=replay_payload, headers={"X-Request-Id": replay_payload["requestId"]})
        assert replay.status_code == 200, replay.text
        assert replay.json()["requestId"] == replay_payload["requestId"]
        for stable_key in {"codeKbRunId", "s5ProducerRunId", "retrievalRunId", "rowSetId"} & set(first.json()):
            assert replay.json()[stable_key] == first.json()[stable_key]
        if "rows" in first.json():
            assert [row["itemId"] for row in replay.json()["rows"]] == [row["itemId"] for row in first.json()["rows"]]

        changed = deepcopy(replay_payload)
        mutate_semantic(changed)
        conflict = client.post(endpoint, json=changed, headers={"X-Request-Id": changed["requestId"]})
        assert conflict.status_code == 409, conflict.text
        assert conflict.json()["errorDetail"]["code"] == "S5_PAPER_IDEMPOTENCY_CONFLICT"

        observations = fresh_repo.list_provider_observations(provider="s5-paper-context-idempotency")
        assert any(
            obs["subjectKey"] == f"{_endpoint_subject(endpoint)}:{payload['idempotencyKey']}"
            and obs["payload"].get("schemaVersion") == "s5-paper-idempotency-record-v1"
            for obs in observations
        )
    finally:
        paper_context_api.reset_paper_context_state()
        paper_context_api.set_ledger_repository(None)


def _endpoint_subject(path: str) -> str:
    return {
        "/v1/paper/code-kb/prepare": "prepare_code_kb",
        "/v1/paper/finding-context/retrieve": "retrieve_finding_context",
        "/v1/paper/threat-context/generic": "retrieve_generic_threat_context",
    }[path]


def test_same_idempotency_key_is_endpoint_scoped(paper_repo):
    shared_key = "case-001:shared-idempotency-key:freeze"
    prepare_payload = _prepare_with_ingest_payload(idempotencyKey=shared_key, requestId="s3-s5-shared-prepare")
    finding_payload = _finding_payload(idempotencyKey=shared_key, requestId="s3-s5-shared-finding")
    threat_payload = _threat_payload(idempotencyKey=shared_key, requestId="s3-s5-shared-threat")

    prepare = client.post("/v1/paper/code-kb/prepare", json=prepare_payload, headers={"X-Request-Id": prepare_payload["requestId"]})
    finding = client.post("/v1/paper/finding-context/retrieve", json=finding_payload, headers={"X-Request-Id": finding_payload["requestId"]})
    threat = client.post("/v1/paper/threat-context/generic", json=threat_payload, headers={"X-Request-Id": threat_payload["requestId"]})

    assert prepare.status_code == finding.status_code == threat.status_code == 200
    assert prepare.json()["schemaVersion"] == "s5-prepare-code-kb-response-v1"
    assert finding.json()["schemaVersion"] == "s5-retrieve-finding-context-response-v1"
    assert threat.json()["schemaVersion"] == "s5-retrieve-generic-threat-context-response-v1"


@pytest.mark.parametrize(
    ("path", "payload_factory"),
    [
        ("/v1/paper/code-kb/prepare", _prepare_with_ingest_payload),
        ("/v1/paper/finding-context/retrieve", _finding_payload),
        ("/v1/paper/threat-context/generic", _threat_payload),
    ],
)
@pytest.mark.parametrize(
    "mutation",
    ["missing", "partial", "extra", "wrong_case", "duplicate"],
)
def test_malformed_forbidden_leakage_classes_fail_closed_for_all_paper_endpoints(
    paper_repo,
    path: str,
    payload_factory,
    mutation: str,
):
    if path != "/v1/paper/code-kb/prepare":
        _seed_prepare(paper_repo)
    payload = payload_factory()
    payload["requestId"] = f"{payload['requestId']}-forbidden-{mutation}"
    payload["idempotencyKey"] = f"{payload['idempotencyKey']}:forbidden:{mutation}"
    if mutation == "missing":
        payload.pop("forbiddenLeakageClasses")
    elif mutation == "partial":
        payload["forbiddenLeakageClasses"] = FORBIDDEN_LEAKAGE_CLASSES[:-1]
    elif mutation == "extra":
        payload["forbiddenLeakageClasses"] = [*FORBIDDEN_LEAKAGE_CLASSES, "vendor_patch_note"]
    elif mutation == "wrong_case":
        payload["forbiddenLeakageClasses"] = [item.upper() for item in FORBIDDEN_LEAKAGE_CLASSES]
    elif mutation == "duplicate":
        payload["forbiddenLeakageClasses"] = [*FORBIDDEN_LEAKAGE_CLASSES, FORBIDDEN_LEAKAGE_CLASSES[0]]

    resp = client.post(path, json=payload, headers={"X-Request-Id": payload["requestId"]})

    assert resp.status_code == 422, resp.text
    assert resp.json()["errorDetail"]["code"] in {"S5_PAPER_SCHEMA_INVALID", "S5_PAPER_FORBIDDEN_LEAKAGE_CLASSES_REQUIRED"}


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/v1/paper/code-kb/prepare", _prepare_with_ingest_payload()),
        ("/v1/paper/finding-context/retrieve", _finding_payload()),
        ("/v1/paper/threat-context/generic", _threat_payload()),
    ],
)
def test_appendix_visibility_is_frozen_as_fail_closed_unsupported(paper_repo, path: str, payload: dict[str, Any]):
    if path != "/v1/paper/code-kb/prepare":
        _seed_prepare(paper_repo)
    payload = deepcopy(payload)
    payload["requestId"] = f"{payload['requestId']}-appendix"
    payload["idempotencyKey"] = f"{payload['idempotencyKey']}:appendix"
    payload["visibilityMode"] = "appendix_registered"

    resp = client.post(path, json=payload, headers={"X-Request-Id": payload["requestId"]})

    assert resp.status_code == 422, resp.text
    assert resp.json()["errorDetail"]["code"] == "S5_PAPER_VISIBILITY_MODE_UNSUPPORTED"


def test_freeze_gate_report_passes_for_real_s5_owned_fixtures(paper_repo):
    from app.paper_context.freeze_gate import build_freeze_gate_report

    prepare_body = _seed_prepare(paper_repo)
    finding_resp = client.post(
        "/v1/paper/finding-context/retrieve",
        json=_finding_payload(),
        headers={"X-Request-Id": "s3-s5-finding-context-001"},
    )
    no_hit_payload = _finding_payload(
        requestId="s3-s5-finding-context-report-no-hit",
        idempotencyKey="case-001:s4-finding-report-no-hit:s5:finding-context:v1",
        findingId="s4-finding-report-no-hit",
    )
    no_hit_payload["finding"] = {
        **no_hit_payload["finding"],
        "findingId": "s4-finding-report-no-hit",
        "sourceAnchors": [{"displayPath": "ssl/missing-report.c", "symbolName": "missing_report", "lineStart": 1, "lineEnd": 2}],
    }
    no_hit_resp = client.post(
        "/v1/paper/finding-context/retrieve",
        json=no_hit_payload,
        headers={"X-Request-Id": no_hit_payload["requestId"]},
    )
    threat_resp = client.post(
        "/v1/paper/threat-context/generic",
        json=_threat_payload(),
        headers={"X-Request-Id": "s3-s5-threat-context-001"},
    )
    assert finding_resp.status_code == no_hit_resp.status_code == threat_resp.status_code == 200

    report = build_freeze_gate_report(
        responses=[prepare_body, finding_resp.json(), no_hit_resp.json(), threat_resp.json()],
        command_evidence=[
            {
                "command": "pytest services/knowledge-base/tests/test_paper_context_freeze_gate.py services/knowledge-base/tests/test_paper_context_api_contract.py -q",
                "status": "pass",
            }
        ],
    )

    assert report["schemaVersion"] == "s5-freeze-gate-report-v1"
    assert report["suiteVersion"] == "s5-paper-freeze-gate-v1"
    assert report["status"] == "pass"
    assert report["scope"]["s5ProducerFixtureObligations"] == "pass"
    assert report["scope"]["s3ConsumerExecutionStatus"] == "pending_s3_owned_validation"
    assert set(report["passedChecks"]) == EXPECTED_FREEZE_CHECKS
