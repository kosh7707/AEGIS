from __future__ import annotations

from fastapi.testclient import TestClient

from app.ledger.repository import SQLiteLedgerRepository
from app.main import app
from app.routers import target_context_api
from app.target_context_service import TargetContextService

client = TestClient(app, raise_server_exceptions=False)
_HEADERS = {"X-Timeout-Ms": "30000", "X-Request-Id": "req-ledger-integration"}


class MirrorFailingTargetContextService(TargetContextService):
    def _save(self) -> None:
        raise OSError("mirror disk is read-only")


class FailingWriteLedger:
    def initialize(self):
        return None

    def upsert_target_context_version(self, **kwargs):
        raise RuntimeError("sqlite write failed")

    def get_target_context(self, target_knowledge_id, version=None):
        return None


def _bundle():
    return {
        "schemaVersion": "target-context-v1",
        "projectId": "re100",
        "target": {"targetId": "re100:gateway", "buildUnitId": "gateway"},
        "provenance": {"buildSnapshotId": "bsnap-ledger", "buildUnitId": "gateway"},
        "libraries": [],
        "codeGraph": {"projectId": "re100-gateway", "functions": []},
    }


def _install(service):
    old = (target_context_api._target_context_service, target_context_api._ledger_repository)
    target_context_api.set_target_context_service(service)
    target_context_api.set_ledger_repository(getattr(service, "_ledger", None))
    target_context_api.set_code_graph_service(None)
    target_context_api.set_code_vector_search(None)
    target_context_api.set_code_assembler(None)
    target_context_api.set_knowledge_assembler(None)
    target_context_api.set_nvd_client(None)
    return old


def test_ledger_success_json_mirror_failure_is_explicit_non_authoritative_diagnostic(tmp_path):
    ledger = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    service = MirrorFailingTargetContextService(
        str(tmp_path / "target-contexts.json"),
        ledger_repository=ledger,
    )
    old = _install(service)
    try:
        resp = client.post("/v1/target-contexts", json=_bundle(), headers=_HEADERS)
    finally:
        target_context_api.set_target_context_service(old[0])
        target_context_api.set_ledger_repository(old[1])

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["acquisitionStatus"] == "completed_hit"
    assert body["results"]["storage"]["authoritative"] == "sqlite-ledger"
    assert body["results"]["storage"]["compatibilityMirror"]["state"] == "failed"
    assert body["results"]["storage"]["compatibilityMirror"]["authoritative"] is False
    assert "TARGET_CONTEXT_JSON_MIRROR_FAILED" in {diag["code"] for diag in body["diagnostics"]}
    assert ledger.get_target_context(body["targetKnowledgeId"])["targetContextVersion"] == 1


def test_ledger_write_failure_does_not_fall_back_to_json_success(tmp_path):
    service = TargetContextService(
        str(tmp_path / "target-contexts.json"),
        ledger_repository=FailingWriteLedger(),
    )
    old = _install(service)
    try:
        resp = client.post("/v1/target-contexts", json=_bundle(), headers=_HEADERS)
    finally:
        target_context_api.set_target_context_service(old[0])
        target_context_api.set_ledger_repository(old[1])

    assert resp.status_code == 503
    body = resp.json()
    assert body["success"] is False
    assert body["errorDetail"]["code"] == "KB_NOT_READY"
    assert "ledger storage failed" in body["error"].lower()
    assert not (tmp_path / "target-contexts.json").exists()


def test_default_target_context_service_requires_ledger(tmp_path):
    try:
        TargetContextService(str(tmp_path / "target-contexts.json"))
    except Exception as exc:
        assert "requires a SQLite ledger repository" in str(exc)
    else:
        raise AssertionError("TargetContextService must require ledger unless legacy mode is explicit")


def test_explicit_legacy_json_only_mode_is_marked_non_default(tmp_path):
    service = TargetContextService(str(tmp_path / "target-contexts.json"), legacy_json_only=True)

    result = service.ingest(_bundle())

    assert result["ok"] is True
    assert result["storage"]["authoritative"] == "legacy-json"
    assert result["diagnostics"][0]["code"] == "TARGET_CONTEXT_LEGACY_JSON_ONLY"
