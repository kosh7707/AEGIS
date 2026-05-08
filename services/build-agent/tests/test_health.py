def test_health(client):
    from app.runtime.request_summary import request_summary_tracker
    request_summary_tracker.reset()
    resp = client.get("/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "s3-build"
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"
    assert data["activeResponseSchemas"]["build-resolve"] == "build-v1.1"
    assert data["activeResponseSchemas"]["sdk-analyze"] == "build-v1.1"
    assert data["proposedResponseSchemas"] == {}
    assert data["agentConfig"]["taskDeadlineMs"] == 1_800_000
    assert data["agentConfig"]["partialEnvelopeDeadlineMs"] == 1_740_000
    assert data["agentConfig"]["llmAsyncPollIntervalSeconds"] == 1.0
    assert data["activeRequestCount"] == 0
    assert data["requestSummary"]["state"] == "idle"
    assert data["requestSummary"]["localAckState"] is None

def test_build_resolve_mock(client):
    """build-resolve 요청이 200을 반환하고 유효한 응답 구조를 갖는지 확인."""
    resp = client.post("/v1/tasks", json={
        "taskType": "build-resolve",
        "taskId": "test-build-001",
        "context": {"trusted": {"objective": "test build", "projectPath": "/tmp/test"}},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("completed", "budget_exceeded", "model_error", "validation_failed")
    assert data["taskId"] == "test-build-001"
    assert data["taskType"] == "build-resolve"


def test_build_resolve_strict_contract_payload_example(client):
    """strict compile-first 예시 payload도 현재 공개 surface에서 수용된다."""
    request_id = "req-strict-build-001"
    resp = client.post(
        "/v1/tasks",
        headers={"X-Request-Id": request_id},
        json={
            "taskType": "build-resolve",
            "taskId": "test-build-strict-001",
            "context": {
                "trusted": {
                    "projectPath": "/tmp/test",
                    "buildTargetPath": "gateway/",
                    "buildTargetName": "gateway",
                    "contractVersion": "build-resolve-v1",
                    "strictMode": True,
                    "build": {"mode": "native"},
                    "expectedArtifacts": [
                        {"kind": "executable", "path": "build-aegis/gateway"},
                    ],
                },
            },
        },
    )
    assert resp.status_code == 200
    assert resp.headers["X-Request-Id"] == request_id
    data = resp.json()
    assert data["taskId"] == "test-build-strict-001"
    assert data["taskType"] == "build-resolve"


def test_build_resolve_accepts_top_level_strict_contract_fields(client):
    resp = client.post(
        "/v1/tasks",
        json={
            "taskType": "build-resolve",
            "taskId": "test-build-top-level-strict-001",
            "contractVersion": "build-resolve-v1",
            "strictMode": True,
            "context": {
                "trusted": {
                    "projectPath": "/tmp/test",
                    "buildTargetPath": "gateway/",
                    "buildTargetName": "gateway",
                    "build": {"mode": "native"},
                    "expectedArtifacts": [
                        {"kind": "executable", "path": "build-aegis/gateway"},
                    ],
                },
            },
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["taskId"] == "test-build-top-level-strict-001"
    assert data["taskType"] == "build-resolve"
    assert data["contractVersion"] == "build-resolve-v1"
    assert data["strictMode"] is True


def test_build_resolve_legacy_aliases_still_parse(client):
    """legacy alias payload도 migration shim으로 계속 수용된다."""
    resp = client.post(
        "/v1/tasks",
        json={
            "taskType": "build-resolve",
            "taskId": "test-build-legacy-alias-001",
            "context": {
                "trusted": {
                    "projectPath": "/tmp/test",
                    "targetPath": "gateway/",
                    "targetName": "gateway",
                    "contractVersion": "compile-first-v1",
                    "strictMode": True,
                    "buildMode": "native",
                    "expectedArtifacts": [
                        {"kind": "executable", "path": "build-aegis/gateway"},
                    ],
                },
            },
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["taskId"] == "test-build-legacy-alias-001"
    assert data["taskType"] == "build-resolve"


def test_sdk_analyze_mock(client):
    """sdk-analyze 요청이 200을 반환하고 유효한 응답 구조를 갖는지 확인."""
    resp = client.post("/v1/tasks", json={
        "taskType": "sdk-analyze",
        "taskId": "test-sdk-001",
        "context": {"trusted": {"projectPath": "/tmp/test-sdk"}},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("completed", "budget_exceeded", "model_error", "validation_failed")
    assert data["taskId"] == "test-sdk-001"
    assert data["taskType"] == "sdk-analyze"
    # mock 모드에서는 sdkProfile이 포함되어야 함
    if data["status"] == "completed":
        result = data.get("result", {})
        assert "sdkProfile" in result or result.get("sdkProfile") is None


def test_sdk_analyze_request_id_header_round_trip(client):
    """sdk-analyze도 request-id 전파를 유지한다."""
    request_id = "req-sdk-analyze-001"
    resp = client.post(
        "/v1/tasks",
        headers={"X-Request-Id": request_id},
        json={
            "taskType": "sdk-analyze",
            "taskId": "test-sdk-header-001",
            "context": {"trusted": {"projectPath": "/tmp/test-sdk"}},
        },
    )

    assert resp.status_code == 200
    assert resp.headers["X-Request-Id"] == request_id
    data = resp.json()
    assert data["taskId"] == "test-sdk-header-001"
    assert data["taskType"] == "sdk-analyze"


def test_unknown_task_type(client):
    """미지원 taskType은 400을 반환해야 한다."""
    resp = client.post("/v1/tasks", json={
        "taskType": "unknown-type",
        "taskId": "test-unknown",
        "context": {"trusted": {"projectPath": "/tmp/test"}},
    })
    assert resp.status_code in (400, 422)


def test_health_endpoint_reports_build_request_summary(client):
    from app.runtime.request_summary import request_summary_tracker

    request_summary_tracker.reset()
    request_summary_tracker.register("req-build-health", endpoint="tasks")
    request_summary_tracker.mark_transport_only("req-build-health", source="s4-build-ownership-wait")

    resp = client.get("/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["activeRequestCount"] == 1
    assert data["requestSummary"]["requestId"] == "req-build-health"
    assert data["requestSummary"]["state"] == "running"
    assert data["requestSummary"]["localAckState"] == "transport-only"
    assert data["requestSummary"]["blockedReason"] is None

    request_summary_tracker.mark_failed("req-build-health", "blocked")
    failed = client.get("/v1/health", params={"requestId": "req-build-health"}).json()["requestSummary"]
    assert failed["state"] == "failed"
    assert failed["localAckState"] == "ack-break"
    assert failed["blockedReason"] == "blocked"
    request_summary_tracker.reset()
