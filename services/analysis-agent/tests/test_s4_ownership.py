from unittest.mock import AsyncMock, MagicMock

import pytest

from app.clients.s4_ownership import S4OwnershipError, post_and_wait_s4_ownership


def _resp(status_code: int, payload: dict):
    response = MagicMock(status_code=status_code)
    response.json.return_value = payload
    response.text = "<raw text should not be the preferred payload>"
    return response


@pytest.mark.asyncio
async def test_submit_conflict_preserves_standard_json_error_envelope():
    client = AsyncMock()
    client.post.return_value = _resp(409, {
        "success": False,
        "errorDetail": {"code": "REQUEST_ID_CONFLICT", "retryable": False},
        "requestId": "req-conflict",
    })

    with pytest.raises(S4OwnershipError) as exc_info:
        await post_and_wait_s4_ownership(
            client,
            base_url="http://localhost:9000",
            endpoint_path="/v1/scan",
            payload={"projectPath": "/uploads/project"},
            root_request_id="req-root",
            operation="sast_scan",
        )

    assert exc_info.value.status_code == 409
    assert exc_info.value.payload["errorDetail"]["code"] == "REQUEST_ID_CONFLICT"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "expected_code"),
    [(404, "REQUEST_NOT_FOUND"), (410, "REQUEST_EXPIRED")],
)
async def test_status_not_found_or_expired_preserves_standard_json_error_envelope(status_code, expected_code):
    submit = _resp(202, {
        "requestId": "req-owned",
        "statusUrl": "/v1/requests/req-owned",
        "resultUrl": "/v1/requests/req-owned/result",
    })
    status = _resp(status_code, {
        "success": False,
        "errorDetail": {"code": expected_code, "retryable": False},
        "requestId": "req-owned",
    })
    client = AsyncMock()
    client.post.return_value = submit
    client.get.return_value = status

    with pytest.raises(S4OwnershipError) as exc_info:
        await post_and_wait_s4_ownership(
            client,
            base_url="http://localhost:9000",
            endpoint_path="/v1/scan",
            payload={"projectPath": "/uploads/project"},
            root_request_id="req-root",
            operation="sast_scan",
        )

    assert exc_info.value.status_code == status_code
    assert exc_info.value.payload["errorDetail"]["code"] == expected_code
