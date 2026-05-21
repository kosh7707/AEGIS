"""입력 검증 (422) 계약 테스트.

Pydantic 모델 검증에 의한 422 반환을 HTTP 레벨에서 확인한다.
"""

import pytest

from tests.conftest import (
    make_chat_body,
    make_paper_acquisition_body,
    make_paper_finalizer_body,
    make_task_body,
)


class TestInputValidation:
    def test_unknown_task_type_422(self, client_live):
        body = make_task_body(task_type="nonexistent-type")
        resp = client_live.post("/v1/tasks", json=body)
        assert resp.status_code == 422

    def test_missing_task_id_422(self, client_live):
        body = make_task_body()
        del body["taskId"]
        resp = client_live.post("/v1/tasks", json=body)
        assert resp.status_code == 422

    def test_missing_context_422(self, client_live):
        body = make_task_body()
        del body["context"]
        resp = client_live.post("/v1/tasks", json=body)
        assert resp.status_code == 422

    def test_empty_body_422(self, client_live):
        resp = client_live.post("/v1/tasks", json={})
        assert resp.status_code == 422

    def test_invalid_json_422(self, client_live):
        resp = client_live.post(
            "/v1/tasks",
            content=b"not-json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_max_tokens_out_of_range_422(self, client_live):
        body = make_task_body(max_tokens=99999)
        resp = client_live.post("/v1/tasks", json=body)
        assert resp.status_code == 422

    def test_missing_constraints_422(self, client_live):
        body = make_task_body()
        del body["constraints"]
        resp = client_live.post("/v1/tasks", json=body)
        assert resp.status_code == 422
        assert any(
            err.get("loc") == ["body", "constraints"]
            for err in resp.json().get("detail", [])
        )

    @pytest.mark.parametrize("field", [
        "enableThinking",
        "maxTokens",
        "temperature",
        "topP",
        "topK",
        "minP",
        "presencePenalty",
        "repetitionPenalty",
    ])
    def test_missing_required_generation_constraint_422(self, client_live, field):
        body = make_task_body()
        del body["constraints"][field]
        resp = client_live.post("/v1/tasks", json=body)
        assert resp.status_code == 422
        assert any(
            err.get("loc") == ["body", "constraints", field]
            for err in resp.json().get("detail", [])
        )

    @pytest.mark.parametrize(("field", "value"), [
        ("temperature", -0.1),
        ("temperature", 2.1),
        ("topP", -0.1),
        ("topP", 1.1),
        ("topK", -2),
        ("minP", -0.1),
        ("minP", 1.1),
        ("presencePenalty", -2.1),
        ("presencePenalty", 2.1),
        ("repetitionPenalty", -0.1),
        ("repetitionPenalty", 2.1),
    ])
    def test_generation_constraint_out_of_range_422(self, client_live, field, value):
        body = make_task_body()
        body["constraints"][field] = value
        resp = client_live.post("/v1/tasks", json=body)
        assert resp.status_code == 422

    def test_async_chat_missing_messages_422(self, client_live):
        body = make_chat_body()
        del body["messages"]
        resp = client_live.post("/v1/async-chat-requests", json=body)
        assert resp.status_code == 422

    def test_async_chat_empty_messages_422(self, client_live):
        body = make_chat_body()
        body["messages"] = []
        resp = client_live.post("/v1/async-chat-requests", json=body)
        assert resp.status_code == 422

    @pytest.mark.parametrize("field", [
        "max_tokens",
        "temperature",
        "top_p",
        "top_k",
        "min_p",
        "presence_penalty",
        "repetition_penalty",
        "chat_template_kwargs",
    ])
    def test_async_chat_missing_required_generation_control_422(self, client_live, field):
        body = make_chat_body()
        del body[field]
        resp = client_live.post("/v1/async-chat-requests", json=body)
        assert resp.status_code == 422
        assert any(
            err.get("loc") == ["body", field]
            for err in resp.json().get("detail", [])
        )

    def test_async_chat_missing_enable_thinking_422(self, client_live):
        body = make_chat_body()
        body["chat_template_kwargs"] = {}
        resp = client_live.post("/v1/async-chat-requests", json=body)
        assert resp.status_code == 422
        assert any(
            err.get("loc") == ["body", "chat_template_kwargs", "enable_thinking"]
            for err in resp.json().get("detail", [])
        )

    def test_chat_missing_generation_controls_422(self, client_live):
        body = make_chat_body()
        del body["top_p"]
        del body["chat_template_kwargs"]
        resp = client_live.post("/v1/chat", json=body)
        assert resp.status_code == 422
        data = resp.json()
        assert data["success"] is False
        assert data["errorDetail"]["code"] == "INVALID_GENERATION_CONTROLS"
        assert data["errorDetail"]["missingFields"] == [
            "top_p",
            "chat_template_kwargs.enable_thinking",
        ]

    @pytest.mark.parametrize(("field", "value"), [
        ("max_tokens", 99999),
        ("max_tokens", 0),
        ("max_tokens", 1.5),
        ("temperature", "hot"),
        ("temperature", -0.1),
        ("temperature", 2.1),
        ("top_p", 1.1),
        ("top_k", -2),
        ("top_k", 1.5),
        ("min_p", -0.1),
        ("presence_penalty", 2.1),
        ("repetition_penalty", -0.1),
    ])
    def test_chat_invalid_generation_control_422(self, client_live, field, value):
        body = make_chat_body()
        body[field] = value
        resp = client_live.post("/v1/chat", json=body)
        assert resp.status_code == 422
        data = resp.json()
        assert data["errorDetail"]["code"] == "INVALID_GENERATION_CONTROLS"
        assert data["errorDetail"]["invalidFields"] == [field]

    def test_chat_invalid_enable_thinking_422(self, client_live):
        body = make_chat_body()
        body["chat_template_kwargs"] = {"enable_thinking": "true"}
        resp = client_live.post("/v1/chat", json=body)
        assert resp.status_code == 422
        assert resp.json()["errorDetail"]["invalidFields"] == [
            "chat_template_kwargs.enable_thinking",
        ]

    @pytest.mark.parametrize("field", [
        "seed",
        "logprobs",
        "tool_choice",
        "chat_template_kwargs.preserve_thinking",
    ])
    def test_chat_paper_controls_missing_common_field_422(self, client_live, field):
        body = make_paper_acquisition_body()
        if "." in field:
            outer, inner = field.split(".", 1)
            del body[outer][inner]
        else:
            del body[field]

        resp = client_live.post(
            "/v1/chat",
            json=body,
            headers={"X-AEGIS-Paper-Controls": "true"},
        )

        assert resp.status_code == 422
        data = resp.json()
        assert data["errorDetail"]["code"] == "INVALID_GENERATION_CONTROLS"
        assert field in data["errorDetail"]["missingFields"]

    @pytest.mark.parametrize(("field", "value"), [
        ("seed", "not-an-int"),
        ("seed", True),
        ("seed", 2 ** 63),
        ("logprobs", "false"),
        ("chat_template_kwargs.preserve_thinking", "false"),
    ])
    def test_chat_paper_controls_invalid_common_field_422(self, client_live, field, value):
        body = make_paper_acquisition_body()
        if "." in field:
            outer, inner = field.split(".", 1)
            body[outer][inner] = value
        else:
            body[field] = value

        resp = client_live.post(
            "/v1/chat",
            json=body,
            headers={"X-AEGIS-Paper-Controls": "true"},
        )

        assert resp.status_code == 422
        assert field in resp.json()["errorDetail"]["invalidFields"]

    def test_chat_paper_controls_logprobs_true_requires_top_logprobs(self, client_live):
        body = make_paper_acquisition_body()
        body["logprobs"] = True

        resp = client_live.post(
            "/v1/chat",
            json=body,
            headers={"X-AEGIS-Paper-Controls": "true"},
        )

        assert resp.status_code == 422
        assert "top_logprobs" in resp.json()["errorDetail"]["missingFields"]

    def test_chat_paper_controls_logprobs_false_rejects_top_logprobs(self, client_live):
        body = make_paper_acquisition_body()
        body["logprobs"] = False
        body["top_logprobs"] = 0

        resp = client_live.post(
            "/v1/chat",
            json=body,
            headers={"X-AEGIS-Paper-Controls": "true"},
        )

        assert resp.status_code == 422
        assert "top_logprobs" in resp.json()["errorDetail"]["invalidFields"]

    def test_chat_paper_acquisition_rejects_schema_controls(self, client_live):
        body = make_paper_acquisition_body()
        body["response_format"] = {"type": "json_object"}

        resp = client_live.post(
            "/v1/chat",
            json=body,
            headers={"X-AEGIS-Paper-Controls": "true"},
        )

        assert resp.status_code == 422
        data = resp.json()["errorDetail"]
        assert data["paperPhase"] == "ambiguous"
        assert "response_format" in data["invalidFields"]

    def test_chat_paper_acquisition_rejects_strict_header(self, client_live):
        body = make_paper_acquisition_body()

        resp = client_live.post(
            "/v1/chat",
            json=body,
            headers={
                "X-AEGIS-Paper-Controls": "true",
                "X-AEGIS-Strict-JSON": "true",
            },
        )

        assert resp.status_code == 422
        assert "x-aegis-strict-json" in resp.json()["errorDetail"]["invalidFields"]

    def test_chat_paper_finalizer_requires_json_schema_not_json_object(self, client_live):
        body = make_paper_finalizer_body()
        body["response_format"] = {"type": "json_object"}

        resp = client_live.post(
            "/v1/chat",
            json=body,
            headers={"X-AEGIS-Paper-Controls": "true"},
        )

        assert resp.status_code == 422
        assert "response_format" in resp.json()["errorDetail"]["invalidFields"]
