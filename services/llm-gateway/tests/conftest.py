"""Contract test fixtures — HTTP-level 테스트를 위한 공통 설정."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.types import TaskType


@pytest.fixture()
def client_live():
    """실제 mock 파이프라인을 거치는 TestClient.

    settings를 mock 모드 + RAG 비활성화로 고정하여
    Qdrant/vLLM 의존성 없이 엔드투엔드 경로를 테스트한다.
    """
    original_mode = settings.llm_mode
    original_rag = settings.rag_enabled
    object.__setattr__(settings, "llm_mode", "mock")
    object.__setattr__(settings, "rag_enabled", False)

    from app.main import app

    with TestClient(app) as c:
        yield c

    object.__setattr__(settings, "llm_mode", original_mode)
    object.__setattr__(settings, "rag_enabled", original_rag)


@pytest.fixture()
def mock_pipeline():
    """pipeline.execute 반환값을 직접 제어할 수 있는 MagicMock."""
    pipeline = MagicMock()
    pipeline.execute = AsyncMock()
    return pipeline


@pytest.fixture()
def client(mock_pipeline):
    """mock_pipeline이 주입된 TestClient.

    lifespan 이후 app.state.pipeline을 교체하여
    실패 시나리오, 500 에러 등을 제어한다.
    """
    original_mode = settings.llm_mode
    original_rag = settings.rag_enabled
    object.__setattr__(settings, "llm_mode", "mock")
    object.__setattr__(settings, "rag_enabled", False)

    from app.main import app

    with TestClient(app) as c:
        original_pipeline = app.state.pipeline
        app.state.pipeline = mock_pipeline
        yield c
        app.state.pipeline = original_pipeline

    object.__setattr__(settings, "llm_mode", original_mode)
    object.__setattr__(settings, "rag_enabled", original_rag)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def make_task_body(
    task_type: str = "static-explain",
    task_id: str = "test-001",
    *,
    trusted: dict | None = None,
    evidence_refs: list | None = None,
    enable_thinking: bool = True,
    max_tokens: int = 2048,
    temperature: float = 1.0,
    top_p: float = 0.95,
    top_k: int = 20,
    min_p: float = 0.0,
    presence_penalty: float = 0.0,
    repetition_penalty: float = 1.0,
) -> dict:
    """API 계약서 형식의 POST /v1/tasks 요청 body."""
    return {
        "taskType": task_type,
        "taskId": task_id,
        "context": {
            "trusted": trusted or {
                "finding": {
                    "findingId": "F-001",
                    "ruleId": "CWE-120",
                    "severity": "high",
                    "message": "Buffer overflow in gets()",
                    "file": "src/main.c",
                    "line": 42,
                },
            },
        },
        "evidenceRefs": evidence_refs or [
            {
                "refId": "eref-001",
                "artifactId": "art-001",
                "artifactType": "sourceCode",
                "locatorType": "lineRange",
                "locator": {"file": "src/main.c", "startLine": 1, "endLine": 50},
            },
        ],
        "constraints": {
            "enableThinking": enable_thinking,
            "maxTokens": max_tokens,
            "temperature": temperature,
            "topP": top_p,
            "topK": top_k,
            "minP": min_p,
            "presencePenalty": presence_penalty,
            "repetitionPenalty": repetition_penalty,
        },
    }


def make_test_plan_body(task_id: str = "test-tp-001") -> dict:
    """test-plan-propose 전용 요청 body."""
    return make_task_body(
        task_type="test-plan-propose",
        task_id=task_id,
        trusted={
            "objective": "SecurityAccess brute-force lockout 검증",
            "ecuType": "Gateway ECU",
            "protocol": "UDS",
        },
    )


def make_chat_body() -> dict:
    return {
        "model": "ignored-by-gateway",
        "messages": [{"role": "user", "content": "hello async"}],
        "max_tokens": 64,
        "temperature": 1.0,
        "top_p": 0.95,
        "top_k": 20,
        "min_p": 0.0,
        "presence_penalty": 0.0,
        "repetition_penalty": 1.0,
        "chat_template_kwargs": {"enable_thinking": True},
    }


def make_paper_acquisition_body() -> dict:
    body = make_chat_body()
    body.update({
        "seed": 123456789,
        "logprobs": False,
        "chat_template_kwargs": {
            "enable_thinking": True,
            "preserve_thinking": False,
        },
        "tools": [{
            "type": "function",
            "function": {
                "name": "knowledge_search",
                "description": "Search paper evidence",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            },
        }],
        "tool_choice": "auto",
    })
    return body


def make_paper_finalizer_body() -> dict:
    body = make_chat_body()
    body.update({
        "seed": 123456789,
        "logprobs": False,
        "chat_template_kwargs": {
            "enable_thinking": False,
            "preserve_thinking": False,
        },
        "tool_choice": "none",
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "traceaudit_finalizer",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {"answer": {"type": "string"}},
                    "required": ["answer"],
                    "additionalProperties": False,
                },
            },
        },
    })
    return body


ALL_TASK_TYPES = [t.value for t in TaskType]
