"""Generation policy contract tests for S7 caller-owned controls."""

from __future__ import annotations

import pytest

from app.agent_runtime.llm.generation_policy import (
    ChatGenerationProfile,
    GenerationControls,
    STRICT_JSON_REPAIR,
    THINKING_CODING,
    THINKING_GENERAL,
    TRACEAUDIT_QWEN36_ACQUISITION_V1,
    TRACEAUDIT_QWEN36_FINALIZER_V1,
    TRACEAUDIT_QWEN36_TRIAGE_V1,
    TimeoutDefaults,
    controls_from_constraints,
)


def test_thinking_general_serializes_complete_gateway_tuple() -> None:
    fields = THINKING_GENERAL.to_gateway_fields()

    assert fields == {
        "temperature": 1.0,
        "top_p": 0.95,
        "top_k": 20,
        "min_p": 0.0,
        "presence_penalty": 0.0,
        "repetition_penalty": 1.0,
        "chat_template_kwargs": {"enable_thinking": True},
    }


def test_named_presets_capture_intended_sampling_shapes() -> None:
    assert THINKING_CODING.temperature == 0.6
    assert THINKING_CODING.top_p == THINKING_GENERAL.top_p
    assert STRICT_JSON_REPAIR.temperature == 0.0
    assert STRICT_JSON_REPAIR.top_p == 1.0
    assert STRICT_JSON_REPAIR.top_k == 1
    assert STRICT_JSON_REPAIR.enable_thinking is False


def test_traceaudit_qwen36_triage_profile_serializes_complete_gateway_request_controls() -> None:
    fields = TRACEAUDIT_QWEN36_TRIAGE_V1.to_gateway_fields()

    assert TRACEAUDIT_QWEN36_TRIAGE_V1.profile_id == "traceaudit-qwen36-finalizer-v1"
    assert fields == {
        "max_tokens": 8192,
        "temperature": 0.0,
        "top_p": 1.0,
        "top_k": 1,
        "min_p": 0.0,
        "presence_penalty": 0.0,
        "repetition_penalty": 1.0,
        "chat_template_kwargs": {"enable_thinking": False},
        "response_format": {"type": "json_object"},
    }


def test_traceaudit_qwen36_profiles_split_acquisition_from_finalizer() -> None:
    acquisition = TRACEAUDIT_QWEN36_ACQUISITION_V1.to_gateway_fields()
    finalizer = TRACEAUDIT_QWEN36_FINALIZER_V1.to_gateway_fields()

    assert TRACEAUDIT_QWEN36_ACQUISITION_V1.profile_id == "traceaudit-qwen36-acquisition-v1"
    assert acquisition["max_tokens"] == 32768
    assert acquisition["chat_template_kwargs"]["enable_thinking"] is True
    assert "response_format" not in acquisition

    assert TRACEAUDIT_QWEN36_FINALIZER_V1.profile_id == "traceaudit-qwen36-finalizer-v1"
    assert finalizer["response_format"] == {"type": "json_object"}
    assert finalizer["chat_template_kwargs"]["enable_thinking"] is False


def test_chat_generation_profile_records_reproducibility_metadata() -> None:
    metadata = TRACEAUDIT_QWEN36_TRIAGE_V1.to_metadata(model="qwen3.6-27b")

    assert metadata["profileId"] == "traceaudit-qwen36-finalizer-v1"
    assert metadata["model"] == "qwen3.6-27b"
    assert metadata["generationControls"] == TRACEAUDIT_QWEN36_TRIAGE_V1.to_gateway_fields()


def test_constraint_overrides_use_public_camel_case_names() -> None:
    controls = controls_from_constraints(
        THINKING_GENERAL,
        {
            "enableThinking": False,
            "temperature": 0.42,
            "topP": 0.7,
            "topK": -1,
            "minP": 0.05,
            "presencePenalty": 0.2,
            "repetitionPenalty": 1.1,
        },
    )

    assert controls == GenerationControls(
        temperature=0.42,
        top_p=0.7,
        top_k=-1,
        min_p=0.05,
        presence_penalty=0.2,
        repetition_penalty=1.1,
        enable_thinking=False,
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"temperature": -0.1},
        {"temperature": 2.1},
        {"top_p": 1.1},
        {"top_k": -2},
        {"top_k": True},
        {"min_p": -0.01},
        {"presence_penalty": -2.1},
        {"repetition_penalty": 2.1},
    ],
)
def test_generation_controls_reject_out_of_range_values(updates: dict) -> None:
    with pytest.raises(ValueError):
        THINKING_GENERAL.with_updates(**updates)


@pytest.mark.parametrize("max_tokens", [0, 32769, True, 1.5])
def test_chat_generation_profile_rejects_invalid_max_tokens(max_tokens) -> None:
    with pytest.raises(ValueError):
        ChatGenerationProfile(
            profile_id="bad",
            max_tokens=max_tokens,
            controls=THINKING_GENERAL,
        )


def test_timeout_defaults_mirror_s7_policy_contract() -> None:
    assert TimeoutDefaults.CHAT_DEFAULT_SECONDS == 1800.0
    assert TimeoutDefaults.CHAT_MAX_SECONDS == 1800.0
    assert TimeoutDefaults.TASK_CLIENT_READ_SECONDS == 600.0
    assert TimeoutDefaults.REPAIR_OR_STRICT_JSON_SECONDS == 600.0
    assert TimeoutDefaults.TOOL_EXECUTION_SECONDS == 120.0
