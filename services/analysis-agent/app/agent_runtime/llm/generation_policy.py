"""S3-owned generation controls for S7 LLM gateway requests.

These presets make the caller-owned generation tuple explicit instead of relying
on S7 gateway defaults. Values are based on the 2026-04-28 S3/S7 temperature
policy review for Qwen3.6-27B and must be revisited when the model family or
S7 validation ranges change.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any


@dataclass(frozen=True)
class GenerationControls:
    """Complete generation tuple required by S7 chat surfaces."""

    temperature: float
    top_p: float
    top_k: int
    min_p: float
    presence_penalty: float = 0.0
    repetition_penalty: float = 1.0
    enable_thinking: bool = True

    def __post_init__(self) -> None:
        _validate_range("temperature", self.temperature, 0.0, 2.0)
        _validate_range("top_p", self.top_p, 0.0, 1.0)
        if not isinstance(self.top_k, int) or isinstance(self.top_k, bool) or self.top_k < -1:
            raise ValueError("top_k must be an integer >= -1")
        _validate_range("min_p", self.min_p, 0.0, 1.0)
        _validate_range("presence_penalty", self.presence_penalty, -2.0, 2.0)
        _validate_range("repetition_penalty", self.repetition_penalty, 0.0, 2.0)

    def to_gateway_fields(self) -> dict[str, Any]:
        """Return S7 snake_case generation fields for request bodies."""
        return {
            "temperature": self.temperature,
            "top_p": self.top_p,
            "top_k": self.top_k,
            "min_p": self.min_p,
            "presence_penalty": self.presence_penalty,
            "repetition_penalty": self.repetition_penalty,
            "chat_template_kwargs": {"enable_thinking": self.enable_thinking},
        }

    def with_updates(self, **updates: Any) -> "GenerationControls":
        """Return a validated copy with selected fields changed."""
        clean_updates = {key: value for key, value in updates.items() if value is not None}
        if not clean_updates:
            return self
        return replace(self, **clean_updates)


@dataclass(frozen=True)
class ChatGenerationProfile:
    """Named S3 chat profile for reproducible S7 calls.

    `GenerationControls` intentionally excludes max_tokens because many legacy
    S3 call sites budget completion tokens per turn. Paper-facing triage needs a
    stronger contract: every live verdict must be attributable to a named
    profile that includes both the complete S7 generation tuple and the
    completion-token budget used for that profile version.
    """

    profile_id: str
    max_tokens: int
    controls: GenerationControls
    response_format: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.max_tokens, int) or isinstance(self.max_tokens, bool):
            raise ValueError("max_tokens must be an integer")
        if not (1 <= self.max_tokens <= 32768):
            raise ValueError("max_tokens must be between 1 and 32768")
        if not self.profile_id:
            raise ValueError("profile_id must be non-empty")

    def to_gateway_fields(self) -> dict[str, Any]:
        """Return S7 request fields owned by this profile."""
        fields = {
            "max_tokens": self.max_tokens,
            **self.controls.to_gateway_fields(),
        }
        if self.response_format is not None:
            fields["response_format"] = self.response_format
        return fields

    def to_metadata(self, *, model: str | None = None) -> dict[str, Any]:
        """Return reproducibility metadata suitable for transcripts/artifacts."""
        metadata: dict[str, Any] = {
            "profileId": self.profile_id,
            "generationControls": self.to_gateway_fields(),
        }
        if model is not None:
            metadata["model"] = model
        return metadata


class TimeoutDefaults:
    """S7-aligned timeout policy constants consumed by S3 callers/tools.

    Mirrored locally rather than importing S7 code across lane ownership. Keep
    these values in sync with the S7 generation-control contract and update the
    session evidence whenever the gateway policy changes.
    """

    CHAT_DEFAULT_SECONDS: float = 1800.0
    CHAT_MAX_SECONDS: float = 1800.0
    TASK_CLIENT_READ_SECONDS: float = 600.0
    REPAIR_OR_STRICT_JSON_SECONDS: float = 600.0
    TOOL_EXECUTION_SECONDS: float = 120.0


def _validate_range(name: str, value: float, minimum: float, maximum: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    if not (minimum <= float(value) <= maximum):
        raise ValueError(f"{name} must be between {minimum:g} and {maximum:g}")


# General evidence-acquisition/reasoning turn. Keep stochasticity high enough for
# Qwen thinking mode while bounding nucleus/top-k sampling explicitly.
THINKING_GENERAL = GenerationControls(
    temperature=1.0,
    top_p=0.95,
    top_k=20,
    min_p=0.0,
    presence_penalty=0.0,
    repetition_penalty=1.0,
    enable_thinking=True,
)

# Initial code-generation draft. Slightly lower temperature than broad analysis.
THINKING_CODING = GenerationControls(
    temperature=0.6,
    top_p=0.95,
    top_k=20,
    min_p=0.0,
    presence_penalty=0.0,
    repetition_penalty=1.0,
    enable_thinking=True,
)

# Strict JSON repair/finalizer path. Thinking is disabled on structured
# dispatch/finalization turns because Qwen/vLLM can place the requested JSON in
# the reasoning channel instead of assistant content when thinking is enabled.
# If S7/model validation rejects top_k=1 in practice, keep this preset
# centralized and adjust here rather than per callsite.
STRICT_JSON_REPAIR = GenerationControls(
    temperature=0.0,
    top_p=1.0,
    top_k=1,
    min_p=0.0,
    presence_penalty=0.0,
    repetition_penalty=1.0,
    enable_thinking=False,
)

# Paper TraceAudit evidence-acquisition/reasoning profile for Qwen3.6-27B via S7.
#
# Acquisition turns are allowed to think and call tools. They must not request
# strict JSON mode because the model may need to emit OpenAI tool_calls.
TRACEAUDIT_QWEN36_ACQUISITION_V1 = ChatGenerationProfile(
    profile_id="traceaudit-qwen36-acquisition-v1",
    max_tokens=32768,
    controls=THINKING_GENERAL,
    response_format=None,
)

# Paper TraceAudit strict finalizer profile for Qwen3.6-27B via S7.
#
# This profile is deliberately centralized because paper verdict rows must be
# reproducible and audit-attributable. It is tool-less and schema-constrained;
# do not reuse it for acquisition/tool-call turns.
TRACEAUDIT_QWEN36_FINALIZER_V1 = ChatGenerationProfile(
    profile_id="traceaudit-qwen36-finalizer-v1",
    max_tokens=8192,
    controls=STRICT_JSON_REPAIR,
    response_format={"type": "json_object"},
)

# Backward-compatible alias for tests/callers not yet migrated. The canonical
# names above distinguish the acquisition and finalization phases.
TRACEAUDIT_QWEN36_TRIAGE_V1 = TRACEAUDIT_QWEN36_FINALIZER_V1

# Transitional default for legacy call sites during the foundation slice.
# Deprecation milestone: once S3 regression-gate evidence shows every active
# LlmCaller.call() site passes a named GenerationControls preset, remove the
# scalar temperature compatibility argument from LlmCaller.call().
DEFAULT_GENERATION = THINKING_GENERAL


def controls_from_constraints(base: GenerationControls, constraints: Any | None) -> GenerationControls:
    """Apply optional S3 public camelCase constraint overrides to a preset.

    The request schema owns range validation at the API boundary. This helper is
    intentionally duck-typed so eval/tests can reuse it without importing route
    schemas.
    """
    if constraints is None:
        return base

    def read(name: str) -> Any:
        if isinstance(constraints, dict):
            return constraints.get(name)
        return getattr(constraints, name, None)

    return base.with_updates(
        enable_thinking=read("enableThinking"),
        temperature=read("temperature"),
        top_p=read("topP"),
        top_k=read("topK"),
        min_p=read("minP"),
        presence_penalty=read("presencePenalty"),
        repetition_penalty=read("repetitionPenalty"),
    )
