from pathlib import Path
from typing import Literal
from pydantic_settings import BaseSettings

from app.agent_runtime.llm.generation_policy import TimeoutDefaults


_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"

class Settings(BaseSettings):
    llm_mode: Literal["mock", "real"] = "mock"
    llm_endpoint: str = "http://localhost:8000"
    llm_model: str = "Qwen/Qwen3.6-27B"
    llm_api_key: str = ""
    llm_concurrency: int = 4
    llm_async_poll_interval_seconds: float = 1.0

    sast_endpoint: str = "http://localhost:9000"

    agent_max_steps: int = 10
    agent_max_completion_tokens: int = 32768
    agent_max_cheap_calls: int = 20
    agent_max_medium_calls: int = 0
    agent_max_expensive_calls: int = 5
    agent_no_evidence_threshold: int = 6
    agent_tool_timeout_ms: int = int(TimeoutDefaults.TOOL_EXECUTION_SECONDS * 1000)
    agent_llm_max_tokens: int = 32768
    agent_llm_retry_max: int = 1
    build_task_deadline_ms: int = int(TimeoutDefaults.CHAT_DEFAULT_SECONDS * 1000)
    build_partial_envelope_deadline_ms: int = int((TimeoutDefaults.CHAT_DEFAULT_SECONDS - 60.0) * 1000)
    agent_task_deadline_ms: int = int(TimeoutDefaults.CHAT_DEFAULT_SECONDS * 1000)
    agent_partial_envelope_deadline_ms: int = int((TimeoutDefaults.CHAT_DEFAULT_SECONDS - 60.0) * 1000)

    model_config = {
        "env_prefix": "AEGIS_",
        "env_file": str(_ENV_FILE),
        "extra": "ignore",
    }

settings = Settings()
