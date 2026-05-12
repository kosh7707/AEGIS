from typing import Literal

from pydantic_settings import BaseSettings

from app.generation_policy import TimeoutDefaults


class Settings(BaseSettings):
    llm_mode: Literal["mock", "real"] = "mock"
    llm_endpoint: str = "http://localhost:8080"
    llm_model: str = "Qwen/Qwen3.6-27B"
    llm_api_key: str = ""
    llm_concurrency: int = 4
    llm_connect_timeout: float = 10.0  # LLM Engine 연결 타임아웃 (초). 장애 감지용
    llm_read_timeout: float = TimeoutDefaults.TASK_CLIENT_READ_SECONDS  # LLM Engine 응답 대기 타임아웃 (초). 대형 생성 대비
    llm_health_cache_ttl_seconds: float = 1.0  # /v1/health LLM backend readiness probe freshness window
    llm_max_input_chars: int = 800_000  # 프롬프트 문자 수 상한 (~200K 토큰 추정)
    llm_max_retries: int = 2  # LLM 출력 품질 재시도 (총 시도 = 1 + max_retries)

    # Circuit Breaker
    circuit_breaker_threshold: int = 3  # 연속 실패 횟수 → OPEN
    circuit_breaker_recovery_seconds: float = 30.0  # OPEN → HALF_OPEN 대기 시간

    # CORS
    cors_allow_origins: str = "http://localhost:5173,http://localhost:3000"

    # RAG (S5 Knowledge Base 연동)
    rag_enabled: bool = True
    kb_endpoint: str = "http://localhost:8002"
    rag_top_k: int = 5
    rag_min_score: float = 0.35  # 이 점수 미만의 RAG 결과는 제외

    # Confidence 가중치 (합계 = 1.0)
    confidence_w_grounding: float = 0.45
    confidence_w_deterministic: float = 0.30
    confidence_w_rag_coverage: float = 0.15
    confidence_w_schema: float = 0.10

    model_config = {"env_prefix": "AEGIS_", "env_file": ".env"}


settings = Settings()
