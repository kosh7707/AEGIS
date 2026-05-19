import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.agent_runtime.observability import setup_logging
from app.routers import tasks
from app.paper import api as paper_api

_SERVICE_NAME = "aegis-analysis-agent"
_log_dir = setup_logging(_SERVICE_NAME, service_id="s3-agent")

# LLM 교환 로그
_exchange_handler = logging.FileHandler(_log_dir / "llm-exchange.jsonl")
_exchange_handler.setFormatter(logging.Formatter("%(message)s"))
_exchange_logger = logging.getLogger("llm_exchange")
_exchange_logger.handlers = [_exchange_handler]
_exchange_logger.setLevel(logging.INFO)
_exchange_logger.propagate = False

# LLM 호출별 전문 덤프 디렉토리
(_log_dir / "llm-dumps").mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # RAG: S5 Knowledge Base HTTP 클라이언트 초기화
    threat_search = None
    if settings.rag_enabled:
        from app.rag.threat_search import ThreatSearch
        threat_search = ThreatSearch(settings.kb_endpoint)
        logger.info("RAG 활성화: kb_endpoint=%s", settings.kb_endpoint)

    _app.state.threat_search = threat_search

    logger.info(
        "Analysis Agent started (mode: %s, rag: %s, concurrency: %d)",
        settings.llm_mode,
        "enabled" if threat_search else "disabled",
        settings.llm_concurrency,
    )
    yield

    if threat_search:
        await threat_search.close()


app = FastAPI(
    title="AEGIS Analysis Agent",
    description="자동차 전장부품 사이버보안 검증 프레임워크 - 에이전트 기반 분석 서비스",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tasks.router)
app.include_router(paper_api.router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8001, reload=True)
