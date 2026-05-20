"""observability — JSON structured logging + agent context utilities."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from app.agent_runtime.context import get_request_id

_log_dir: Path | None = None

_AEGIS_LEVEL_NUMBERS = {
    logging.DEBUG: 20,
    logging.INFO: 30,
    logging.WARNING: 40,
    logging.ERROR: 50,
    logging.CRITICAL: 60,
}


class _JsonFormatter(logging.Formatter):
    """JSON structured log formatter with agent context support."""

    def __init__(self, service_name: str) -> None:
        super().__init__()
        self._service = service_name

    def format(self, record: logging.LogRecord) -> str:
        log_record: dict = {
            "level": _AEGIS_LEVEL_NUMBERS.get(record.levelno, record.levelno),
            "time": int(record.created * 1000),
            "service": self._service,
            "msg": record.getMessage(),
        }
        request_id = get_request_id()
        if request_id:
            log_record["requestId"] = request_id
        agent = getattr(record, "agent", None)
        if agent:
            log_record["agent"] = agent
        _extra = getattr(record, "_extra", None)
        if _extra:
            log_record.update(_extra)
        return json.dumps(log_record, ensure_ascii=False)


def _default_log_dir() -> Path:
    """Return the repository-level canonical log directory.

    ``observability.md`` and ``log-analyzer`` expect S3 logs at
    ``<AEGIS>/logs/aegis-analysis-agent.jsonl``.  This module lives one level
    deeper than other service logging modules
    (``services/analysis-agent/app/agent_runtime``), so a plain four-parent
    walk lands on ``<AEGIS>/services`` and silently writes to the wrong cache
    surface.  Keep this path centralized to avoid another split-brain log
    location.
    """

    return Path(__file__).resolve().parents[4] / "logs"


def setup_logging(
    service_name: str,
    log_dir: Path | None = None,
    *,
    service_id: str | None = None,
) -> Path:
    """JSON structured logging + JSONL file output. Returns log_dir.

    Args:
        service_name: 로그 파일명에 사용 (예: "aegis-analysis-agent" → aegis-analysis-agent.jsonl)
        service_id: 로그 JSON의 service 필드 (예: "s3-agent"). 미지정 시 service_name 사용.
    """
    global _log_dir
    if log_dir is None:
        log_dir = Path(os.environ.get("LOG_DIR", str(_default_log_dir())))
    log_dir.mkdir(parents=True, exist_ok=True)
    _log_dir = log_dir

    formatter = _JsonFormatter(service_id or service_name)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(log_dir / f"{service_name}.jsonl")
    file_handler.setFormatter(formatter)

    logging.root.handlers = [stdout_handler, file_handler]
    logging.root.setLevel(logging.INFO)

    return log_dir


def get_log_dir() -> Path:
    """Returns the configured log directory."""
    if _log_dir is not None:
        return _log_dir
    d = Path(os.environ.get("LOG_DIR", str(_default_log_dir())))
    d.mkdir(parents=True, exist_ok=True)
    return d


def agent_log(
    _logger: logging.Logger,
    msg: str,
    *,
    component: str,
    phase: str,
    turn: int | None = None,
    level: int = logging.INFO,
    **extra,
) -> None:
    """에이전트 컨텍스트를 포함한 구조화된 로그 출력."""
    agent_ctx: dict = {"component": component, "phase": phase}
    if turn is not None:
        agent_ctx["turn"] = turn
    agent_ctx.update(extra)
    _logger.log(level, msg, extra={"agent": agent_ctx})
