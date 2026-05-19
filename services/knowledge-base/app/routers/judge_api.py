"""Evidence-Grounded Judge API.

The Judge composes S5 ledger evidence into an answerability packet.  The result
is an S5 evidence-grounded knowledge verdict, not an S3 final security verdict.
"""

from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException

from app.context import set_request_id
from app.judge.models import JudgeQueryRequest
from app.judge.service import build_judge_answer
from app.ledger.repository import SQLiteLedgerRepository
from app.timeout import parse_timeout, run_sync_durable_write_with_deadline

router = APIRouter(prefix="/v1/judge", tags=["judge"])

_ledger_repository: SQLiteLedgerRepository | None = None


def set_ledger_repository(repo: SQLiteLedgerRepository | None) -> None:
    global _ledger_repository
    _ledger_repository = repo


def _require_ledger() -> SQLiteLedgerRepository:
    if _ledger_repository is None:
        raise HTTPException(503, "Judge ledger not initialized")
    return _ledger_repository


def _query_sync(repo: SQLiteLedgerRepository, req: JudgeQueryRequest) -> dict:
    return build_judge_answer(repo, req)


@router.post("/query")
async def query(
    req: JudgeQueryRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    repo = _require_ledger()
    return await run_sync_durable_write_with_deadline(deadline, "judge-query", _query_sync, repo, req)
