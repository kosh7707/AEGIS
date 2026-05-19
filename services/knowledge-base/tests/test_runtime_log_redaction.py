from pathlib import Path

from app.config import redact_url_for_log


def test_redact_url_for_log_strips_userinfo_from_future_ledger_urls():
    """Runtime startup logs must not expose credentials from non-sqlite ledger URLs."""

    raw = "postgresql://s5_user:super-secret@ledger.internal:5432/aegis"

    redacted = redact_url_for_log(raw)

    assert redacted == "postgresql://***:***@ledger.internal:5432/aegis"
    assert "s5_user" not in redacted
    assert "super-secret" not in redacted


def test_redact_url_for_log_masks_sensitive_query_parameters():
    """Credential-like URL query parameters must not survive shared log redaction."""

    raw = (
        "https://q_user:q_password@qdrant.internal:6333/collections"
        "?api_key=q-api-secret&timeout=30&access_token=q-token&sslmode=require"
    )

    redacted = redact_url_for_log(raw)

    assert redacted == (
        "https://***:***@qdrant.internal:6333/collections"
        "?api_key=***&timeout=30&access_token=***&sslmode=require"
    )
    assert "q_user" not in redacted
    assert "q_password" not in redacted
    assert "q-api-secret" not in redacted
    assert "q-token" not in redacted


def test_redact_url_for_log_leaves_sqlite_ledger_urls_readable():
    assert redact_url_for_log("sqlite:///data/s5-ledger.sqlite") == "sqlite:///data/s5-ledger.sqlite"


def test_runtime_startup_ledger_log_uses_redacted_url():
    source = Path("app/main.py").read_text(encoding="utf-8")
    banner_index = source.index("Target context SQLite ledger 초기화 완료")
    banner_window = source[banner_index : banner_index + 260]

    assert "redact_url_for_log(settings.ledger_url)" in source
    assert "settings.ledger_url," not in banner_window


def test_runtime_startup_qdrant_log_uses_redacted_url():
    source = Path("app/main.py").read_text(encoding="utf-8")
    banner_index = source.index("Qdrant 초기화 완료")
    banner_window = source[banner_index : banner_index + 260]

    assert "redact_url_for_log(settings.qdrant_url)" in source
    assert "settings.qdrant_url or settings.qdrant_path" not in banner_window
