from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_root_etl_seed_uses_ledger_projection_contract():
    """S5 root ETL helper must follow the ledger-first Neo4j seed contract."""

    source = (REPO_ROOT / "scripts/knowledge-base/etl-build.sh").read_text(encoding="utf-8")

    assert "AEGIS_KB_LEDGER_URL" in source
    assert "--ledger-url \"$LEDGER_URL\"" in source
    assert "--neo4j-uri \"$NEO4J_URI\"" in source
    assert "--neo4j-user \"$NEO4J_USER\"" in source
    assert "--neo4j-password \"$NEO4J_PASSWORD\"" in source
    assert "scripts/neo4j-seed.py --qdrant-path" not in source


def test_root_etl_seed_sources_service_env_for_s5_owned_settings():
    """The S5 ETL helper should honor service-local .env before seed execution."""

    source = (REPO_ROOT / "scripts/knowledge-base/etl-build.sh").read_text(encoding="utf-8")
    env_load_index = source.index('load_env_file ".env"')
    seed_index = source.index("scripts/neo4j-seed.py")

    assert env_load_index < seed_index
    assert 'source ".env"' not in source
    assert "AEGIS_KB_*" in source
    assert 'LEDGER_URL="${AEGIS_KB_LEDGER_URL:-sqlite:///data/s5-ledger.sqlite}"' in source


def test_root_etl_helper_reports_repo_root_service_scripts_after_cd():
    """User-facing script hints must remain valid after the helper cd's into the service."""

    source = (REPO_ROOT / "scripts/knowledge-base/etl-build.sh").read_text(encoding="utf-8")

    assert 'REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"' in source
    assert '$REPO_ROOT/scripts/stop.sh' in source
    assert '$REPO_ROOT/scripts/start-knowledge-base.sh' in source
    assert '다음 단계: ./scripts/start-knowledge-base.sh' not in source


def test_root_etl_qdrant_lock_check_fails_closed_without_lsof():
    """If a Qdrant lock file exists and lsof is unavailable, ETL must not proceed."""

    source = (REPO_ROOT / "scripts/knowledge-base/etl-build.sh").read_text(encoding="utf-8")
    lock_check_index = source.index('[ -f "$QDRANT_PATH/.lock" ]')
    lsof_guard_index = source.index("command -v lsof")
    etl_start_index = source.index(".venv/bin/python scripts/threat-db/build.py")

    assert lock_check_index < lsof_guard_index < etl_start_index
    assert "Qdrant lock file exists but lsof is unavailable" in source


def test_root_etl_banner_redacts_ledger_url_userinfo():
    """The ETL banner must not print credentials from future non-sqlite ledger URLs."""

    source = (REPO_ROOT / "scripts/knowledge-base/etl-build.sh").read_text(encoding="utf-8")
    banner_index = source.index("Ledger:")

    assert "redact_url_userinfo" in source
    assert 'LEDGER_DISPLAY_URL="$(redact_url_userinfo "$LEDGER_URL")"' in source
    assert "Ledger: $LEDGER_DISPLAY_URL" in source
    assert "Ledger: $LEDGER_URL" not in source[banner_index - 80 : banner_index + 80]


def test_neo4j_seed_progress_output_redacts_connection_urls():
    """The seed script must align with the ETL banner and redact connection URLs."""

    source = (REPO_ROOT / "services/knowledge-base/scripts/neo4j-seed.py").read_text(encoding="utf-8")
    ledger_print_index = source.index("Ledger 연결")
    neo4j_print_index = source.index("Neo4j 연결")

    assert "from app.config import redact_url_for_log" in source
    assert "Ledger 연결: {redact_url_for_log(ledger_url)}" in source
    assert "Neo4j 연결: {redact_url_for_log(args.neo4j_uri)}" in source
    assert "Ledger 연결: {ledger_url}" not in source[ledger_print_index - 80 : ledger_print_index + 140]
    assert "Neo4j 연결: {args.neo4j_uri}" not in source[neo4j_print_index - 80 : neo4j_print_index + 140]
