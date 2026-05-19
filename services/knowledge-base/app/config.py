import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic_settings import BaseSettings


SENSITIVE_QUERY_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
)
URL_IN_TEXT_PATTERN = re.compile(r"(?P<url>[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>'\"]+)")


def _redact_query_for_log(query: str) -> str:
    if not query:
        return ""
    redacted_pairs = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        normalized = key.lower().replace("-", "_")
        if any(fragment in normalized for fragment in SENSITIVE_QUERY_KEY_FRAGMENTS):
            redacted_pairs.append((key, "***"))
        else:
            redacted_pairs.append((key, value))
    return urlencode(redacted_pairs, doseq=True, safe="*")


def redact_url_for_log(url: str | None) -> str:
    """Return a log-safe URL by redacting userinfo credentials when present."""

    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<invalid-url>"
    query = _redact_query_for_log(parts.query)
    if not parts.netloc:
        if query == parts.query:
            return url
        if parts.scheme and url.startswith(f"{parts.scheme}:///"):
            fragment = f"#{parts.fragment}" if parts.fragment else ""
            return f"{parts.scheme}://{parts.path}?{query}{fragment}"
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
    if "@" not in parts.netloc:
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
    host_port = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, f"***:***@{host_port}", parts.path, query, parts.fragment))


def redact_urls_in_text_for_log(value: str | None) -> str:
    """Redact credential-bearing URL substrings without treating surrounding text as a URL."""

    if not value:
        return ""
    return URL_IN_TEXT_PATTERN.sub(lambda match: redact_url_for_log(match.group("url")), value)


class Settings(BaseSettings):
    qdrant_path: str = "data/qdrant"
    qdrant_url: str | None = None
    qdrant_api_key: str | None = None
    rag_top_k: int = 5
    rag_min_score: float = 0.35
    graph_depth: int = 2

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "aegis-kb"

    nvd_api_key: str = ""
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_rate_delay: float = 1.0
    nvd_cache_ttl: int = 86400
    nvd_cache_file: str = "data/cve-cache.json"
    nvd_batch_concurrency: int = 5
    epss_enabled: bool = True
    kev_ttl: int = 3600

    rrf_k: int = 60
    memory_limit_per_project: int = 1000
    ledger_url: str = "sqlite:///data/s5-ledger.sqlite"
    target_context_store_file: str = "data/target-contexts.json"
    scoring_policy_path: str = "config/scoring-policy-v1.json"
    default_scoring_profile: str = "balanced"

    model_config = {"env_prefix": "AEGIS_KB_", "env_file": ".env", "extra": "ignore"}


settings = Settings()
