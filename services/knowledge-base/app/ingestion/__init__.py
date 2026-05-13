"""Corpus ingestion v1 fixtures and harness."""

from .corpus_ingestion import (
    DEFAULT_SOURCE_MANIFEST_PATH,
    REQUIRED_COMPLETED_SOURCE_KINDS,
    REQUIRED_SOURCE_KINDS,
    ingest_fixture_corpus,
    load_source_manifest,
    manifest_coverage_summary,
    validate_source_manifest,
)
from .cached_artifact_adapter import verify_cached_artifacts
from .source_coverage_matrix import (
    DEFAULT_SOURCE_COVERAGE_MATRIX_PATH,
    evaluate_source_coverage,
    load_source_coverage_matrix,
    validate_source_coverage,
)

__all__ = [
    "DEFAULT_SOURCE_MANIFEST_PATH",
    "DEFAULT_SOURCE_COVERAGE_MATRIX_PATH",
    "REQUIRED_COMPLETED_SOURCE_KINDS",
    "REQUIRED_SOURCE_KINDS",
    "evaluate_source_coverage",
    "ingest_fixture_corpus",
    "load_source_manifest",
    "load_source_coverage_matrix",
    "manifest_coverage_summary",
    "validate_source_manifest",
    "validate_source_coverage",
    "verify_cached_artifacts",
]
