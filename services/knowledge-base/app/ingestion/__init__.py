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

__all__ = [
    "DEFAULT_SOURCE_MANIFEST_PATH",
    "REQUIRED_COMPLETED_SOURCE_KINDS",
    "REQUIRED_SOURCE_KINDS",
    "ingest_fixture_corpus",
    "load_source_manifest",
    "manifest_coverage_summary",
    "validate_source_manifest",
]
