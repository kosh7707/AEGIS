"""Machine-readable S5 contract surfaces."""

from app.contracts.acquisition import (
    ACQUISITION_READINESS_CONTRACT_VERSION,
    KNOWLEDGE_COVERAGE_CONTRACT_VERSION,
    apply_no_hit_safety,
    contract_snapshot,
    evaluate_no_hit_eligibility,
    runtime_semantics_metadata,
)

__all__ = [
    "ACQUISITION_READINESS_CONTRACT_VERSION",
    "KNOWLEDGE_COVERAGE_CONTRACT_VERSION",
    "apply_no_hit_safety",
    "contract_snapshot",
    "evaluate_no_hit_eligibility",
    "runtime_semantics_metadata",
]
