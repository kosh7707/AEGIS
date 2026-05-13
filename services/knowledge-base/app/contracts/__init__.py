"""Machine-readable S5 contract surfaces."""

from app.contracts.acquisition import (
    ACQUISITION_READINESS_CONTRACT_VERSION,
    KNOWLEDGE_COVERAGE_CONTRACT_VERSION,
    apply_no_hit_safety,
    contract_snapshot,
    evaluate_no_hit_eligibility,
    runtime_semantics_metadata,
)
from app.contracts.source_kg import (
    SOURCE_CODE_KG_CONTRACT_VERSION,
    source_code_kg_contract_snapshot,
)

__all__ = [
    "ACQUISITION_READINESS_CONTRACT_VERSION",
    "KNOWLEDGE_COVERAGE_CONTRACT_VERSION",
    "SOURCE_CODE_KG_CONTRACT_VERSION",
    "apply_no_hit_safety",
    "contract_snapshot",
    "evaluate_no_hit_eligibility",
    "runtime_semantics_metadata",
    "source_code_kg_contract_snapshot",
]
