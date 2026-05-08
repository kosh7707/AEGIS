from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from app.core.evidence_catalog import EvidenceCatalog
from app.schemas.response import Claim
from app.types import ClaimStatus


@dataclass(frozen=True)
class ClaimEvidenceDiagnosis:
    requiredEvidence: list[str] = field(default_factory=list)
    presentEvidence: list[str] = field(default_factory=list)
    missingEvidence: list[str] = field(default_factory=list)
    evidenceTrail: list[str] = field(default_factory=list)
    invalidRefs: list[str] = field(default_factory=list)
    family: str | None = None
    status: ClaimStatus = ClaimStatus.CANDIDATE


_FAMILY_REQUIRED_SLOTS: dict[str, tuple[str, ...]] = {
    "command_injection": (
        "source_location",
        "sink_or_dangerous_api",
        "caller_chain_or_source_slice",
    ),
    "path_traversal": (
        "source_location",
        "sink_or_dangerous_api",
        "source_slice",
    ),
    "buffer_bounds": (
        "source_location",
        "source_slice",
        "sink_or_dangerous_api",
    ),
    "null_deref": (
        "source_location",
        "source_slice",
    ),
    "integer_overflow": (
        "source_location",
        "source_slice",
    ),
    "credential_exposure": (
        "source_location",
        "source_slice",
    ),
    "dependency_vulnerability": (
        "library_origin",
    ),
}

_CWE_FAMILY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("CWE-78", "command_injection"),
    ("CWE-77", "command_injection"),
    ("CWE-22", "path_traversal"),
    ("CWE-23", "path_traversal"),
    ("CWE-36", "path_traversal"),
    ("CWE-120", "buffer_bounds"),
    ("CWE-121", "buffer_bounds"),
    ("CWE-122", "buffer_bounds"),
    ("CWE-787", "buffer_bounds"),
    ("CWE-119", "buffer_bounds"),
    ("CWE-476", "null_deref"),
    ("CWE-190", "integer_overflow"),
    ("CWE-191", "integer_overflow"),
    ("CWE-798", "credential_exposure"),
    ("CWE-259", "credential_exposure"),
    ("CWE-321", "credential_exposure"),
    ("CWE-532", "credential_exposure"),
)


def derive_required_evidence(
    claim: Claim,
    catalog: EvidenceCatalog,
    mode: str = "product",
) -> list[str]:
    """Return deterministic evidence slots required before a claim is final.

    LLM-provided ``requiredEvidence`` may add requirements, but it may not
    weaken the canonical family slot policy from the S3 state-machine docs.
    """
    family = _infer_family(claim, catalog)
    required = ["local_or_derived_support", *_FAMILY_REQUIRED_SLOTS.get(family, ())]
    if _is_sast_backed_claim(claim, catalog):
        required.append("sast_finding")
    required.extend(slot for slot in claim.requiredEvidence if isinstance(slot, str) and slot)
    return list(dict.fromkeys(required))


def diagnose_claim_evidence(
    claim: Claim,
    catalog: EvidenceCatalog,
    mode: str = "product",
    allowed_local_refs: set[str] | None = None,
) -> ClaimEvidenceDiagnosis:
    """Diagnose whether claim refs satisfy local/derived-local grounding."""
    required = derive_required_evidence(claim, catalog, mode)
    present: set[str] = set()
    trail: list[str] = []
    invalid_refs: list[str] = []
    allowed_local_refs = allowed_local_refs or set()

    for ref_id in claim.supportingEvidenceRefs:
        entry = catalog.get(ref_id)
        if entry is None:
            if ref_id in allowed_local_refs:
                present.add("local_or_derived_support")
                trail.append(ref_id)
                continue
            invalid_refs.append(ref_id)
            continue
        if entry.can_support_claim:
            trail.append(ref_id)
            present.update(_slots_filled_by_entry(entry))

    missing = [slot for slot in required if slot not in present]
    if claim.supportingEvidenceRefs and len(invalid_refs) == len(claim.supportingEvidenceRefs):
        status = ClaimStatus.REJECTED
    else:
        status = ClaimStatus.GROUNDED if not missing and not invalid_refs else ClaimStatus.UNDER_EVIDENCED
    return ClaimEvidenceDiagnosis(
        requiredEvidence=required,
        presentEvidence=[slot for slot in required if slot in present],
        missingEvidence=missing,
        evidenceTrail=trail,
        invalidRefs=invalid_refs,
        family=_infer_family(claim, catalog),
        status=status,
    )


def transition_claim_status(
    claim: Claim,
    diagnosis: ClaimEvidenceDiagnosis,
    *,
    timestamp_ms: int | None = None,
) -> Claim:
    """Apply deterministic lifecycle status and slot fields to a claim."""
    from_status = claim.status
    status = diagnosis.status
    if claim.status == ClaimStatus.REJECTED:
        status = ClaimStatus.REJECTED
    elif claim.status == ClaimStatus.NEEDS_HUMAN_REVIEW:
        status = ClaimStatus.NEEDS_HUMAN_REVIEW
    revision = {
        "fromStatus": _status_value(from_status),
        "toStatus": _status_value(status),
        "reason": _revision_reason(claim.status, status, diagnosis),
        "timestampMs": timestamp_ms if timestamp_ms is not None else int(time.time() * 1000),
    }
    return claim.model_copy(update={
        "status": status,
        "requiredEvidence": diagnosis.requiredEvidence,
        "presentEvidence": diagnosis.presentEvidence,
        "missingEvidence": diagnosis.missingEvidence,
        "evidenceTrail": diagnosis.evidenceTrail,
        "revisionHistory": [*claim.revisionHistory, revision],
    })


def _slots_filled_by_entry(entry) -> set[str]:
    roles = set(entry.roles)
    slots = {"local_or_derived_support"}
    if entry.evidence_class == "derived" and entry.source_local_refs:
        roles.add("derived_from_local")
    if entry.file or roles.intersection({"source_location", "function_symbol"}):
        slots.add("source_location")
    if "source_slice" in roles:
        slots.add("source_slice")
        slots.add("caller_chain_or_source_slice")
    if entry.sink or "sink_or_dangerous_api" in roles:
        slots.add("sink_or_dangerous_api")
    if "caller_chain" in roles:
        slots.add("caller_chain")
        slots.add("caller_chain_or_source_slice")
    if "input_or_dataflow_path" in roles:
        slots.add("input_or_dataflow_path")
    if "build_context" in roles:
        slots.add("build_context")
    if "target_metadata" in roles:
        slots.add("target_metadata")
    if "library_origin" in roles:
        slots.add("library_origin")
    if "sast_finding" in roles:
        slots.add("sast_finding")
    return slots


def _status_value(status: ClaimStatus | str) -> str:
    return status.value if hasattr(status, "value") else str(status)


def _revision_reason(
    previous_status: ClaimStatus,
    status: ClaimStatus,
    diagnosis: ClaimEvidenceDiagnosis,
) -> str:
    if previous_status == ClaimStatus.REJECTED:
        return "preserve_rejected"
    if previous_status == ClaimStatus.NEEDS_HUMAN_REVIEW and status == ClaimStatus.NEEDS_HUMAN_REVIEW:
        if diagnosis.missingEvidence:
            return "nhr_held_under_evidenced"
        return "preserve_human_review"
    if status == ClaimStatus.REJECTED and diagnosis.invalidRefs:
        return "rejected:all_invalid_refs"
    if diagnosis.missingEvidence:
        return f"missing:{','.join(diagnosis.missingEvidence)}"
    if diagnosis.invalidRefs:
        return f"invalid_refs:{','.join(diagnosis.invalidRefs)}"
    return "grounded"


def _is_sast_backed_claim(claim: Claim, catalog: EvidenceCatalog) -> bool:
    for ref_id in claim.supportingEvidenceRefs:
        entry = catalog.get(ref_id)
        if entry and "sast_finding" in entry.roles:
            return True
    return False


def _infer_family(claim: Claim, catalog: EvidenceCatalog | None = None) -> str:
    text_parts = [claim.statement, claim.detail, claim.location]
    if catalog is not None:
        for ref_id in claim.supportingEvidenceRefs:
            entry = catalog.get(ref_id)
            if entry is None:
                continue
            text_parts.extend([entry.cwe_id, entry.rule_id, entry.summary, entry.sink])
    text = " ".join(part or "" for part in text_parts).lower()
    cwe_family = _family_from_cwe_text(text)
    if cwe_family:
        return cwe_family
    if re.search(r"\b(command injection|cwe-78|popen|system\s*\(|exec(?:ve|v|le|lp|l|p)?\b)", text):
        return "command_injection"
    if re.search(r"\b(path traversal|cwe-22|\.\./|open\s*\()", text):
        return "path_traversal"
    if re.search(r"\b(buffer|bounds|overflow|cwe-120|cwe-787|memcpy|strcpy|sprintf)\b", text):
        return "buffer_bounds"
    if re.search(r"\b(null|cwe-476)\b", text):
        return "null_deref"
    if re.search(r"\b(integer overflow|cwe-190|truncation)\b", text):
        return "integer_overflow"
    if re.search(
        r"\b(cwe-798|cwe-259|cwe-321|cwe-532|hardcoded[- ]credential|default secret|"
        r"default credential|credential exposure|credential logging|psk|secret)\b",
        text,
    ):
        return "credential_exposure"
    if re.search(r"\b(cve-\d{4}-\d+|dependency|library|package|version)\b", text):
        return "dependency_vulnerability"
    return "generic"


def _family_from_cwe_text(text: str) -> str | None:
    normalized = text.upper()
    for cwe, family in _CWE_FAMILY_PREFIXES:
        if cwe in normalized:
            return family
    return None
