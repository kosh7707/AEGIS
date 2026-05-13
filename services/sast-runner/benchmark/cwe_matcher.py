"""CWE 매칭 — finding의 CWE 정보와 ground truth를 비교."""

from __future__ import annotations

from app.schemas.response import SastFinding

# CWE 계층 관계: 부모 → 자식들 (부모가 보고되면 자식 ground truth도 매칭)
CWE_HIERARCHY: dict[str, list[str]] = {
    "CWE-119": ["CWE-120", "CWE-121", "CWE-122", "CWE-787", "CWE-125", "CWE-126"],
    "CWE-120": ["CWE-121", "CWE-122"],
    "CWE-190": ["CWE-680"],
    "CWE-416": ["CWE-415"],
    "CWE-664": ["CWE-416", "CWE-476"],
}

# 역방향: 자식 → 부모들 (전처리)
_CHILD_TO_PARENTS: dict[str, set[str]] = {}


def _build_child_to_parents() -> None:
    if _CHILD_TO_PARENTS:
        return
    for parent, children in CWE_HIERARCHY.items():
        for child in children:
            _CHILD_TO_PARENTS.setdefault(child, set()).add(parent)


def extract_cwes(finding: SastFinding) -> set[str]:
    """finding에서 CWE 목록 추출 (정규화)."""
    cwes: set[str] = set()
    meta = finding.metadata or {}

    # metadata.cweId: "CWE-78" (S4 standard representative CWE)
    cwe_id = meta.get("cweId")
    if isinstance(cwe_id, str):
        normalized = cwe_id.upper().strip()
        if not normalized.startswith("CWE-"):
            normalized = f"CWE-{normalized}"
        cwes.add(normalized)

    # metadata.cwe: ["CWE-78"] 또는 ["CWE-120", "CWE-242"]
    for cwe in meta.get("cwe", []):
        if isinstance(cwe, str):
            # "CWE-78" 형식 정규화
            normalized = cwe.upper().strip()
            if not normalized.startswith("CWE-"):
                normalized = f"CWE-{normalized}"
            cwes.add(normalized)

    # metadata.evidenceResolution.cwe.id: deterministic evidence projection
    evidence_resolution = meta.get("evidenceResolution")
    if isinstance(evidence_resolution, dict):
        cwe_info = evidence_resolution.get("cwe")
        if isinstance(cwe_info, dict):
            cwe = cwe_info.get("id")
            if isinstance(cwe, str):
                normalized = cwe.upper().strip()
                if not normalized.startswith("CWE-"):
                    normalized = f"CWE-{normalized}"
                cwes.add(normalized)

    return cwes


def matches_cwe(
    finding: SastFinding,
    target_cwe: str,
) -> bool:
    """finding이 target CWE와 매칭되는지 판정.

    3단계 매칭:
    1. 직접 매칭 (exact)
    2. 계층 매칭: finding이 부모 CWE를 보고하고 target이 자식이면 매칭
    3. 계층 매칭: finding이 자식 CWE를 보고하고 target이 부모이면 매칭
    """
    _build_child_to_parents()

    found_cwes = extract_cwes(finding)
    if not found_cwes:
        return False

    target = target_cwe.upper().strip()

    # 1. 직접 매칭
    if target in found_cwes:
        return True

    # 2. finding이 부모 CWE 보고 → target 자식과 매칭
    for parent_cwe, children in CWE_HIERARCHY.items():
        if parent_cwe in found_cwes and target in children:
            return True

    # 3. finding이 자식 CWE 보고 → target 부모와 매칭
    parents = _CHILD_TO_PARENTS.get(target, set())
    if found_cwes & parents:
        return True

    return False


def classify_findings(
    findings: list[SastFinding],
    target_cwe: str,
) -> dict[str, list[SastFinding]]:
    """findings를 target CWE 기준으로 TP/other로 분류.

    Returns:
        {"matched": [...], "unmatched": [...]}
    """
    matched = []
    unmatched = []
    for f in findings:
        if matches_cwe(f, target_cwe):
            matched.append(f)
        else:
            unmatched.append(f)
    return {"matched": matched, "unmatched": unmatched}
