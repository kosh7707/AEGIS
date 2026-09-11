"""SystemPromptBuilder — 빌더 패턴 시스템 프롬프트 조립기.

claw-code prompt.rs 패턴 참조:
- 섹션 기반 조립 (이름 + 내용)
- 환경 정보 동적 주입
- 예산 정보 동적 주입
- 동적 경계 마커 (정적 캐시 vs 동적 구간 분리)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.agent_runtime.schemas.agent import BudgetState


# 정적/동적 프롬프트 경계 — 이 마커 이전은 캐시 가능, 이후는 세션별 변동
DYNAMIC_BOUNDARY = "__SYSTEM_PROMPT_DYNAMIC_BOUNDARY__"


class SystemPromptBuilder:
    """시스템 프롬프트를 섹션 단위로 조립하는 빌더.

    Usage::

        prompt = (
            SystemPromptBuilder()
            .add_section("역할", "당신은 자동차 임베디드 보안 분석가입니다.")
            .add_section("임무", "SAST 결과를 심층 분석하라.")
            .with_environment(platform="linux", cwd="/project", date="2026-04-02")
            .with_budget(budget_state)
            .add_section("규칙", "JSON만 출력하라.")
            .set_suffix("추가 지침: 최종 응답은 요구된 출력 형식을 엄격히 따른다.")
            .build()
        )
    """

    def __init__(self) -> None:
        self._sections: list[tuple[str, str]] = []
        self._environment: dict[str, str] | None = None
        self._budget_text: str | None = None
        self._suffix: str | None = None
        self._dynamic_boundary_after: str | None = None

    def add_section(self, name: str, content: str) -> SystemPromptBuilder:
        """이름 있는 섹션을 추가한다. 순서가 보존된다."""
        self._sections.append((name, content))
        return self

    def with_environment(
        self,
        *,
        platform: str = "unknown",
        cwd: str = "unknown",
        date: str = "unknown",
        model: str | None = None,
    ) -> SystemPromptBuilder:
        """환경 정보 섹션을 설정한다."""
        self._environment = {
            "platform": platform,
            "cwd": cwd,
            "date": date,
        }
        if model:
            self._environment["model"] = model
        return self

    def with_budget(self, budget: BudgetState) -> SystemPromptBuilder:
        """도구 예산 섹션을 BudgetState에서 동적 생성한다."""
        lines = [
            "## 도구 예산",
            f"- cheap: 최대 {budget.max_cheap_calls}회",
            f"- medium: 최대 {budget.max_medium_calls}회",
            f"- 합계: 최대 {budget.max_steps} 턴",
            "예산을 초과하면 도구가 비활성화되고 즉시 보고서를 작성해야 한다.",
            "높은 심각도 finding에 도구 예산을 우선 배분하라.",
        ]
        self._budget_text = "\n".join(lines)
        return self

    def set_suffix(self, suffix: str) -> SystemPromptBuilder:
        """프롬프트 끝에 추가할 접미사를 설정한다."""
        self._suffix = suffix
        return self

    def mark_dynamic_boundary(self, after_section: str) -> SystemPromptBuilder:
        """지정된 섹션 이후에 동적 경계 마커를 삽입한다.

        경계 이전 = 정적 (캐시 가능), 경계 이후 = 동적 (세션별 변동).
        """
        self._dynamic_boundary_after = after_section
        return self

    def build(self) -> str:
        """모든 섹션을 조합하여 최종 시스템 프롬프트를 반환한다."""
        parts: list[str] = []

        for name, content in self._sections:
            # 섹션 이름이 ##으로 시작하면 그대로 사용, 아니면 ## 헤더 추가
            if content.startswith("#"):
                parts.append(content)
            else:
                parts.append(f"## {name}\n{content}")

            # 동적 경계 마커 삽입
            if self._dynamic_boundary_after and name == self._dynamic_boundary_after:
                parts.append(DYNAMIC_BOUNDARY)

        # 환경 정보 주입
        if self._environment:
            env_lines = ["## 환경 정보"]
            for key, val in self._environment.items():
                env_lines.append(f"- {key}: {val}")
            parts.append("\n".join(env_lines))

        # 예산 정보 주입
        if self._budget_text:
            parts.append(self._budget_text)

        result = "\n\n".join(parts)

        # 접미사
        if self._suffix:
            result += f"\n\n{self._suffix}"

        return result

    def section_count(self) -> int:
        """등록된 섹션 수를 반환한다."""
        return len(self._sections)

    def has_section(self, name: str) -> bool:
        """특정 이름의 섹션이 존재하는지 확인한다."""
        return any(n == name for n, _ in self._sections)
