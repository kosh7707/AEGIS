"""벤치마크 메트릭 산출 — Recall + Noise density, 도구별/룰별 기여도."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SAFE_CWE_DISPLAY_NAMES = {
    "CWE-78": "OS_Command_Injection",
    "CWE-121": "Stack_Based_Buffer_Overflow",
    "CWE-122": "Heap_Based_Buffer_Overflow",
    "CWE-134": "Uncontrolled_Format_String",
    "CWE-190": "Integer_Overflow",
    "CWE-252": "Unchecked_Return_Value",
    "CWE-369": "Divide_by_Zero",
    "CWE-401": "Memory_Leak",
    "CWE-416": "Use_After_Free",
    "CWE-457": "Use_of_Uninitialized_Variable",
    "CWE-476": "NULL_Pointer_Dereference",
    "CWE-680": "Integer_Overflow_to_Buffer_Overflow",
}


def safe_cwe_display_name(cwe: str) -> str:
    return SAFE_CWE_DISPLAY_NAMES.get(cwe, cwe)


@dataclass
class ToolMetrics:
    """단일 도구의 CWE별 메트릭."""
    tool_name: str
    tp: int = 0
    fn: int = 0
    targeted_noise: int = 0   # target 파일 내 wrong-CWE findings
    portfolio_noise: int = 0  # non-target 파일 findings

    @property
    def noise_findings(self) -> int:
        """하위호환: targeted + portfolio 합산."""
        return self.targeted_noise + self.portfolio_noise

    @property
    def recall(self) -> float:
        total = self.tp + self.fn
        return self.tp / total if total > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name,
            "tp": self.tp,
            "fn": self.fn,
            "noise": self.noise_findings,
            "targetedNoise": self.targeted_noise,
            "portfolioNoise": self.portfolio_noise,
            "recall": round(self.recall, 4),
        }


@dataclass
class RuleMetrics:
    """단일 룰의 CWE별 메트릭."""
    rule_id: str
    tool: str
    tp: int = 0
    noise: int = 0  # target CWE 미매칭 findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "tool": self.tool,
            "tp": self.tp,
            "noise": self.noise,
        }


@dataclass
class CWEMetrics:
    """하나의 CWE에 대한 전체 메트릭."""
    cwe: str
    cwe_name: str
    total_files: int = 0
    combined_tp: int = 0       # 파일 단위 TP
    combined_fn: int = 0       # 파일 단위 FN
    targeted_noise: int = 0    # target 파일 내 wrong-CWE findings
    portfolio_noise: int = 0   # non-target 파일 findings (지원 파일 등)
    by_tool: dict[str, ToolMetrics] = field(default_factory=dict)
    by_rule: dict[str, RuleMetrics] = field(default_factory=dict)
    detected_files: list[str] = field(default_factory=list)
    missed_files: list[str] = field(default_factory=list)

    @property
    def combined_noise(self) -> int:
        """하위호환: targeted + portfolio 합산."""
        return self.targeted_noise + self.portfolio_noise

    @property
    def combined_recall(self) -> float:
        total = self.combined_tp + self.combined_fn
        return self.combined_tp / total if total > 0 else 0.0

    @property
    def noise_per_file(self) -> float:
        """파일당 평균 noise findings 수 (전체)."""
        return self.combined_noise / self.total_files if self.total_files > 0 else 0.0

    @property
    def targeted_noise_per_file(self) -> float:
        """파일당 평균 targeted noise findings 수."""
        return self.targeted_noise / self.total_files if self.total_files > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "cwe": self.cwe,
            "cweName": safe_cwe_display_name(self.cwe),
            "totalFiles": self.total_files,
            "combined": {
                "tp": self.combined_tp,
                "fn": self.combined_fn,
                "recall": round(self.combined_recall, 4),
                "noise": self.combined_noise,
                "targetedNoise": self.targeted_noise,
                "portfolioNoise": self.portfolio_noise,
                "noisePerFile": round(self.noise_per_file, 2),
                "targetedNoisePerFile": round(self.targeted_noise_per_file, 2),
            },
            "byTool": {
                name: tm.to_dict() for name, tm in self.by_tool.items()
            },
            "detectedFiles": self.detected_files[:20],
            "missedFiles": self.missed_files[:20],
        }
        if self.by_rule:
            result["byRule"] = {
                rid: rm.to_dict() for rid, rm in self.by_rule.items()
            }
        return result


@dataclass
class BenchmarkResult:
    """전체 벤치마크 결과."""
    cwe_results: dict[str, CWEMetrics] = field(default_factory=dict)

    @property
    def overall_recall(self) -> float:
        total_tp = sum(m.combined_tp for m in self.cwe_results.values())
        total_fn = sum(m.combined_fn for m in self.cwe_results.values())
        total = total_tp + total_fn
        return total_tp / total if total > 0 else 0.0

    @property
    def overall_noise_per_file(self) -> float:
        total_noise = sum(m.combined_noise for m in self.cwe_results.values())
        total_files = sum(m.total_files for m in self.cwe_results.values())
        return total_noise / total_files if total_files > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "results": {
                cwe: m.to_dict() for cwe, m in self.cwe_results.items()
            },
            "summary": {
                "overallRecall": round(self.overall_recall, 4),
                "overallNoisePerFile": round(self.overall_noise_per_file, 2),
                "totalTP": sum(m.combined_tp for m in self.cwe_results.values()),
                "totalFN": sum(m.combined_fn for m in self.cwe_results.values()),
                "totalNoise": sum(m.combined_noise for m in self.cwe_results.values()),
                "totalTargetedNoise": sum(m.targeted_noise for m in self.cwe_results.values()),
                "totalPortfolioNoise": sum(m.portfolio_noise for m in self.cwe_results.values()),
                "cweCount": len(self.cwe_results),
            },
        }

    def to_markdown(self, show_rules: bool = False) -> str:
        lines = ["# SAST Runner Benchmark Results", ""]
        lines.append(
            f"**Overall — Recall: {self.overall_recall:.1%}  |  "
            f"Noise/File: {self.overall_noise_per_file:.1f}**"
        )
        lines.append("")

        # CWE별 테이블
        tools = set()
        for m in self.cwe_results.values():
            tools.update(m.by_tool.keys())
        tools_sorted = sorted(tools)

        header = "| CWE | " + " | ".join(tools_sorted) + " | Recall | Noise/File |"
        sep = "|-----|" + "|".join(["------"] * len(tools_sorted)) + "|--------|------------|"
        lines.extend([header, sep])

        for cwe, m in sorted(self.cwe_results.items()):
            cells = []
            for t in tools_sorted:
                tm = m.by_tool.get(t)
                cells.append(f"{tm.recall:.0%}" if tm else "—")
            cells.append(f"**{m.combined_recall:.0%}**")
            cells.append(f"{m.noise_per_file:.1f}")
            lines.append(f"| {cwe} | " + " | ".join(cells) + " |")

        lines.append("")
        lines.append(f"Total files: {sum(m.total_files for m in self.cwe_results.values())}")

        # Per-rule 테이블 (옵션)
        if show_rules:
            lines.append("")
            lines.append("## Per-Rule Breakdown")
            lines.append("")
            for cwe, m in sorted(self.cwe_results.items()):
                if not m.by_rule:
                    continue
                lines.append(f"### {cwe}")
                lines.append("| Rule | Tool | TP | Noise |")
                lines.append("|------|------|---:|------:|")
                for rid, rm in sorted(m.by_rule.items(), key=lambda x: -x[1].tp):
                    lines.append(f"| {rid} | {rm.tool} | {rm.tp} | {rm.noise} |")
                lines.append("")

        return "\n".join(lines)
