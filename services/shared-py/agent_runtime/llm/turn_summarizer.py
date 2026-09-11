"""TurnSummarizer — 구조화 컨텍스트 압축.

claw-code compact.rs 패턴 참조:
- 도구 호출 이력/evidence ref 보존
- 재압축 시 이전 요약과 병합 (컨텍스트 유실 방지)
"""

from __future__ import annotations

import json
import re

# 재압축 시 이전 요약을 식별하기 위한 마커
_SUMMARY_MARKER = "[컨텍스트 압축:"
_PREV_SUMMARY_HEADER = "## 이전 압축 요약"

# claw-code compact.rs 패턴: Continuation Preamble
_CONTINUATION_PREAMBLE = (
    "이전 컨텍스트가 압축되었습니다. 아래는 압축 요약입니다.\n"
    "요약을 반복하거나 확인하지 마라. 바로 이어서 작업하라."
)
_RECENT_MESSAGES_NOTE = "최근 메시지는 원문 그대로 보존되었습니다."


class TurnSummarizer:
    """긴 대화를 압축한다. 도구 이력·evidence ref를 구조화 보존."""

    async def summarize(
        self,
        messages: list[dict],
        keep_last_n: int = 4,
        state_summary: dict | None = None,
    ) -> list[dict]:
        """system prompt + 마지막 N개 메시지를 유지한다.

        tool_call/tool 쌍이 깨지지 않도록, 절단점이 'tool' 메시지에
        걸리면 해당 assistant 메시지까지 포함하여 보존한다.
        """
        if len(messages) <= keep_last_n + 1:
            return messages

        system = messages[0] if messages and messages[0].get("role") == "system" else None
        prefix_len = 1 if system else 0

        cut_idx = len(messages) - keep_last_n

        # tool 메시지에서 시작하면 해당 assistant(tool_calls)까지 후퇴
        while cut_idx > prefix_len and messages[cut_idx].get("role") == "tool":
            cut_idx -= 1

        # 후퇴해도 prefix 경계까지 도달하면 압축 불가 -> 원본 반환
        if cut_idx <= prefix_len:
            return messages

        removed = messages[prefix_len:cut_idx]
        tail = messages[cut_idx:]
        omitted = len(removed)

        # 구조화 요약 생성
        summary_text = self._build_structured_summary(removed, omitted, state_summary)

        result: list[dict] = []
        if system:
            result.append(system)
        result.append({
            "role": "system",
            "content": summary_text,
        })
        result.extend(tail)
        return result

    def _build_structured_summary(
        self,
        removed_messages: list[dict],
        omitted_count: int,
        state_summary: dict | None,
    ) -> str:
        """제거되는 메시지에서 구조화 정보를 추출하여 요약을 생성한다."""
        sections: list[str] = [
            _CONTINUATION_PREAMBLE,
            f"{_SUMMARY_MARKER} 이전 {omitted_count}개 메시지 요약]",
        ]

        # 1. 이전 압축 요약 추출 (재압축 시 병합)
        prev_summary = self._extract_previous_summary(removed_messages)

        # 2. 도구 호출 이력 추출
        tool_entries = _extract_tool_summary(removed_messages)
        if tool_entries:
            sections.append("\n## 도구 호출 이력")
            for entry in tool_entries[:15]:  # 최대 15개
                sections.append(f"- {entry}")

        # 3. Evidence Refs 추출
        all_refs = _extract_evidence_refs(removed_messages)
        if all_refs:
            sections.append(f"\n## 수집된 Evidence Refs\n- {', '.join(sorted(all_refs))}")

        # 4. 참조 파일 추출 (claw-code collect_key_files 패턴)
        file_refs = _extract_file_references(removed_messages)
        if file_refs:
            sections.append(f"\n## 참조 파일\n- {', '.join(file_refs)}")

        # 5. 미완료 작업 추론 (claw-code infer_pending_work 패턴)
        pending = _infer_pending_work(removed_messages)
        if pending:
            sections.append("\n## 미완료 작업")
            for item in pending:
                sections.append(f"- {item}")

        # 6. 최근 사용자 요청 (claw-code collect_recent_role_summaries 패턴)
        recent_requests = _collect_recent_user_requests(removed_messages, limit=3)
        if recent_requests:
            sections.append("\n## 최근 사용자 요청")
            for req in recent_requests:
                sections.append(f"- {req}")

        # 7. 시스템 지시 메시지 추출
        injections = _extract_system_injections(removed_messages)
        if injections:
            sections.append("\n## 시스템 지시")
            for inj in injections[:5]:
                sections.append(f"- {inj}")

        # 8. 구조화 상태 요약 (세션에서 전달)
        if state_summary:
            sections.append(
                "\n## 세션 상태\n" + json.dumps(state_summary, ensure_ascii=False, indent=2)
            )

        # 9. 이전 압축 요약 병합 (claw-code merge_compact_summaries 패턴)
        if prev_summary:
            prev_highlights = _extract_highlights(prev_summary)
            if prev_highlights:
                sections.append(f"\n## 이전 압축 요약 (핵심)\n" + "\n".join(prev_highlights))

        # 10. 최근 메시지 보존 안내 (claw-code continuation preamble)
        sections.append(f"\n{_RECENT_MESSAGES_NOTE}")

        return "\n".join(sections)

    @staticmethod
    def _extract_previous_summary(messages: list[dict]) -> str:
        """제거 대상 메시지 중 이전 압축 요약이 있으면 추출한다."""
        for msg in messages:
            content = msg.get("content", "") or ""
            if content.startswith(_SUMMARY_MARKER) or content.startswith(_CONTINUATION_PREAMBLE):
                # 이전 요약 전체를 보존 (이전의 이전 요약 포함)
                return content
        return ""


def _extract_tool_summary(messages: list[dict]) -> list[str]:
    """assistant(tool_calls) + tool(result) 쌍에서 도구 호출 이력을 추출한다."""
    entries: list[str] = []

    # tool_calls를 가진 assistant 메시지 -> 다음 tool 메시지와 매핑
    i = 0
    while i < len(messages):
        msg = messages[i]
        tool_calls = msg.get("tool_calls", [])
        if msg.get("role") == "assistant" and tool_calls:
            # 이 assistant 이후의 tool result 메시지 수집
            tool_results: dict[str, dict] = {}
            j = i + 1
            while j < len(messages) and messages[j].get("role") == "tool":
                tr = messages[j]
                tool_results[tr.get("tool_call_id", "")] = tr
                j += 1

            for tc in tool_calls:
                func = tc.get("function", {})
                name = func.get("name", "?")
                args_raw = func.get("arguments", "{}")

                # 인자 요약 (첫 60자)
                try:
                    args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                    args_short = json.dumps(args, ensure_ascii=False)[:60]
                except (json.JSONDecodeError, TypeError):
                    args_short = str(args_raw)[:60]

                # 대응 결과에서 evidence refs와 성공 여부 추출
                tc_id = tc.get("id", "")
                result_msg = tool_results.get(tc_id, {})
                result_content = result_msg.get("content", "") or ""

                refs = _find_eref_in_text(result_content)
                ref_str = f" [{', '.join(refs)}]" if refs else ""

                # 실패 여부 판단 (error 키워드 포함)
                is_error = '"error"' in result_content[:100].lower()
                status = "실패" if is_error else "성공"

                entry = f"{name}({args_short}) → {status}{ref_str}"
                entries.append(entry)

            i = j  # tool 결과 이후로 건너뛰기
        else:
            i += 1

    return entries


def _extract_evidence_refs(messages: list[dict]) -> set[str]:
    """모든 메시지에서 eref- 패턴의 evidence ref를 추출한다."""
    refs: set[str] = set()
    for msg in messages:
        content = msg.get("content", "") or ""
        refs.update(_find_eref_in_text(content))
    return refs


def _extract_system_injections(messages: list[dict]) -> list[str]:
    """[시스템] 프리픽스가 붙은 user 메시지를 추출한다."""
    injections: list[str] = []
    for msg in messages:
        if msg.get("role") == "user":
            content = msg.get("content", "") or ""
            if content.startswith("[시스템]"):
                # 첫 100자만
                injections.append(content[:100].replace("\n", " "))
    return injections


_EREF_PATTERN = re.compile(r"eref-[\w-]+")


def _find_eref_in_text(text: str) -> list[str]:
    """텍스트에서 eref-xxx 패턴을 모두 추출한다."""
    return _EREF_PATTERN.findall(text)


# ── claw-code compact.rs 패턴: 파일 참조·미완료 작업·사용자 요청 추출 ──

_FILE_PATH_PATTERN = re.compile(
    r"(?:^|[\s\"'`(,])("            # 앞 경계
    r"(?:[\w./-]+/[\w./-]+\.\w+)"   # path/to/file.ext 형태
    r")"
)


def _extract_file_references(messages: list[dict]) -> list[str]:
    """메시지에서 참조된 파일 경로를 추출한다 (claw-code collect_key_files 패턴)."""
    files: set[str] = set()
    for msg in messages:
        content = msg.get("content", "") or ""
        # tool_calls의 arguments에서도 추출
        for tc in msg.get("tool_calls", []):
            func = tc.get("function", {})
            content += " " + func.get("arguments", "")

        for match in _FILE_PATH_PATTERN.findall(content):
            candidate = match.strip("\"'`(),")
            # 확장자 필터: 코드/빌드 파일만
            if candidate.rsplit(".", 1)[-1].lower() in (
                "c", "h", "cpp", "hpp", "py", "rs", "ts", "js", "json",
                "cmake", "mk", "sh", "yaml", "yml", "toml", "md",
            ):
                files.add(candidate)
    return sorted(files)[:8]


_PENDING_KEYWORDS = ("todo", "next", "pending", "follow up", "remaining", "남은", "다음")


def _infer_pending_work(messages: list[dict]) -> list[str]:
    """미완료 작업을 추론한다 (claw-code infer_pending_work 패턴).

    최근 메시지에서 TODO/next/pending 등의 키워드가 포함된 텍스트를 추출.
    """
    items: list[str] = []
    for msg in reversed(messages):
        content = msg.get("content", "") or ""
        if not content.strip():
            continue
        lowered = content.lower()
        if any(kw in lowered for kw in _PENDING_KEYWORDS):
            truncated = content[:160].replace("\n", " ").strip()
            if len(content) > 160:
                truncated += "…"
            items.append(truncated)
            if len(items) >= 3:
                break
    items.reverse()  # 시간순 복원
    return items


def _extract_highlights(summary_text: str) -> list[str]:
    """이전 압축 요약에서 핵심 정보(highlights)를 추출한다.

    claw-code extract_summary_highlights 패턴:
    - preamble, 빈 줄, 마커 줄은 제외
    - 도구 호출 이력, evidence refs, 참조 파일 등의 핵심 항목만 보존
    - 최대 15줄로 제한하여 재압축 시 크기 폭발 방지
    """
    highlights: list[str] = []
    skip_prefixes = (
        _CONTINUATION_PREAMBLE.split("\n")[0],  # preamble 첫 줄
        _RECENT_MESSAGES_NOTE,
        _SUMMARY_MARKER,
    )
    for line in summary_text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(p) for p in skip_prefixes):
            continue
        # ## 헤더는 보존하되 내용 줄은 truncate
        if stripped.startswith("##"):
            highlights.append(stripped)
        elif stripped.startswith("- "):
            # 항목 줄은 120자로 truncate
            if len(stripped) > 120:
                highlights.append(stripped[:120] + "…")
            else:
                highlights.append(stripped)
    return highlights[:15]


def _collect_recent_user_requests(messages: list[dict], limit: int = 3) -> list[str]:
    """최근 사용자 요청을 추출한다 (claw-code collect_recent_role_summaries 패턴)."""
    requests: list[str] = []
    for msg in reversed(messages):
        if msg.get("role") != "user":
            continue
        content = msg.get("content", "") or ""
        if not content.strip():
            continue
        # [시스템] 메시지는 제외 (별도 추출됨)
        if content.startswith("[시스템]"):
            continue
        truncated = content[:160].replace("\n", " ").strip()
        if len(content) > 160:
            truncated += "…"
        requests.append(truncated)
        if len(requests) >= limit:
            break
    requests.reverse()  # 시간순 복원
    return requests
