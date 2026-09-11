"""Shared parser for JSON-object LLM responses."""

from __future__ import annotations

import json
import re


class V1ResponseParser:
    """Parse a raw LLM response into an Assessment-like dict."""

    def parse(self, raw: str) -> dict | None:
        text = _strip_thinking(raw)

        data = self._try_parse(text)
        if data is not None:
            return data

        match = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
        if match:
            data = self._try_parse(match.group(1).strip())
            if data is not None:
                return data

        return self._try_extract_json_object(text)

    @staticmethod
    def _try_parse(text: str) -> dict | None:
        try:
            data = json.loads(text, strict=False)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _try_extract_json_object(text: str) -> dict | None:
        start = text.find("{")
        if start < 0:
            return None
        try:
            data, _ = json.JSONDecoder(strict=False).raw_decode(text[start:])
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None


def _strip_thinking(raw: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL)
    while "<think>" in text:
        start = text.find("<think>")
        json_start = text.find("{", start)
        if json_start < 0:
            text = text[:start]
            break
        text = text[:start] + text[json_start:]
    return text.strip()
