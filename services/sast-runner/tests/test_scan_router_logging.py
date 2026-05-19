from __future__ import annotations

import ast
from pathlib import Path


ROUTER_SCAN = Path(__file__).resolve().parents[1] / "app" / "routers" / "scan.py"

FORBIDDEN_LOG_EXTRA_KEYS = {
    "projectPath",
    "buildCommand",
    "requestedBuildCommand",
    "effectiveBuildCommand",
    "compileCommandsPath",
    "sdkId",
}

LOGGER_METHODS = {"debug", "info", "warning", "error", "exception", "critical"}


def _is_logger_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in LOGGER_METHODS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "logger"
    )


def _literal_extra_keys(node: ast.Call) -> list[tuple[int, str]]:
    for keyword in node.keywords:
        if keyword.arg != "extra" or not isinstance(keyword.value, ast.Dict):
            continue
        keys: list[tuple[int, str]] = []
        for key in keyword.value.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                keys.append((key.lineno, key.value))
        return keys
    return []


def test_scan_router_logger_extras_do_not_emit_raw_path_command_or_sdk_identity_keys() -> None:
    tree = ast.parse(ROUTER_SCAN.read_text(), filename=str(ROUTER_SCAN))

    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_logger_call(node):
            continue
        for lineno, key in _literal_extra_keys(node):
            if key in FORBIDDEN_LOG_EXTRA_KEYS:
                offenders.append(f"{ROUTER_SCAN.name}:{lineno}:{key}")

    assert offenders == []
