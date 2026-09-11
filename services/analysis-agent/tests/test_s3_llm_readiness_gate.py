"""Static S3 LLM readiness regression gate.

This mirrors the local `.omx/context/s3-llm-readiness-gate-20260503.py`
artifact in pytest so P10/P16/P18/P19 cannot silently regress in the durable
S3 test surface.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
S3_ROOTS = [REPO_ROOT / "services/analysis-agent", REPO_ROOT / "services/build-agent"]


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return f"{_dotted(node.func)}()"
    return type(node).__name__


def _literal(node: ast.AST) -> object:
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _field_keyword_value(field: ast.AnnAssign, keyword: str) -> object:
    assert isinstance(field.value, ast.Call)
    for kw in field.value.keywords:
        if kw.arg == keyword:
            return _literal(kw.value)
    return None


def test_s3_constraints_align_topk_with_s7_escape_hatch() -> None:
    for root in S3_ROOTS:
        path = root / "app/schemas/request.py"
        tree = ast.parse(path.read_text(), filename=str(path))
        constraints = next(node for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and node.name == "Constraints")
        fields = {
            stmt.target.id: stmt
            for stmt in constraints.body
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
        }

        assert {"enableThinking", "temperature", "topP", "topK", "minP", "presencePenalty", "repetitionPenalty"} <= set(fields)
        assert _field_keyword_value(fields["topK"], "ge") == -1


def test_s3_active_llm_call_sites_use_generation_presets_not_scalar_temperature() -> None:
    for root in S3_ROOTS:
        for relative in ["app/core/agent_loop.py", "app/routers/generate_poc_handler.py"]:
            path = root / relative
            if not path.exists():
                continue
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not _dotted(node.func).endswith(".call"):
                    continue
                keywords = {kw.arg for kw in node.keywords if kw.arg}
                assert "temperature" not in keywords, f"{path}:{node.lineno} uses scalar temperature"
                assert "generation" in keywords, f"{path}:{node.lineno} lacks generation preset"


def test_s3_p10_toolintent_p16_p19_static_readiness_markers_remain_present() -> None:
    for root in S3_ROOTS:
        caller = (root / "app/agent_runtime/llm/caller.py").read_text()
        policy = (root / "app/agent_runtime/llm/generation_policy.py").read_text()
        loop = (root / "app/core/agent_loop.py").read_text()
        boundary = (root / "app/agent_runtime/security/input_boundary.py").read_text()
        manager = (root / "app/agent_runtime/llm/message_manager.py").read_text()
        tool_intent = (root / "app/tools/tool_intent.py").read_text()

        assert "warnings.warn" in caller and "DeprecationWarning" in caller
        assert "body.update(controls.to_gateway_fields())" in caller
        assert "Deprecation milestone" in policy and "top_k < -1" in policy
        assert 'return "required"' not in loop
        assert "ToolIntent runtime" in loop and "_call_tool_intent_with_retry" in loop
        assert "build_tool_intent_messages" in tool_intent and "tool_intent_to_request" in tool_intent
        assert "UNTRUSTED TOOL RESULT" in boundary and "UNTRUSTED SOURCE CONTENT" in boundary
        assert "BOUNDARY-MARKER-NEUTRALIZED" in boundary
        assert "render_tool_result_for_llm" in manager

    poc_handler = (S3_ROOTS[0] / "app/routers/generate_poc_handler.py").read_text()
    assert "render_untrusted_source_for_llm" in poc_handler


def test_eval_runner_remains_in_generation_tuple_gate() -> None:
    eval_runner = (S3_ROOTS[0] / "eval/eval_runner.py").read_text()

    assert "THINKING_GENERAL.to_gateway_fields()" in eval_runner
    assert "TimeoutDefaults.TASK_CLIENT_READ_SECONDS" in eval_runner
    assert "chat_template_kwargs" not in eval_runner  # tuple comes only from the named preset serializer
    assert "temperature=0.3" not in eval_runner
