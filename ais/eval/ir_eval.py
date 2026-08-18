"""零依赖的 IR 评估器（v1 默认）：直接解释 PolicyIR，与 emit/rego.py 的 Rego 语义一一对应。

opa 评估器（可选）见 eval/opa_eval.py。两者决策必须在交叉测试中一致（防漂移）。
"""
from __future__ import annotations

import re

from ..core.models import Effect, MatchOp, PolicyIR, ToolCall, TriggerEvent


def _resolve(field: str, data: dict):
    """字段路径导航，如 'tool.args.url' -> data['tool']['args']['url']。"""
    cur: Any = data
    for part in field.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _clause_match(op: MatchOp, actual: Any, expected: Any) -> bool:
    if actual is None:
        return False
    if op == MatchOp.EQUALS:
        return actual == expected
    if op == MatchOp.IN_SET:
        return actual in expected
    if op == MatchOp.CONTAINS:
        return expected in actual
    if op == MatchOp.PREFIX:
        return str(actual).startswith(expected)
    if op == MatchOp.MATCHES:
        return re.search(expected, str(actual)) is not None
    return False


def evaluate(policy: PolicyIR, tool_call: ToolCall) -> str:
    """返回 'allow' 或 'deny'。v1 仅对 tool_call 触发事件在 harness 内裁决。"""
    if policy.trigger != TriggerEvent.TOOL_CALL:
        return "allow"
    inp = {"tool": {"name": tool_call.name, "args": tool_call.args}}
    if all(_clause_match(c.op, _resolve(c.field, inp), c.value) for c in policy.match):
        return "deny" if policy.action == Effect.DENY else "allow"
    return "allow"
