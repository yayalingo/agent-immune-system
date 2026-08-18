"""Rule Compiler 第二步（v1 唯一后端）：PolicyIR -> OPA Rego。

映射契约见 SPEC §5.1。生成的规则对人类可读、可进 Git、可被 `opa test` 验证。

设计要点：
- `emit_rule(ir)` 只输出**单条** deny 规则（含注释），不含 package/default。
- `emit(irs)` 统一加 `package agent.policies` + `default allow = true` 头，避免多规则重复。
- `emit_test(irs)` 生成配套的 `*_test.rego`（对样本断言 deny/allow）。
"""
from __future__ import annotations

import json
from typing import Any, Optional

from ...core.models import MatchOp, MatchClause, PolicyIR, ToolCall, TriggerEvent


def _quoted(v) -> str:
    if isinstance(v, list):
        return "[" + ", ".join(_quoted(x) for x in v) + "]"
    return json.dumps(v)


def _safe_comment(text: str) -> str:
    # 防止 evidence 中的换行/回车破坏 Rego 注释或注入
    return " ".join((text or "").split())


def _clause(c: MatchClause) -> str:
    field = "input." + c.field
    op = c.op
    if op == MatchOp.EQUALS:
        return f"{field} == {_quoted(c.value)}"
    if op == MatchOp.CONTAINS:
        return f"contains({field}, {_quoted(c.value)})"
    if op == MatchOp.PREFIX:
        return f"startswith({field}, {_quoted(c.value)})"
    if op == MatchOp.IN_SET:
        return f"{field} in {_quoted(c.value)}"
    if op == MatchOp.MATCHES:
        return f"regex.match({_quoted(c.value)}, {field})"
    raise ValueError(f"未知 op: {op}")


def _body(ir: PolicyIR) -> str:
    if ir.match:
        return "\n".join("  " + _clause(c) for c in ir.match)
    return "  true"


def emit_rule(ir: PolicyIR) -> str:
    desc = _safe_comment(ir.meta.get("description", ""))
    head = [
        f"# asi_id: {ir.meta.get('asi_id')}",
        f"# scenario_id: {ir.meta.get('scenario_id')}",
        f"# description: {desc}",
    ]
    return "\n".join(head + [f"deny {{\n{_body(ir)}\n}}"])


def emit(irs: list[PolicyIR]) -> str:
    parts = ["package agent.policies", "", "default allow = true", ""]
    parts.append("\n\n".join(emit_rule(ir) for ir in irs))
    parts.append("")
    return "\n".join(parts)


def _sample_input(ir: PolicyIR, malicious: bool) -> Optional[dict]:
    """为 tool_call 触发、且含 equals/contains 子句的规则构造样本输入。

    恶意样本满足所有 match；良性样本全部取安全值。不支持的 trigger/op 返回 None。
    """
    if ir.trigger != TriggerEvent.TOOL_CALL:
        return None
    tool: dict[str, Any] = {"name": "http_request", "args": {}}
    for c in ir.match:
        if c.op not in (MatchOp.EQUALS, MatchOp.CONTAINS):
            return None
        if c.field == "tool.name":
            tool["name"] = c.value if malicious else "benign_tool"
        elif c.field.startswith("tool.args."):
            arg = c.field.split(".", 2)[2]
            tool["args"][arg] = c.value if malicious else "benign-value"
        else:
            return None
    if not malicious:
        # 确保良性样本一定不满足：把可能被 contains 命中的值也替换掉
        tool["name"] = "benign_tool"
        tool["args"] = {k: "benign-value" for k in tool["args"]}
    return {"tool": tool}


def emit_test(irs: list[PolicyIR]) -> str:
    L = ["package agent.policies", ""]
    for ir in irs:
        sid = ir.meta.get("scenario_id")
        mal = _sample_input(ir, malicious=True)
        ben = _sample_input(ir, malicious=False)
        if mal is None or ben is None:
            L.append(f"# 无法为 {sid} 生成 opa test 样本（trigger/op 暂不支持），跳过")
            L.append("")
            continue
        L.append(f"test_deny_{sid} {{")
        L.append(f"  not deny with input as {_json(mal)}")
        L.append("}")
        L.append(f"test_allow_{sid} {{")
        L.append(f"  deny with input as {_json(ben)}")
        L.append("}")
        L.append("")
    return "\n".join(L)


def _json(d: dict) -> str:
    return json.dumps(d, ensure_ascii=False)
