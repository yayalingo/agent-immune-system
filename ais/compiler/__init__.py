"""Rule Compiler 编排：findings -> 策略包（rego 文本 + IR 列表）。

v1 仅 opa 后端；Cedar/Casbin 见 emit/ 下的桩。
"""
from __future__ import annotations

from typing import Any

from ..core.models import Finding
from .emit import rego
from .ir import build_ir_from_finding


def compile_findings(findings: list[Finding], engine: str = "opa") -> dict[str, Any]:
    vulnerable = [f for f in findings if f.outcome == "vulnerable" and f.signature]
    if not vulnerable:
        raise ValueError("没有可编译的 vulnerable finding（全部 safe 或缺少 signature）")
    irs = [build_ir_from_finding(f) for f in vulnerable]
    if engine == "opa":
        rego_text = rego.emit(irs)
        rego_test = rego.emit_test(irs)
    else:
        raise ValueError(f"暂不支持 engine={engine}（v1 仅 opa）")
    return {"rego": rego_text, "rego_test": rego_test, "irs": [ir.to_dict() for ir in irs]}
