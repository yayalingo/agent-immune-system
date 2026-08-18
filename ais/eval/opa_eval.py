"""可选 opa 评估器：当 opa 二进制存在时，用真实 Rego 裁决，验证生成规则在真引擎上也能拦。

缺失时显式报错（fail-loud）。决策必须与 ir_eval 一致（test_emit_rego 交叉校验）。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

from ..core.models import PolicyIR, ToolCall

_OPA_BIN = "opa"


def available() -> bool:
    return shutil.which(_OPA_BIN) is not None


def evaluate(policy_path: str, tool_call: ToolCall) -> str:
    """policy_path: .rego 文件路径。以 input={tool:{name,args}} 评估 data.agent.policies.deny。"""
    if not available():
        raise RuntimeError(
            "未找到 opa 二进制。安装：https://www.openpolicyagent.org/docs/latest/#1-download-opa "
            "或改用 --evaluator ir（内置零依赖评估器）。"
        )
    inp = {"tool": {"name": tool_call.name, "args": tool_call.args}}
    # Windows 无 /dev/stdin；统一写临时文件传路径，跨平台可移植。
    fd, tmp_path = tempfile.mkstemp(prefix="ais-opa-in-", suffix=".json")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(json.dumps(inp).encode("utf-8"))
        proc = subprocess.run(
            [_OPA_BIN, "eval", "--format", "pretty", "-i", tmp_path,
             policy_path, "data.agent.policies.deny"],
            capture_output=True,
        )
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
    if proc.returncode != 0:
        raise RuntimeError(f"opa eval 失败: {proc.stderr.decode().strip()}")
    out = proc.stdout.decode().strip()
    # opa 输出 true / false / undefined
    return "deny" if out == "true" else "allow"
