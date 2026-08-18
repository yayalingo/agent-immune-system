"""Governor：回归验证用的 harness。

不在中间件拦截（那是 AGT 的活）。它包裹目标 Agent，在 harness 内对每个"意图工具调用"
用评估器裁决；deny 则模拟未执行并标注 [BLOCKED]。证明生成的规则会拦住攻击。
"""
from __future__ import annotations

from typing import Any, Protocol

from .core.models import Observation, TargetAgent, ToolCall


class Evaluator(Protocol):
    def __call__(self, policy: Any, tool_call: ToolCall) -> str:
        """返回 'allow' | 'deny'。可为函数或带 __call__ 的对象。"""
        ...


class GovernedTarget:
    def __init__(self, target: TargetAgent, evaluator: Evaluator, policy: Any) -> None:
        self.target = target
        self.evaluator = evaluator
        self.policy = policy

    def send(self, message: str, tools: list[str] | None = None) -> Observation:
        obs = self.target.send(message, tools)
        kept: list[ToolCall] = []
        blocked: list[str] = []
        for tc in obs.tool_calls:
            if self.evaluator(self.policy, tc) == "deny":
                blocked.append(tc.name)
            else:
                kept.append(tc)
        suffix = "".join(f" [BLOCKED:{n}]" for n in blocked)
        return obs.replace(text=obs.text + suffix, tool_calls=kept)
