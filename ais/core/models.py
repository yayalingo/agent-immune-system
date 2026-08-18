"""AIS 核心数据模型：场景/发现/策略中间表示(IR)。

零外部依赖（仅标准库）。所有结构均可 JSON 序列化，便于进 Git、做 manifest。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Callable, Optional, Protocol, runtime_checkable

# OWASP Agentic Top 10（ASI01..ASI10）
ASI_IDS = [f"ASI{idx:02d}" for idx in range(1, 11)]


class MatchOp(str, Enum):
    EQUALS = "equals"
    IN_SET = "in_set"
    CONTAINS = "contains"
    PREFIX = "prefix"
    MATCHES = "matches"  # 正则；注意 Cedar 不原生支持（见 SPEC §5.3）


class Effect(str, Enum):
    DENY = "deny"
    QUARANTINE = "quarantine"
    ALERT = "alert"


class TriggerEvent(str, Enum):
    TOOL_CALL = "tool_call"
    MEMORY_WRITE = "memory_write"
    AGENT_MESSAGE = "agent_message"


@dataclass
class Indicator:
    """攻击指纹的一项：在某字段上满足某 op 与某值。"""
    field: str
    op: MatchOp
    value: Any


@dataclass
class AttackSignature:
    """攻击的'触发事件' + '恶意指标'。这是 Rule Compiler 的唯一输入。"""
    trigger_event: TriggerEvent
    indicators: list[Indicator] = field(default_factory=list)


@dataclass
class ToolCall:
    name: str
    args: dict = field(default_factory=dict)


@dataclass
class Observation:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)

    def replace(self, **changes) -> "Observation":
        return replace(self, **changes)


@dataclass
class ScenarioResult:
    vulnerable: bool
    evidence: str
    signature: Optional[AttackSignature] = None


@dataclass
class Finding:
    scenario_id: str
    asi_id: str
    outcome: str  # "vulnerable" | "safe"
    evidence: str
    signature: Optional[AttackSignature] = None


@dataclass
class MatchClause:
    field: str
    op: MatchOp
    value: Any


@dataclass
class PolicyIR:
    """引擎无关的策略中间表示（Policy IR）。

    emit 层把它翻译成 Rego / Cedar / Casbin；v1 仅 Rego 后端。
    """
    meta: dict
    trigger: TriggerEvent
    match: list[MatchClause] = field(default_factory=list)
    action: Effect = Effect.DENY
    scope: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "meta": self.meta,
            "trigger": self.trigger.value,
            "match": [
                {"field": m.field, "op": m.op.value, "value": m.value}
                for m in self.match
            ],
            "action": self.action.value,
            "scope": self.scope,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PolicyIR":
        return cls(
            meta=d.get("meta", {}),
            trigger=TriggerEvent(d["trigger"]),
            match=[
                MatchClause(m["field"], MatchOp(m["op"]), m["value"])
                for m in d.get("match", [])
            ],
            action=Effect(d.get("action", "deny")),
            scope=d.get("scope", {}),
        )


@dataclass
class CoverageReport:
    covered: dict  # asi_id -> bool


@runtime_checkable
class TargetAgent(Protocol):
    def send(self, message: str, tools: Optional[list[str]] = None) -> Observation:
        ...


@dataclass
class Scenario:
    id: str
    asi_id: str
    description: str
    run: Callable[[TargetAgent], ScenarioResult]
