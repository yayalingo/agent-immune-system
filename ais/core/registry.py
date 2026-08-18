"""场景注册表：用 @scenario 装饰器登记红队场景，run_all 统一驱动。"""
from __future__ import annotations

from typing import Callable, Optional

from .models import Scenario, TargetAgent, ScenarioResult

SCENARIOS: dict[str, Scenario] = {}


def scenario(asi_id: str, id: str, description: str = ""):
    def deco(fn: Callable[[TargetAgent], ScenarioResult]) -> Callable:
        if id in SCENARIOS:
            raise ValueError(f"重复场景 id: {id}")
        SCENARIOS[id] = Scenario(id=id, asi_id=asi_id, description=description, run=fn)
        return fn
    return deco


def get(id: str) -> Scenario:
    if id not in SCENARIOS:
        raise KeyError(f"未知场景: {id}（已注册: {list(SCENARIOS)}）")
    return SCENARIOS[id]


def all_ids() -> list[str]:
    return list(SCENARIOS)
