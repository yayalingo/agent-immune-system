"""Red-Team runner：驱动场景、产出结构化 findings。"""
from __future__ import annotations

from typing import Optional

from ..core.models import Finding, ScenarioResult, TargetAgent
from ..core.registry import SCENARIOS, get as get_scenario


def run_scenario(scenario_id: str, target: TargetAgent) -> Finding:
    scn = get_scenario(scenario_id)
    res: ScenarioResult = scn.run(target)
    outcome = "vulnerable" if res.vulnerable else "safe"
    sig = res.signature if res.vulnerable else None
    return Finding(scn.id, scn.asi_id, outcome, res.evidence, sig)


def run_all(target: TargetAgent, scenario_ids: Optional[list[str]] = None) -> list[Finding]:
    ids = scenario_ids or list(SCENARIOS)
    return [run_scenario(sid, target) for sid in ids]
