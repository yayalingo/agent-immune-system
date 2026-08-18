"""Rule Compiler 第一步：把 AttackSignature 编译成引擎无关的 PolicyIR。"""
from __future__ import annotations

from typing import Optional

from ..core.models import AttackSignature, Effect, Finding, MatchClause, PolicyIR


def build_ir(
    signature: AttackSignature,
    asi_id: str,
    scenario_id: str,
    description: str = "",
) -> PolicyIR:
    match = [MatchClause(i.field, i.op, i.value) for i in signature.indicators]
    return PolicyIR(
        meta={
            "asi_id": asi_id,
            "scenario_id": scenario_id,
            "description": description,
            "generated_from": "vulnerable finding",
        },
        trigger=signature.trigger_event,
        match=match,
        action=Effect.DENY,
        scope={"agent_id": "*", "session": "*"},
    )


def build_ir_from_finding(finding: Finding) -> PolicyIR:
    if finding.signature is None:
        raise ValueError(f"safe finding（{finding.scenario_id}）无 signature，无法编译")
    return build_ir(
        finding.signature, finding.asi_id, finding.scenario_id, finding.evidence[:120]
    )
