"""Casbin 后端（Phase 2 桩）。

约束（SPEC §5.3）：IR 的 `matches`(正则) 在 Casbin 用 matcher 的 regexMatch 函数，
`contains`/`prefix` 亦需映射到 matcher 表达式。Phase 2 实现。
"""
from __future__ import annotations

from ...core.models import PolicyIR


def emit(ir: PolicyIR) -> str:
    raise NotImplementedError(
        "Casbin 后端属 Phase 2。IR 已就绪，仅需新增 emitter（CONF + CSV + matcher）。"
    )
