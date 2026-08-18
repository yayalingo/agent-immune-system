"""Cedar 后端（Phase 2 桩）。

约束（SPEC §5.3）：IR 的 `matches`(正则) 在 Cedar 无原生支持，仅 `like` 通配。
Phase 2 实现时需限制该 op 或转换，避免静默丢语义。
"""
from __future__ import annotations

from ...core.models import PolicyIR


def emit(ir: PolicyIR) -> str:
    raise NotImplementedError(
        "Cedar 后端属 Phase 2。IR 已就绪，仅需新增 emitter；"
        "注意 `matches`(正则) 在 Cedar 需转 `like` 或拒绝。"
    )
