"""AIS CLI：红队扫描 / 规则编译 / 部署 / 覆盖度。

用法：
  python -m ais.cli redteam --target mock --scenario all [--out findings.json]
  python -m ais.cli redteam --target mock --scenario asi06-memory-poisoning \
         --with-policy bundle.aip --evaluator ir
  python -m ais.cli compile findings.json --engine opa [--out bundle.aip]
  python -m ais.cli deploy bundle.aip [--store DIR]
  python -m ais.cli coverage [--store DIR] [--format text|json]
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import ais.redteam.scenarios  # 触发场景注册  # noqa: F401
from ais.adapters.local_fn import VulnerableAgent
from ais.compiler import compile_findings
from ais.core.models import (
    ASI_IDS,
    AttackSignature,
    Finding,
    Indicator,
    MatchOp,
    PolicyIR,
    TargetAgent,
    TriggerEvent,
)
from ais.coverage.report import compute, render_text
from ais.governor import GovernedTarget
from ais.policy_store import local as store
from ais.redteam.runner import run_all, run_scenario


class _Enc(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, Enum):
            return o.value
        if hasattr(o, "__dataclass_fields__"):
            return asdict(o)
        return super().default(o)


def _finding_from_dict(d: dict) -> Finding:
    sig = None
    if d.get("signature"):
        s = d["signature"]
        sig = AttackSignature(
            TriggerEvent(s["trigger_event"]),
            [Indicator(i["field"], MatchOp(i["op"]), i["value"]) for i in s["indicators"]],
        )
    return Finding(d["scenario_id"], d["asi_id"], d["outcome"], d["evidence"], sig)


def _resolve_target(name: str) -> TargetAgent:
    if name in ("mock", "vulnerable"):
        return VulnerableAgent()
    # 扩展点：name 为 import.path:Class 时动态加载真实框架适配器
    raise ValueError(f"未知 target：{name}（v1 仅支持 mock）")


def _is_policy_blocked(f: Finding) -> bool:
    """回归仅当策略**实际拦住**攻击才算通过（evidence 含 [BLOCKED:）。

    场景本就 safe（非策略拦截）不计入策略覆盖，避免误标（审查 #5）。
    """
    return f.outcome == "safe" and "[BLOCKED:" in f.evidence


def _make_evaluator(kind: str, policy_obj: Any):
    if kind == "ir":
        irs = policy_obj

        def ev_ir(_p, tc):
            from ais.eval.ir_eval import evaluate as ir_eval_fn

            return "deny" if any(ir_eval_fn(ir, tc) == "deny" for ir in irs) else "allow"

        return ev_ir
    if kind == "opa":
        rego_path = policy_obj

        def ev_opa(_p, tc):
            from ais.eval.opa_eval import evaluate as opa_fn

            return opa_fn(rego_path, tc)

        return ev_opa
    raise ValueError(f"未知 evaluator：{kind}")


def cmd_redteam(args: argparse.Namespace) -> int:
    from ais.core.registry import SCENARIOS

    target = _resolve_target(args.target)
    ids = None if args.scenario in (None, "all") else [args.scenario]

    if ids and args.scenario not in (None, "all") and args.scenario not in SCENARIOS:
        sys.stderr.write(
            f"[错误] 未知场景: {args.scenario}（已注册: {', '.join(sorted(SCENARIOS))}）\n"
        )
        return 2

    if args.with_policy:
        bundle = json.loads(Path(args.with_policy).read_text(encoding="utf-8"))
        irs = [PolicyIR.from_dict(ir) for ir in bundle["irs"]]
        # opa 评估器需要 rego 文件：写到临时文件
        if args.evaluator == "opa":
            tmp = Path(args.with_policy).with_suffix(".rego")
            tmp.write_text(bundle["rego"], encoding="utf-8")
            policy_obj: Any = str(tmp)
        else:
            policy_obj = irs
        evaluator = _make_evaluator(args.evaluator, policy_obj)
        governed = GovernedTarget(target, evaluator, policy_obj)
        findings = run_all(governed, ids)
        # 回归：只有"被策略拦住"才标 regression_passed。
        # 场景本就 safe（非策略拦截）不算策略生效，避免误标覆盖。
        for f in findings:
            if f.outcome == "safe":
                store.mark_regression(f.scenario_id, _is_policy_blocked(f), args.store)
        sys.stderr.write(f"[回归] 用策略 {args.with_policy}（{args.evaluator}）重跑：\n")
    else:
        findings = run_all(target, ids)

    print(json.dumps([asdict(f) for f in findings], indent=2, cls=_Enc, ensure_ascii=False))
    if args.out:
        Path(args.out).write_text(
            json.dumps([asdict(f) for f in findings], indent=2, cls=_Enc, ensure_ascii=False),
            encoding="utf-8",
        )
        sys.stderr.write(f"[已写出] {args.out}\n")

    vulnerable = [f for f in findings if f.outcome == "vulnerable"]
    if args.with_policy:
        return 0 if not vulnerable else 1
    # 裸跑：存在 vulnerable 属预期，但 CLI 以非 0 提示需处理
    return 0 if not vulnerable else 2


def cmd_compile(args: argparse.Namespace) -> int:
    raw = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    findings = [_finding_from_dict(d) for d in raw]
    try:
        bundle = compile_findings(findings, args.engine)
    except ValueError as e:
        print(f"[错误] {e}")
        return 1
    out = args.out or "ais_bundle.aip"
    stem = str(Path(out).with_suffix(""))
    Path(stem + ".aip").write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    Path(stem + ".rego").write_text(bundle["rego"], encoding="utf-8")
    if bundle.get("rego_test"):
        Path(stem + ".rego_test").write_text(bundle["rego_test"], encoding="utf-8")
    n = len(bundle["irs"])
    print(f"[已编译] {n} 条规则 -> {stem}.aip + {stem}.rego" + (" + 测试" if bundle.get("rego_test") else ""))
    return 0


def cmd_deploy(args: argparse.Namespace) -> int:
    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    path = store.deploy(bundle["rego"], bundle["irs"], args.store, rego_test=bundle.get("rego_test"))
    sids = [ir["meta"]["scenario_id"] for ir in bundle["irs"]]
    print(f"[已部署] {path}（规则: {', '.join(sids)}）")
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    rules = store.list_rules(args.store)
    report = compute(rules)
    if args.format == "json":
        print(json.dumps(report.covered, indent=2, ensure_ascii=False))
    else:
        print(render_text(report))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ais", description="Agent Immune System v1")
    sub = p.add_subparsers(dest="cmd", required=True)

    rt = sub.add_parser("redteam", help="运行红队扫描")
    rt.add_argument("--target", default="mock")
    rt.add_argument("--scenario", default="all")
    rt.add_argument("--out", default=None)
    rt.add_argument("--with-policy", default=None, help="策略包 .aip 路径（回归模式）")
    rt.add_argument("--evaluator", default="ir", choices=["ir", "opa"])
    rt.add_argument("--store", default=None)
    rt.set_defaults(func=cmd_redteam)

    cp = sub.add_parser("compile", help="把 findings 编译成策略包")
    cp.add_argument("findings")
    cp.add_argument("--engine", default="opa", choices=["opa"])
    cp.add_argument("--out", default=None)
    cp.set_defaults(func=cmd_compile)

    dp = sub.add_parser("deploy", help="部署策略包到本地 store")
    dp.add_argument("bundle")
    dp.add_argument("--store", default=None)
    dp.set_defaults(func=cmd_deploy)

    cv = sub.add_parser("coverage", help="覆盖度报告")
    cv.add_argument("--store", default=None)
    cv.add_argument("--format", default="text", choices=["text", "json"])
    cv.set_defaults(func=cmd_coverage)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
