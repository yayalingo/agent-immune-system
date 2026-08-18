import contextlib
import io
import tempfile
import unittest

import ais.redteam.scenarios  # 注册  # noqa: F401
from ais.adapters.local_fn import VulnerableAgent
from ais.cli import _is_policy_blocked, main
from ais.compiler import compile_findings
from ais.compiler.ir import build_ir_from_finding
from ais.coverage.report import compute
from ais.core.models import Finding, PolicyIR
from ais.eval.ir_eval import evaluate as ir_evaluate
from ais.governor import GovernedTarget
from ais.policy_store import local as store
from ais.redteam.runner import run_all


class TestE2ELoop(unittest.TestCase):
    def test_full_loop(self):
        tmp = tempfile.mkdtemp()
        target = VulnerableAgent()

        # 1) 裸跑：全部 vulnerable
        findings = run_all(target)
        self.assertTrue(all(f.outcome == "vulnerable" for f in findings))

        # 2) 编译：findings -> 策略包（IR + Rego）
        bundle = compile_findings(findings, "opa")
        self.assertGreaterEqual(len(bundle["irs"]), 3)

        # 3) 回归：用 IR 评估器包裹目标重跑 -> 全部 safe
        irs = [PolicyIR.from_dict(ir) for ir in bundle["irs"]]

        def ev(_p, tc):
            return "deny" if any(ir_evaluate(ir, tc) == "deny" for ir in irs) else "allow"

        gov = GovernedTarget(target, ev, None)
        reg = run_all(gov)
        self.assertTrue(all(f.outcome == "safe" for f in reg), [f.__dict__ for f in reg])

        # 4) 部署 + 标记回归通过
        store.deploy(bundle["rego"], bundle["irs"], tmp)
        for f in reg:
            store.mark_regression(f.scenario_id, True, tmp)

        # 5) coverage：被保护的 ASI 标记覆盖
        report = compute(store.list_rules(tmp))
        protected = {f.asi_id for f in findings}
        self.assertTrue(all(report.covered[asi] for asi in protected))

    def test_is_policy_blocked_guard(self):
        # 审查 #5：仅策略实际拦住（evidence 含 [BLOCKED:）才算回归通过
        blocked = Finding("s1", "ASI01", "safe", "exfil [BLOCKED:http_request]", None)
        safe_unblocked = Finding("s2", "ASI01", "safe", "normal reply", None)
        vuln = Finding("s3", "ASI02", "vulnerable", "exfil", None)
        self.assertTrue(_is_policy_blocked(blocked))
        self.assertFalse(_is_policy_blocked(safe_unblocked))  # 非策略拦截，不算覆盖
        self.assertFalse(_is_policy_blocked(vuln))

    def test_unknown_scenario_clean_error(self):
        # 审查 #6：未知 scenario id 给出清晰报错，而非裸 traceback
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = main(["redteam", "--scenario", "nope"])
        self.assertEqual(rc, 2)
        self.assertIn("未知场景", buf.getvalue())
