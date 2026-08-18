import unittest

import ais.redteam.scenarios  # 注册  # noqa: F401
from ais.adapters.local_fn import VulnerableAgent
from ais.compiler.ir import build_ir
from ais.core.models import AttackSignature, Indicator, MatchOp, TriggerEvent
from ais.eval.ir_eval import evaluate as ir_evaluate
from ais.governor import GovernedTarget
from ais.redteam.runner import run_scenario


def _ir():
    sig = AttackSignature(
        TriggerEvent.TOOL_CALL,
        [Indicator("tool.name", MatchOp.EQUALS, "http_request"),
         Indicator("tool.args.url", MatchOp.CONTAINS, "evil.a")],
    )
    return build_ir(sig, "ASI01", "asi01-goal-hijack")


class TestGovernor(unittest.TestCase):
    def test_blocks_attack(self):
        gov = GovernedTarget(VulnerableAgent(), ir_evaluate, _ir())
        f = run_scenario("asi01-goal-hijack", gov)
        self.assertEqual(f.outcome, "safe")
        self.assertIn("[BLOCKED:http_request]", f.evidence)

    def test_allows_unrelated(self):
        # 这条规则只拦 evil.a；asi02 命中 exfil.b，不应被拦
        gov = GovernedTarget(VulnerableAgent(), ir_evaluate, _ir())
        f = run_scenario("asi02-tool-misuse", gov)
        self.assertEqual(f.outcome, "vulnerable")
