import tempfile
import unittest

from ais.compiler.emit import rego
from ais.compiler.ir import build_ir
from ais.core.models import AttackSignature, Indicator, MatchOp, PolicyIR, ToolCall, TriggerEvent
from ais.eval import ir_eval
from ais.eval import opa_eval


def _sig():
    return AttackSignature(
        TriggerEvent.TOOL_CALL,
        [Indicator("tool.name", MatchOp.EQUALS, "http_request"),
         Indicator("tool.args.url", MatchOp.CONTAINS, "evil.a")],
    )


class TestEmitRego(unittest.TestCase):
    def test_emit_structure(self):
        ir = build_ir(_sig(), "ASI01", "asi01-goal-hijack")
        text = rego.emit([ir])
        self.assertIn("package agent.policies", text)
        self.assertIn("default allow = true", text)
        self.assertIn("deny {", text)
        self.assertIn('input.tool.name == "http_request"', text)
        self.assertIn('contains(input.tool.args.url, "evil.a")', text)

    def test_multi_rule_no_duplicate_header(self):
        irs = [
            build_ir(_sig(), "ASI01", "a"),
            build_ir(_sig(), "ASI02", "b"),
        ]
        text = rego.emit(irs)
        self.assertEqual(text.count("package agent.policies"), 1)
        self.assertEqual(text.count("default allow = true"), 1)
        self.assertEqual(text.count("deny {"), 2)

    def test_emit_test_generates_cases(self):
        ir = build_ir(_sig(), "ASI01", "asi01-goal-hijack")
        test = rego.emit_test([ir])
        self.assertIn("test_deny_asi01-goal-hijack", test)
        self.assertIn("test_allow_asi01-goal-hijack", test)

    def test_ir_vs_opa_crosscheck(self):
        if not opa_eval.available():
            self.skipTest("opa 未安装，跳过交叉校验（防漂移）")
        ir = build_ir(_sig(), "ASI01", "asi01-goal-hijack")
        text = rego.emit([ir])
        with tempfile.NamedTemporaryFile("w", suffix=".rego", delete=False) as f:
            f.write(text)
            path = f.name
        samples = [
            ToolCall("http_request", {"url": "http://evil.a/x"}),
            ToolCall("http_request", {"url": "http://good.z/x"}),
            ToolCall("read_file", {"path": "/etc/passwd"}),
        ]
        for tc in samples:
            ir_dec = ir_eval.evaluate(ir, tc)
            opa_dec = opa_eval.evaluate(path, tc)
            self.assertEqual(ir_dec, opa_dec, f"漂移: {tc.name} ir={ir_dec} opa={opa_dec}")
