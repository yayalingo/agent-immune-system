import unittest

from ais.compiler.ir import build_ir, build_ir_from_finding
from ais.core.models import AttackSignature, Finding, Indicator, MatchOp, TriggerEvent


class TestIR(unittest.TestCase):
    def test_build_ir_maps_indicators(self):
        sig = AttackSignature(
            TriggerEvent.TOOL_CALL,
            [Indicator("tool.name", MatchOp.EQUALS, "http_request"),
             Indicator("tool.args.url", MatchOp.CONTAINS, "evil.a")],
        )
        ir = build_ir(sig, "ASI01", "asi01-goal-hijack", "demo")
        self.assertEqual(ir.trigger, TriggerEvent.TOOL_CALL)
        self.assertEqual(len(ir.match), 2)
        self.assertEqual(ir.match[0].op, MatchOp.EQUALS)
        self.assertEqual(ir.action.value, "deny")
        self.assertEqual(ir.meta["asi_id"], "ASI01")

    def test_build_ir_from_finding_safe_raises(self):
        f = Finding("s", "ASI01", "safe", "ok", signature=None)
        with self.assertRaises(ValueError):
            build_ir_from_finding(f)

    def test_ir_roundtrip_dict(self):
        sig = AttackSignature(TriggerEvent.TOOL_CALL,
                              [Indicator("tool.name", MatchOp.IN_SET, ["a", "b"])])
        ir = build_ir(sig, "ASI02", "x")
        ir2 = type(ir).from_dict(ir.to_dict())
        self.assertEqual(ir.to_dict(), ir2.to_dict())
