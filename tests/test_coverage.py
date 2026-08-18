import unittest

from ais.coverage.report import compute, render_text


class TestCoverage(unittest.TestCase):
    def test_compute(self):
        rules = {
            "a": {"asi_id": "ASI01", "regression_passed": True},
            "b": {"asi_id": "ASI06", "regression_passed": False},
        }
        rep = compute(rules)
        self.assertTrue(rep.covered["ASI01"])
        self.assertFalse(rep.covered["ASI06"])
        self.assertFalse(rep.covered["ASI02"])

    def test_render(self):
        rules = {"a": {"asi_id": "ASI01", "regression_passed": True}}
        text = render_text(compute(rules))
        self.assertIn("ASI01", text)
        self.assertIn("覆盖 1/10", text)
