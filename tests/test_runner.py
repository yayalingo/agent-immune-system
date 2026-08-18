import unittest

import ais.redteam.scenarios  # 注册  # noqa: F401
from ais.adapters.local_fn import VulnerableAgent
from ais.core.registry import all_ids
from ais.redteam.runner import run_all, run_scenario


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.target = VulnerableAgent()

    def test_all_scenarios_registered(self):
        self.assertGreaterEqual(len(all_ids()), 3)

    def test_vulnerable_by_default(self):
        findings = run_all(self.target)
        self.assertTrue(all(f.outcome == "vulnerable" for f in findings))
        for f in findings:
            self.assertIsNotNone(f.signature)

    def test_single_scenario(self):
        f = run_scenario("asi06-memory-poisoning", self.target)
        self.assertEqual(f.asi_id, "ASI06")
        self.assertEqual(f.outcome, "vulnerable")
