"""
Unit and Benchmark Tests for Red-Team in a Box (Gate H)
"""

import unittest
from visionguard.modules.red_team.simulator import RedTeamSimulator
from visionguard.modules.red_team.benchmark import RedTeamBenchmark


class TestRedTeam(unittest.TestCase):
    def setUp(self):
        self.benchmark = RedTeamBenchmark(seed=42)

    def test_red_team_benchmark_execution(self):
        summary = self.benchmark.run_full_benchmark()

        self.assertGreaterEqual(len(summary.scenarios_evaluated), 5)
        self.assertGreaterEqual(summary.macro_precision, 0.70)
        self.assertGreaterEqual(summary.macro_recall, 0.70)
        self.assertGreaterEqual(summary.macro_f1, 0.70)

        for sc in summary.scenarios_evaluated:
            self.assertTrue(sc.held_out_evaluated)
            self.assertGreaterEqual(sc.f1_score, 0.50)
            self.assertLessEqual(sc.precision, 1.0)
            self.assertLessEqual(sc.recall, 1.0)


if __name__ == "__main__":
    unittest.main()
