"""Regression checks for the measurement contract (no bridge required)."""
import json
import unittest

from mcp_baseline import FIXTURE, declared_tools, task_summary


class DeclaredToolsTest(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(FIXTURE.read_bytes())
        self.required = {step["tool"] for step in self.fixture["steps"]}

    @staticmethod
    def listing(names):
        return {"tools": [{"name": name} for name in names]}

    def test_additional_job_tool_is_included(self):
        names = self.required | {"job"}
        self.assertEqual(declared_tools(self.listing(names), self.fixture), sorted(names))

    def test_missing_required_tool_fails(self):
        with self.assertRaisesRegex(RuntimeError, "missing fixture tools: read_result"):
            declared_tools(self.listing(self.required - {"read_result"}), self.fixture)


class FixtureTaskSummaryTest(unittest.TestCase):
    def test_empty_followup_group_is_unmeasured(self):
        self.assertIsNone(task_summary([]))

    def test_counts_and_nearest_rank_latency(self):
        samples = [
            {"elapsed_ms": latency, "tool_calls": 5, "expected_mcp_errors": 1,
             "request_bytes": 100, "response_bytes": 200}
            for latency in range(20, 0, -1)
        ]
        result = task_summary(samples)
        self.assertEqual(result["completed"], 20)
        self.assertEqual(result["tool_calls"], 100)
        self.assertEqual(result["expected_mcp_errors"], 20)
        self.assertEqual(result["request_bytes"], 2000)
        self.assertEqual(result["response_bytes"], 4000)
        self.assertEqual((result["p50_ms"], result["p95_ms"]), (10, 19))


if __name__ == "__main__":
    unittest.main()
