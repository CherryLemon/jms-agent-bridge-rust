"""Regression checks for the measurement contract (no bridge required)."""
import json
import unittest

from mcp_baseline import FIXTURE, declared_tools


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


if __name__ == "__main__":
    unittest.main()
