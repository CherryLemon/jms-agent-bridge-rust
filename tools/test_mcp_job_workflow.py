"""The mock denominator cannot silently drop failed jobs or incomplete tasks."""
import json
import unittest
from unittest.mock import Mock

from mcp_job_workflow import FIXTURE, mock_workflow_report, replay


class MockWorkflowTest(unittest.TestCase):
    def test_counts_and_failed_terminal_coverage(self):
        result = mock_workflow_report(30)
        self.assertEqual(result["completed_workflows"], 30)
        self.assertEqual(result["targets_per_workflow"], 3)
        self.assertEqual(result["modeled_calls_by_step"],
                         {"submit": 30, "wait": 60, "logs": 90})
        self.assertEqual(result["simulated_probes_by_kind"],
                         {"launch": 90, "status": 120, "log": 90})
        self.assertEqual(result["simulated_probes_per_workflow"], 10)
        self.assertEqual(result["terminal_jobs_by_state"], {"done": 60, "failed": 30})

    def test_missing_job_is_not_a_completed_workflow(self):
        fixture = json.loads(FIXTURE.read_bytes())
        jobs = [{k: row[k] for k in ("target", "job_id")}
                for row in fixture["targets"]]
        call = Mock(side_effect=[
            {"ok": True, "jobs": jobs},
            {"finished": True, "pending": [], "status": []},
        ])
        with self.assertRaisesRegex(RuntimeError, "pending handles"):
            replay(fixture, call)
        self.assertEqual(call.call_count, 2)

    def test_incorrect_exit_code_is_not_a_completed_workflow(self):
        fixture = json.loads(FIXTURE.read_bytes())
        jobs = [{k: row[k] for k in ("target", "job_id")}
                for row in fixture["targets"]]
        call = Mock(side_effect=[
            {"ok": True, "jobs": jobs},
            {"finished": False, "pending": [jobs[0]], "status": [
                {**jobs[1], "status": "failed", "exit_code": "0"},
            ]},
        ])
        with self.assertRaisesRegex(RuntimeError, "terminal state or exit code"):
            replay(fixture, call)
        self.assertEqual(call.call_count, 2)
