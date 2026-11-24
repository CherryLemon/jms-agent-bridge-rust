"""Small contract tests; the optional loopback CLI is the integration test."""
import unittest
from unittest.mock import Mock

from mcp_job_measure import summarize, workflow


class JobMeasurementTest(unittest.TestCase):
    def test_success_failure_timeout_and_counts_are_distinct(self):
        sample = {
            "elapsed_ms": 12.5, "timed_out": True,
            "calls": {"submit": 1, "wait": 2, "logs": 2},
            "backend_requests": {"ssh_launch": 2, "ssh_status": 7, "ssh_logs": 2},
            "terminal_jobs": {"done": 1, "failed": 1},
            "request_bytes": {"submit": 20, "wait": 30, "logs": 40},
            "response_bytes": {"submit": 100, "wait": 120, "logs": 80},
        }
        result = summarize([sample, {**sample, "elapsed_ms": 14}])
        self.assertEqual(result["completed_workflows"], 2)
        self.assertEqual(result["workflows_with_wait_timeout"], 2)
        self.assertEqual(result["terminal_jobs"], {"done": 2, "failed": 2})
        self.assertEqual(result["backend_requests"]["ssh_status"], 14)
        self.assertEqual((result["p50_ms"], result["p95_ms"]), (12.5, 14))

    def test_missing_expected_target_is_rejected_before_wait(self):
        client = Mock()
        client.job.return_value = {"ok": True, "jobs": []}
        with self.assertRaisesRegex(RuntimeError, "unexpected submission"):
            workflow(client, {"targets": [{"id": "fixture-a"}], "command": "printf synthetic"})
        self.assertEqual(client.job.call_count, 1)
