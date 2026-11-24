"""Small contract tests; the optional loopback CLI is the integration test."""
import json
import unittest
from unittest.mock import Mock, patch

from mcp_job_measure import CASES, summarize, workflow


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

    def test_one_target_and_above_concurrency_cases_are_distinct(self):
        fixtures = {name: json.loads(path.read_text()) for name, path in CASES.items()}
        self.assertEqual(len(fixtures["one-target"]["targets"]), 1)
        batch = fixtures["above-concurrency"]
        self.assertEqual(len({row["id"] for row in batch["targets"]}), 6)
        self.assertEqual({row["exit_code"] for row in batch["targets"]}, {0, 7})
        self.assertGreater(batch["status_delay_ms"], 0)
        self.assertNotIn("require_timeout", fixtures["mixed-timeout"])

    @patch("mcp_job_measure.follow_jobs", return_value=({"done": 1}, True))
    def test_no_timeout_case_rejects_unexpected_continuation(self, follow):
        fixture = json.loads(CASES["one-target"].read_text())
        asset = fixture["targets"][0]["id"]
        client = Mock()
        client.job.return_value = {"ok": True, "jobs": [{"target": asset, "job_id": "00123456"}]}
        with self.assertRaisesRegex(RuntimeError, "unexpectedly needed a continuation"):
            workflow(client, fixture)
        self.assertEqual(follow.call_args.kwargs, {"require_timeout": False})
