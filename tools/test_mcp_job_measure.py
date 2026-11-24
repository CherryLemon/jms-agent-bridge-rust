"""Small contract tests; the optional loopback CLI is the integration test."""
import json
import unittest
from unittest.mock import Mock, patch

from mcp_job_measure import CASES, Client, follow_growing_log, summarize, workflow


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

    def test_growing_log_reconstructs_each_page_and_eof(self):
        from unittest.mock import call

        source = json.loads(CASES["growing-log"].read_text())["targets"][0]
        combined = source["log"] + source["append_log"]
        start = len(source["log"])
        offsets = [0, start, start + 1024, len(combined)]
        bodies = [source["log"], combined[start:start+1024],
                  combined[start+1024:], ""]
        handle = {"target": source["id"], "job_id": "00123456"}
        replies = [
            {"ok": True, "job_id": handle["job_id"], "offset": offset,
             "next_offset": offset + len(body), "size": start if not offset else len(combined),
             "log": body}
            for offset, body in zip(offsets, bodies, strict=True)
        ]
        client = Mock()
        client.job.side_effect = replies
        follow_growing_log(client, handle, source)
        self.assertEqual(client.job.call_args_list, [
            call("logs", **handle, offset=offset, max_bytes=1024) for offset in offsets
        ])
        for field, invalid in (("log", "wrong"), ("size", 1), ("next_offset", 2),
                               ("job_id", "99999999")):
            with self.subTest(field=field):
                client.job.side_effect = [replies[0], {**replies[1], field: invalid}]
                with self.assertRaisesRegex(RuntimeError, "unexpected growing log page"):
                    follow_growing_log(client, handle, source)

    def test_tokens_count_only_the_original_result_text_when_asked(self):
        rpc = Mock()
        with patch.object(Client, "rpc", return_value=({}, (0, 0))):
            client = Client(Mock(), legacy=False, count_result_tokens=rpc)
        client.rpc = Mock()
        raw = '{ "x": "fixture text" }'
        client.rpc.return_value = ({"content": [{"type": "text", "text": raw}],
                                    "isError": False, "meta": "excluded"}, (13, 22))
        rpc.return_value = 9
        self.assertEqual(client.tool("logs", "job", action="logs"), {"x": "fixture text"})
        rpc.assert_not_called()
        self.assertEqual(client.result_tokens(), {"logs": 9})
        rpc.assert_called_once_with(raw)
        self.assertEqual(client.bytes["logs"], {"request_bytes": 13, "response_bytes": 22})
