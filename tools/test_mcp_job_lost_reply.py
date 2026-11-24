import unittest
from unittest.mock import Mock

from mcp_baseline import encode
from mcp_job_lost_reply import DroppedSubmitReply, REQUEST_ID, drop_acknowledged_submit, job_records


class ReplyCutTest(unittest.TestCase):
    targets = {"fixture"}
    row = {"asset_id": "fixture", "job_id": "aaaaaaaa", "result_id": "b" * 32,
           "launch_state": "acknowledged"}
    submit = encode({"id": 3, "method": "tools/call", "params": {
        "name": "job", "arguments": {"action": "submit", "request_id": REQUEST_ID}}})

    def test_cuts_only_acknowledged_submit(self):
        result = {"ok": True, "request_id": REQUEST_ID, "submissions": [self.row]}
        wire = encode({"id": 3, "result": {"content": [{"text": encode(result).decode()}]}})
        exchange = Mock(return_value=(len(self.submit), wire))
        oracle = {}
        cut = drop_acknowledged_submit(exchange, self.targets, oracle)
        self.assertEqual(cut(b'{"method":"initialize"}', True), (len(self.submit), wire))
        with self.assertRaises(DroppedSubmitReply):
            cut(self.submit, True)
        self.assertEqual(oracle["records"], {"fixture": ("aaaaaaaa", "b" * 32)})
        self.assertEqual(oracle["response_bytes"], len(wire))

    def test_server_error_is_not_counted_as_a_lost_reply(self):
        wire = encode({"id": 3, "result": {"isError": True}})
        oracle = {}
        cut = drop_acknowledged_submit(lambda *_: (1, wire), self.targets, oracle)
        with self.assertRaisesRegex(RuntimeError, "unacknowledged"):
            cut(self.submit, True)
        self.assertEqual(oracle, {})

    def test_duplicate_or_unknown_job_cannot_pass_recovery(self):
        for rows in ([self.row, self.row], [{**self.row, "launch_state": "unknown"}]):
            with self.subTest(rows=rows), self.assertRaisesRegex(RuntimeError, "unique acknowledged"):
                job_records(rows, self.targets)
