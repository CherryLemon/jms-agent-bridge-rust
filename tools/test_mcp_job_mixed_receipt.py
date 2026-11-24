"""Validate the mixed wait response before authorizing its read-only continuation."""
import copy
import unittest

from mcp_job_mixed_receipt import check_mixed
from mcp_job_portable_receipt import status_action


class MixedReceiptTest(unittest.TestCase):
    def test_only_pending_job_may_continue(self):
        failed = {"target": "fixture-a", "job_id": "12345678"}
        running = {"target": "fixture-b", "job_id": "23456789"}
        receipt = {"finished": False, "pending_scope": "remote_job", "pending": [running],
                   "next_action": status_action(running),
                   "status": [{**failed, "ok": True, "status": "failed", "exit_code": "7"},
                              {**running, "ok": True, "status": "running"}]}
        check_mixed(receipt, failed, running, 7)
        for patch in ({"pending": [failed, running]}, {"next_action": status_action(failed)},
                      {"next_action": {"tool": "job", "arguments": {"action": "submit"}}},
                      {"pending_scope": "bridge_local"}, {"finished": True}):
            with self.subTest(patch=patch), self.assertRaises(RuntimeError):
                check_mixed({**receipt, **patch}, failed, running, 7)
        bad_row = copy.deepcopy(receipt)
        bad_row["status"][0]["exit_code"] = "0"
        with self.assertRaises(RuntimeError):
            check_mixed(bad_row, failed, running, 7)
