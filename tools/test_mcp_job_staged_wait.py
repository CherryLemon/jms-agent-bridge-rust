import copy
import json
import unittest

from mcp_job_staged_wait import FIXTURE, check_payload, check_staged, seeded_case
from mcp_job_staged_result import read_action


class StagedWaitTest(unittest.TestCase):
    def setUp(self):
        _, self.handles = seeded_case(json.loads(FIXTURE.read_text()))
        self.pending = self.handles[-2:]
        self.rid = "a" * 32

    def test_check_staged_keeps_two_pending_pairs_and_local_action(self):
        receipt = dict(staged=True, operation="jms_job_wait", finished=False, pending=self.pending,
                       pending_scope="remote_job", result_id_scope="bridge_local",
                       bytes=11469, result_id=self.rid, diagnostics_action=read_action(self.rid, 0))
        self.assertEqual(check_staged(receipt, self.pending), (11469, self.rid))
        for fields in (dict(pending=self.pending[::-1]), dict(next_action=read_action(self.rid, 0)),
                       dict(diagnostics_action=read_action(self.rid, 1))):
            with self.subTest(fields=fields), self.assertRaises(RuntimeError):
                check_staged({**receipt, **fields}, self.pending)

    def test_check_payload_rejects_terminal_reentry_and_altered_artifact_reference(self):
        status = []
        for i, h in enumerate(self.handles):
            row = dict(target=h["target"], job_id=h["job_id"],
                       status="failed" if i < 6 else "running", ok=True)
            if i < 6:
                row.update(exit_code="7", artifact_refs=[
                    dict(target=h["target"], job_id=h["job_id"], path=p, verified=False,
                         options={"expected_asset_id": h["target"]}) for p in h["artifact_paths"]])
            status.append(row)
        payload = dict(finished=False, pending=self.pending, status=status)
        check_payload(payload, self.handles)
        with self.assertRaises(RuntimeError):
            check_payload({**payload, "pending": [self.handles[0], *self.pending]}, self.handles)
        altered = copy.deepcopy(payload)
        altered["status"][0]["artifact_refs"][0]["verified"] = True
        with self.assertRaises(RuntimeError):
            check_payload(altered, self.handles)


if __name__ == "__main__":
    unittest.main()
