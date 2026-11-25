from collections import Counter
from types import SimpleNamespace
import unittest

from mcp_job_rollback import REQUEST_ID, require_receipt, ssh_delta

TARGET = "22222222-2222-4222-8222-222222222222"
JOB = "00bb00bb"
RESULT = "ef" * 16


class RollbackTest(unittest.TestCase):
    def setUp(self):
        self.receipt = dict(request_id=REQUEST_ID, operation="jms_submit_job",
                            request_state="complete", completion_unknown=False,
                            execution_replayed=False,
                            submission_receipts=[dict(asset_id=TARGET, job_id=JOB,
                                                      result_id=RESULT, launch_state="acknowledged")])

    def test_only_definite_original_receipt_can_resume(self):
        self.assertEqual(require_receipt(self.receipt, {TARGET}), {TARGET: (JOB, RESULT)})
        for field, value in (("request_id", "different"), ("operation", "jms_job_wait"),
                             ("request_state", "running"), ("completion_unknown", True),
                             ("execution_replayed", True), ("submission_receipts", [])):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                require_receipt({**self.receipt, field: value}, {TARGET})
        with self.assertRaises(RuntimeError):
            require_receipt(self.receipt, {"wrong-asset"})

    def test_local_reads_cannot_probe_ssh_but_catalog_is_allowed(self):
        before = Counter(ssh_launch=1)
        backend = SimpleNamespace(counts=Counter(ssh_launch=1, catalog_list=1), errors=[])
        ssh_delta(backend, before)
        backend.counts.update(ssh_status=1, ssh_logs=1)
        ssh_delta(backend, before, ssh_status=1, ssh_logs=1)
        with self.assertRaises(RuntimeError):
            ssh_delta(backend, before)
        backend.counts.update(ssh_launch=1)
        with self.assertRaises(RuntimeError):
            ssh_delta(backend, before, ssh_status=1, ssh_logs=1)
        backend.errors = ["fixture failure"]
        with self.assertRaises(RuntimeError):
            ssh_delta(backend, backend.counts)


if __name__ == "__main__":
    unittest.main()
