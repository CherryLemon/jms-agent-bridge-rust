"""Contract tests for the offline-only projection."""
import copy
import json
import unittest

from mcp_job_projection import compact_submit, expand_submit


def receipt():
    return {
        "ok": True, "request_state": "completed", "request_id": "fixture",
        "jobs_scope": "remote_job",
        "next_action": {"tool": "op", "arguments": {"value": "keep"}},
        "jobs": [{"target": "alpha", "job_id": "synthetic"}],
        "submissions": [{"target": "alpha", "asset_id": "alpha",
                         "launch_state": "acknowledged", "launched": True,
                         "job_id": "synthetic", "result_id": "fixture", "executed": None}],
    }


class ProjectionTest(unittest.TestCase):
    def test_exact_semantic_round_trip(self):
        obj = receipt()
        raw = json.dumps(obj)
        compact = compact_submit(raw)
        self.assertNotEqual(raw, compact)
        row = json.loads(compact)["submissions"][0]
        self.assertNotIn("asset_id", row)
        self.assertNotIn("launched", row)
        self.assertIsNone(row["executed"])
        self.assertEqual(expand_submit(compact), obj)

    def test_error_stage_and_replay_are_byte_identical(self):
        for flags in ({"ok": False}, {"staged": True}, {"completion_unknown": True},
                      {"duplicate": True}, {"execution_replayed": True}):
            with self.subTest(flags=flags):
                raw = json.dumps({**receipt(), **flags})
                self.assertEqual(compact_submit(raw), raw)

    def test_no_projection_for_ambiguous_or_incomplete_rows(self):
        for patch in ({"asset_id": "beta"}, {"launch_state": "unknown"},
                      {"launched": None}, {"launched": 1}, {"target": ""}):
            with self.subTest(patch=patch):
                obj = copy.deepcopy(receipt())
                obj["submissions"].append({**obj["submissions"][0], **patch})
                raw = json.dumps(obj)
                self.assertEqual(compact_submit(raw), raw)
