"""Byte cursor and result identity are checked before another page is read."""
import unittest

from mcp_job_staged_result import check_page, read_action


class StagedResultTest(unittest.TestCase):
    def test_result_cursor_counts_utf8_source_bytes(self):
        page = {"result_id": "fixture", "offset": 5, "total_bytes": 12,
                "next_offset": 12, "text": "段🌕", "eof": True}
        self.assertEqual(check_page(page, "fixture", 5, 12), 12)
        for patch in ({"next_offset": 7}, {"total_bytes": 13}, {"eof": False},
                      {"result_id": "other"}, {"offset": 0}, {"stream": "stdout"}):
            with self.subTest(patch=patch), self.assertRaises(RuntimeError):
                check_page({**page, **patch}, "fixture", 5, 12)
        self.assertEqual(read_action("fixture", 5)["arguments"],
                         {"result_id": "fixture", "stream": "result", "offset": 5, "limit": 4096})
