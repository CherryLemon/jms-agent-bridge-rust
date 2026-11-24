"""Unit contracts for the loopback warm Terminal benchmark."""
import json
import unittest
from unittest.mock import Mock

from mcp_terminal_measure import FIXTURE, LoopbackTerminal, measure_sample


class WarmTerminalTest(unittest.TestCase):
    def test_physical_lines_survive_multiple_packets_and_truncated_eof_fails(self):
        channel = Mock()
        channel.recv.side_effect = [b"a", b"b\ncd\n", b"tail", b""]
        pending = bytearray()
        self.assertEqual(LoopbackTerminal.line(channel, pending), b"ab\n")
        self.assertEqual(LoopbackTerminal.line(channel, pending), b"cd\n")
        with self.assertRaisesRegex(ValueError, "truncated"):
            LoopbackTerminal.line(channel, pending)

    def test_both_facades_validate_terminal_identity_output_and_silent_completion(self):
        fixture = json.loads(FIXTURE.read_text())
        rows = [
            {"ok": True, "state": "idle", "session": "s"},
            {"ok": True, "state": "completed", "session": "s", "executed": True,
             "result_id": "r1", "stdout": fixture["commands"][0]["stdout"], "exit_code": 0},
            {"ok": True, "state": "completed", "session": "s", "executed": True,
             "result_id": "r2", "exit_code": 0},
            {"ok": True, "state": "closed", "session": "s"},
        ]
        for legacy in (True, False):
            client = Mock(legacy=legacy)
            client.tool.side_effect = rows
            self.assertEqual(set(measure_sample(client, fixture)),
                             {"open", "exec_output", "exec_silent", "close"})
            calls = client.tool.call_args_list
            self.assertTrue(all(x.args[1] == ("call" if legacy else "terminal") for x in calls))
            self.assertTrue(all(x.kwargs["arguments" if legacy else "options"]["wait_for"]
                                == "completed" for x in calls[1:3]))
            for field, value in (("result_id", "r1"), ("stdout", "wrong"),
                                 ("state", "running"), ("executed", None)):
                with self.subTest(legacy=legacy, field=field):
                    client.tool.side_effect = [*rows[:2], {**rows[2], field: value}]
                    with self.assertRaisesRegex(RuntimeError, "unexpected terminal completion"):
                        measure_sample(client, fixture)
