"""Only the read-only, receipt-scoped messages reach the transport."""
import json
import unittest
from unittest.mock import Mock

from mcp_job_portable_receipt import guarded, status_action


class PortableReceiptTest(unittest.TestCase):
    def test_exact_receipt_action_only(self):
        handle = {"target": "fixture-a", "job_id": "12345678"}
        action = status_action(handle)
        exchange = Mock(return_value=(0, b"{}"))
        reader = guarded(exchange, action)
        def request(args, tool="call"):
            return json.dumps({"method": "tools/call",
                               "params": {"name": tool, "arguments": args}}).encode()

        permitted = request(action["arguments"])
        self.assertEqual(reader(permitted, True), (0, b"{}"))
        for body in [
            request({"operation": "jms_submit_job", "arguments": {}}),
            request(status_action({**handle, "job_id": "deadbeef"})["arguments"]),
            request(status_action({**handle, "target": "fixture-b"})["arguments"]),
            request(action["arguments"], tool="job"),
            b'{"method":"other"}',
        ]:
            with self.subTest(body=body), self.assertRaises(RuntimeError):
                reader(body, True)
        exchange.assert_called_once_with(permitted, True)
