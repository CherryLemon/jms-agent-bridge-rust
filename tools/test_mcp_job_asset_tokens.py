"""Pure offline identity-field transformation contracts."""
import json
import unittest

from mcp_job_asset_tokens import fixture_aliases, paired

A = "00000000-0000-4000-8000-000000000001"
B = "00000000-0000-4000-8000-000000000002"


class AssetTokenTest(unittest.TestCase):
    def test_structured_scope_and_free_text(self):
        value = {"asset_id": A, "result_id": A, "log": A,
                 "nested": {"target": B, "targets": [A, B, "fixture-host"]},
                 "options": {"expected_asset_id": A}}
        short, count = paired(json.dumps(value), {A: "fx1"})
        self.assertEqual(count, 3)
        value["asset_id"] = "fx1"
        value["options"]["expected_asset_id"] = "fx1"
        value["nested"]["targets"][0] = "fx1"
        self.assertEqual(json.loads(short), value)

    def test_detect_preexisting_alias_and_nonbijective_map(self):
        for value, aliases in (({"asset_id": "fx1"}, {A: "fx1"}),
                               ({"target": A}, {A: "fx1", B: "fx1"})):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "alias collision"):
                    paired(json.dumps(value), aliases)

    def test_ordering_and_bad_fixtures(self):
        fixture = {"targets": [{"id": B}, {"id": A}]}
        self.assertEqual(fixture_aliases(fixture), {A: "fx1", B: "fx2"})
        for rows in ([], [{"id": A}, {"id": A}], [{"id": "not-uuid"}]):
            with self.assertRaisesRegex(ValueError, "fixture UUIDs"):
                fixture_aliases({"targets": rows})
