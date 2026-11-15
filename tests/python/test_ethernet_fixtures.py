"""Check fixture expectations and differential failure detection without OctetRail."""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from ethernet_cases import DST, OPAQUE_TYPES, PAYLOAD_LENGTHS, SRC, cases, frame, literal  # noqa: E402
from ethernet_differential import validate  # noqa: E402


class EthernetFixtureTests(unittest.TestCase):
    def test_literal_matches_manually_reviewed_header_and_payload(self):
        raw = literal()
        self.assertEqual(raw[:6], b"\x02\xaa\xbb\xcc\xdd\xee")
        self.assertEqual(raw[6:12], b"\x02\x11\x22\x33\x44\x55")
        self.assertEqual(raw[12:14], b"\x88\xb5")
        self.assertEqual(raw[14:], b"octetrail")
        self.assertEqual(len(raw), 23)

    def test_struct_encoder_agrees_with_literal(self):
        self.assertEqual(frame(DST, SRC, 0x88B5, b"octetrail"), literal())

    def test_generated_headers_agree_with_arithmetic_and_explicit_slices(self):
        for eth_type in OPAQUE_TYPES:
            for size in PAYLOAD_LENGTHS:
                with self.subTest(eth_type=eth_type, size=size):
                    payload = bytes((index * 29 + size) % 256 for index in range(size))
                    raw = frame(DST, SRC, eth_type, payload)
                    self.assertEqual(
                        raw, DST + SRC + bytes((eth_type // 256, eth_type % 256)) + payload
                    )
                    self.assertEqual(len(raw), 14 + size)

    def test_corpus_is_deterministic_unique_and_has_both_construction_paths(self):
        payload = cases()
        self.assertEqual(payload, cases())
        self.assertEqual(len({case["id"] for case in payload}), len(payload))
        identifiers = {case["id"] for case in payload}
        for eth_type in OPAQUE_TYPES:
            for size in PAYLOAD_LENGTHS:
                for operation in ("construct", "parse"):
                    self.assertIn(f"{operation}.{eth_type:04x}.{size}", identifiers)

    def test_expected_success_snapshots_have_consistent_wire_fields(self):
        for case in cases():
            if case["expected"]["outcome"] != "ok":
                continue
            for state in case["expected"]["snapshots"]:
                with self.subTest(case=case["id"]):
                    raw = bytes.fromhex(state["hex"])
                    self.assertEqual(raw[:6], bytes.fromhex(state["dst"]).ljust(6, b"\0"))
                    self.assertEqual(raw[6:12], bytes.fromhex(state["src"]).ljust(6, b"\0"))
                    self.assertEqual(raw[12] * 256 + raw[13], state["type"])
                    self.assertEqual(raw[14:], bytes.fromhex(state["data"]))
                    self.assertEqual(len(raw), state["length"])

    def test_scope_has_all_header_truncations_and_labels_upstream_flexibility(self):
        payload = cases()
        truncations = [case for case in payload if case["id"].startswith("short_header.")]
        self.assertEqual([len(bytes.fromhex(case["hex"])) for case in truncations], list(range(14)))
        for case in payload:
            self.assertIn(case["status"], ("matching", "reference_only"))
            if case["status"] == "reference_only":
                self.assertTrue(case["reason"])

    def test_validator_rejects_wrong_unsigned_field_bytes_length_and_missing_case(self):
        payload = [case for case in cases() if case["id"] == "literal_parse"]
        key = payload[0]["id"]
        good = {
            "module": "test-observation",
            "version": "0",
            "origin_verified": True,
            "cases_run": 1,
            "results": {key: copy.deepcopy(payload[0]["expected"])},
        }
        validate(good, payload)
        for field, replacement in (("type", -30539), ("hex", "00"), ("length", 24), ("data", "")):
            with self.subTest(field=field):
                bad = copy.deepcopy(good)
                bad["results"][key]["snapshots"][0][field] = replacement
                with self.assertRaises(AssertionError):
                    validate(bad, payload)
        bad = copy.deepcopy(good)
        bad["results"] = {}
        with self.assertRaises(AssertionError):
            validate(bad, payload)

    def test_validator_rejects_wrong_error_family_and_phase(self):
        payload = [case for case in cases() if case["id"] == "short_header.13"]
        key = payload[0]["id"]
        for field, value in (("error", "ValueError"), ("phase", "serialize")):
            report = {
                "module": "test-observation",
                "version": "0",
                "origin_verified": True,
                "cases_run": 1,
                "results": {key: {**payload[0]["expected"], field: value}},
            }
            with self.subTest(field=field), self.assertRaises(AssertionError):
                validate(report, payload)


if __name__ == "__main__":
    unittest.main()
