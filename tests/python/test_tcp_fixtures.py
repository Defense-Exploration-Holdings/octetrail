"""Independent fixture and validator checks; runnable without a wheel."""

import copy
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from tcp_cases import BASE, NAMES, cases, encode, literal  # noqa: E402
from tcp_differential import ComparisonError, validate  # noqa: E402


class TCPFixtureTests(unittest.TestCase):
    def test_literal_and_struct_encoder_agree_with_explicit_offsets(self):
        raw = literal()
        self.assertEqual(raw[:4], b"\xc0\x00\x01\xbb")
        self.assertEqual(raw[4:12], b"\x89\xab\xcd\xef\x10\x20\x30\x40")
        self.assertEqual(raw[12:20], b"\x50\x18\x80\x01\xa1\xb2\x00\x00")
        self.assertEqual(raw[20:], b"tcp-base")
        self.assertEqual(len(raw), 28)
        self.assertEqual(encode(BASE, b"tcp-base"), raw)

    def test_expected_fields_agree_with_independent_unsigned_byte_arithmetic(self):
        spans = {
            "sport": (0, 2),
            "dport": (2, 4),
            "seq": (4, 8),
            "ack": (8, 12),
            "win": (14, 16),
            "sum": (16, 18),
            "urp": (18, 20),
        }
        for case in cases():
            if case["status"] != "matching" or case["expected"]["outcome"] != "ok":
                continue
            for state in case["expected"]["snapshots"]:
                with self.subTest(case=case["id"]):
                    raw = bytes.fromhex(state["hex"])
                    for name, (start, end) in spans.items():
                        value = 0
                        for byte in raw[start:end]:
                            value = value * 256 + byte
                        self.assertEqual(value, state[name])
                    self.assertEqual(raw[12], state["off"] * 16)
                    self.assertEqual(raw[13], state["flags"])
                    self.assertEqual(raw[20 : state["off"] * 4].hex(), state["opts"])
                    self.assertEqual(raw[state["off"] * 4 :].hex(), state["data"])
                    self.assertEqual(len(raw), state["length"])
                    self.assertEqual(raw[:20].hex(), state["header_hex"])

    def test_corpus_is_unique_deterministic_and_labels_all_declared_differences(self):
        payload = cases()
        self.assertEqual(payload, cases())
        self.assertEqual(len({case["id"] for case in payload}), len(payload))
        self.assertEqual(sum(case["status"] == "difference" for case in payload), 2)
        self.assertEqual(
            {case["id"] for case in payload if case["status"] == "difference"},
            {"excluded_nonce", "excluded_reserved"},
        )
        self.assertEqual(
            len([case for case in payload if case["id"].startswith("short_header.")]), 20
        )
        self.assertEqual(len(NAMES), 9)

    def test_validator_rejects_signed_sequence_wrong_checksum_bytes_length_and_missing_case(self):
        payload = [case for case in cases() if case["id"] == "literal_parse"]
        key = payload[0]["id"]
        good = {
            "module": "test",
            "version": "0",
            "origin_verified": True,
            "cases_run": 1,
            "results": {key: payload[0]["expected"]},
        }
        validate(good, payload)
        for name, value in (("seq", -1985229329), ("sum", 0), ("hex", "00"), ("length", 20)):
            bad = copy.deepcopy(good)
            bad["results"][key]["snapshots"][0][name] = value
            with self.subTest(name=name), self.assertRaises(ComparisonError):
                validate(bad, payload)
        bad = {**good, "results": {}}
        with self.assertRaises(ComparisonError):
            validate(bad, payload)

    def test_validator_rejects_wrong_error_phase_and_family(self):
        payload = [case for case in cases() if case["id"] == "short_header.19"]
        for name, value in (("phase", "serialize"), ("error", "ValueError")):
            result = {**payload[0]["expected"], name: value}
            report = {
                "module": "test",
                "version": "0",
                "origin_verified": True,
                "cases_run": 1,
                "results": {payload[0]["id"]: result},
            }
            with self.subTest(name=name), self.assertRaises(ComparisonError):
                validate(report, payload)

    def test_optimized_validator_rejects_unverified_or_incorrect_reports(self):
        script = textwrap.dedent("""
            import copy
            import sys
            sys.path.insert(0, sys.argv[1])
            from tcp_cases import cases
            from tcp_differential import validate
            payload = [case for case in cases() if case['id'] == 'literal_parse']
            key = payload[0]['id']
            good = {'module': 'test', 'version': '0', 'origin_verified': True,
                    'cases_run': 1, 'results': {key: payload[0]['expected']}}
            validate(good, payload)
            for change in ('origin', 'count', 'missing', 'sum', 'length'):
                bad = copy.deepcopy(good)
                if change == 'origin':
                    bad['origin_verified'] = False
                elif change == 'count':
                    bad['cases_run'] = 0
                elif change == 'missing':
                    bad['results'] = {}
                else:
                    bad['results'][key]['snapshots'][0][change] = 0
                try:
                    validate(bad, payload)
                except ValueError:
                    continue
                raise SystemExit('optimized validator accepted bad ' + change)
            print('rejected five optimized TCP comparison negatives')
        """)
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                "-c",
                script,
                str(Path(__file__).resolve().parents[2] / "tools"),
            ],
            capture_output=True,
            text=True,
            cwd=tempfile.gettempdir(),
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rejected five optimized TCP comparison negatives", result.stdout)


if __name__ == "__main__":
    unittest.main()
