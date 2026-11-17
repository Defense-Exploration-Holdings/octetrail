"""Independent UDP bytes and validation controls, including optimized Python."""

import copy
import importlib.metadata
import json
import runpy
import subprocess
import sys
import textwrap
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
CASES = runpy.run_path(str(ROOT / "tools/udp_cases.py"))
module = types.ModuleType("udp_cases")
module.__dict__.update(CASES)
with patch.dict(sys.modules, {"udp_cases": module}):
    DRIVER = runpy.run_path(str(ROOT / "tools/udp_differential.py"))


def good_report(case):
    return {
        "module": "dpkt",
        "version": "1.9.8",
        "origin_verified": True,
        "cases_run": 1,
        "results": {case["id"]: copy.deepcopy(case["expected"])},
    }


class UDPFixtureTests(unittest.TestCase):
    def test_literal_and_struct_encoder_match_independent_byte_arithmetic(self):
        literal = CASES["literal"]()
        expected = (
            b"".join(value.to_bytes(2, "big") for value in (12345, 54321, 12, 0x1234)) + b"rail"
        )
        self.assertEqual(literal, expected)
        self.assertEqual(CASES["encode"](CASES["BASE"], b"rail"), expected)
        for case in CASES["cases"]():
            for snapshot in case["expected"].get("snapshots", []):
                values = snapshot["before"]
                header = b"".join(values[name].to_bytes(2, "big") for name in CASES["NAMES"])
                self.assertEqual(snapshot["before"], snapshot["after"])
                self.assertEqual(snapshot["header_hex"], header.hex())
                self.assertEqual(snapshot["hex"], (header + bytes.fromhex(snapshot["data"])).hex())

    def test_validator_rejects_incorrect_fields_bytes_and_payload(self):
        case = next(c for c in CASES["cases"]() if c["id"] == "literal.parse")
        for field in ("ulen", "sum", "hex", "header_hex", "data", "length", "stable"):
            report = good_report(case)
            snapshot = report["results"][case["id"]]["snapshots"][0]
            if field in ("ulen", "sum"):
                snapshot["after"][field] = 0
            else:
                snapshot[field] = False if field == "stable" else 0
            with self.subTest(field=field), self.assertRaises(ValueError):
                DRIVER["validate"](report, [case])

    def test_validator_rejects_wrong_error_family_and_phase(self):
        case = next(c for c in CASES["cases"]() if c["id"] == "short.0")
        for field, value in (("phase", "serialize"), ("error", "OSError")):
            report = good_report(case)
            report["results"][case["id"]][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                DRIVER["validate"](report, [case])

    def test_validator_rejects_unverified_provenance_missing_and_duplicate_cases(self):
        case = CASES["cases"]()[0]
        for field, value in (
            ("module", "octetrail"),
            ("version", "wrong"),
            ("origin_verified", False),
            ("cases_run", 0),
            ("results", {}),
        ):
            report = good_report(case)
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                DRIVER["validate"](report, [case])
        duplicate_report = good_report(case)
        duplicate_report["cases_run"] = 2
        with self.assertRaises(ValueError):
            DRIVER["validate"](duplicate_report, [case, case])

    def test_validator_negative_controls_still_fail_with_optimization(self):
        methods = (
            "test_validator_rejects_incorrect_fields_bytes_and_payload",
            "test_validator_rejects_wrong_error_family_and_phase",
            "test_validator_rejects_unverified_provenance_missing_and_duplicate_cases",
        )
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                str(Path(__file__).resolve()),
                *("UDPFixtureTests." + name for name in methods),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Ran 3 tests", result.stderr)

    def test_probe_optimized_positive_wrong_version_and_isolation_controls(self):
        version = importlib.metadata.version("octetrail")
        for flags, requested, error in (
            (["-I", "-O"], version, None),
            (["-I", "-O"], "wrong", "version mismatch"),
            (["-O"], version, "isolated virtual environment required"),
        ):
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    *flags,
                    str(ROOT / "tools/udp_probe.py"),
                    "--module",
                    "octetrail",
                    "--version",
                    requested,
                ],
                input="[]",
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            with self.subTest(flags=flags, requested=requested):
                if error is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertIs(report["origin_verified"], True)
                    self.assertEqual(report["python_optimization"], 1)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(error, result.stderr)

    def test_probe_optimized_origin_checks_cannot_be_skipped(self):
        code = textwrap.dedent("""\
            import importlib
            import runpy
            import sys
            from types import SimpleNamespace
            from unittest.mock import patch
            verify = runpy.run_path(sys.argv[1])["verify_provider"]
            real_import = importlib.import_module
            outside = SimpleNamespace(__file__="/outside-test-venv/provider.py")
            for target in ("octetrail", "octetrail.udp", "octetrail._native"):
                def load(name):
                    return outside if name == target else real_import(name)
                with patch("importlib.import_module", side_effect=load):
                    try:
                        verify("octetrail", "0.4.1")
                    except ValueError as error:
                        if "origin outside environment" not in str(error):
                            raise
                    else:
                        raise RuntimeError("outside origin accepted")
            distribution = SimpleNamespace(
                version="0.4.1", locate_file=lambda path: sys.prefix + "/wrong-member.py"
            )
            with patch("importlib.metadata.distribution", return_value=distribution):
                try:
                    verify("octetrail", "0.4.1")
                except ValueError as error:
                    if "does not match distribution" not in str(error):
                        raise
                else:
                    raise RuntimeError("wrong distribution origin accepted")
            with patch("importlib.util.find_spec", return_value=object()):
                try:
                    verify("octetrail", "0.4.1")
                except ValueError as error:
                    if "unexpected dpkt" not in str(error):
                        raise
                else:
                    raise RuntimeError("dpkt namespace collision accepted")
            print("five provenance controls passed")
            """)
        result = subprocess.run(
            [sys.executable, "-B", "-I", "-O", "-c", code, str(ROOT / "tools/udp_probe.py")],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("five provenance controls passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
