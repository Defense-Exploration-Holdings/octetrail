"""Independent fixture, validator and installed-provider verification controls."""

import copy
import runpy
import subprocess
import sys
import textwrap
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
CASES = runpy.run_path(str(ROOT / "tools/ipv4_cases.py"))
module = types.ModuleType("ipv4_cases")
module.__dict__.update(CASES)
with patch.dict(sys.modules, {"ipv4_cases": module}):
    DRIVER = runpy.run_path(str(ROOT / "tools/ipv4_differential.py"))


class IPv4FixtureTests(unittest.TestCase):
    def test_literal_and_checksum_match_independent_fields(self):
        raw = bytes.fromhex((ROOT / "tests/fixtures/ipv4-base.hex").read_text())
        self.assertEqual(raw, CASES["LITERAL"])
        self.assertEqual(raw[:10], bytes.fromhex("450000181234400040fd"))
        self.assertEqual(raw[10:12], bytes.fromhex("3b7e"))
        self.assertEqual(raw[20:], b"rail")
        self.assertEqual(CASES["checksum"](raw[:20]), 0)
        self.assertEqual(CASES["checksum"](raw[:10] + bytes(2) + raw[12:20]), 0x3B7E)
        self.assertEqual(CASES["checksum"](b"\x01\x02\x03"), 0xFBFD)

    def test_validator_rejects_wrong_checksum_bytes_and_sum_field(self):
        case = CASES["cases"]()[0]
        observation = CASES["expected"](case, "1.9.8")
        for change in ("wire", "sum"):
            actual = copy.deepcopy(observation)
            if change == "wire":
                actual["snapshots"][0]["hex"] = "0000"
            else:
                actual["snapshots"][0]["after"]["sum"] ^= 1
            report = {
                "module": "negative-control",
                "origin_verified": True,
                "cases_run": 1,
                "results": {case["id"]: actual},
            }
            with self.subTest(change=change), self.assertRaises(ValueError):
                DRIVER["validate"](report, [case], "1.9.8")

    def test_validator_rejects_wrong_error_family_and_phase(self):
        case = next(c for c in CASES["cases"]() if c["id"] == "short.0")
        for field, value in (("error", "OSError"), ("phase", "serialize")):
            actual = CASES["expected"](case, "1.9.8")
            actual[field] = value
            report = {
                "module": "negative-control",
                "origin_verified": True,
                "cases_run": 1,
                "results": {case["id"]: actual},
            }
            with self.subTest(field=field), self.assertRaises(ValueError):
                DRIVER["validate"](report, [case], "1.9.8")

    def test_validator_rejects_unverified_origin_counts_and_case_ids(self):
        case = CASES["cases"]()[0]
        report = {
            "module": "negative-control",
            "origin_verified": True,
            "cases_run": 1,
            "results": {case["id"]: CASES["expected"](case, "1.9.8")},
        }
        for field, value in (("origin_verified", False), ("cases_run", 0), ("results", {})):
            actual = dict(report, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                DRIVER["validate"](actual, [case], "1.9.8")

    def test_validator_negative_controls_remain_active_with_optimization(self):
        names = (
            "test_validator_rejects_wrong_checksum_bytes_and_sum_field",
            "test_validator_rejects_wrong_error_family_and_phase",
            "test_validator_rejects_unverified_origin_counts_and_case_ids",
        )
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-O",
                str(Path(__file__).resolve()),
                *("IPv4FixtureTests." + name for name in names),
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Ran 3 tests", result.stderr)

    def test_probe_rejects_wrong_version_and_nonisolated_mode_with_optimization(self):
        probe = str(ROOT / "tools/ipv4_probe.py")
        for optimized in (False, True):
            for isolated in (False, True):
                flags = (["-I"] if isolated else []) + (["-O"] if optimized else [])
                result = subprocess.run(
                    [sys.executable, *flags, probe, "--module", "octetrail", "--version", "wrong"],
                    input="[]",
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
                with self.subTest(optimized=optimized, isolated=isolated):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(
                        "version mismatch" if isolated else "isolated venv required", result.stderr
                    )

    def test_probe_rejects_wrong_origins_with_optimization(self):
        script = textwrap.dedent("""\
            import importlib
            import runpy
            import sys
            from types import SimpleNamespace
            from unittest.mock import patch
            verify = runpy.run_path(sys.argv[1])["verify_provider"]
            real_import = importlib.import_module
            outside = SimpleNamespace(__file__="/outside-test-venv/provider.py")
            for target in ("octetrail", "octetrail.ip"):
                def load(name):
                    return outside if name == target else real_import(name)
                with patch("importlib.import_module", side_effect=load):
                    try:
                        verify("octetrail", "0.4.0")
                    except ValueError as error:
                        if str(error) != "provider outside venv":
                            raise
                    else:
                        raise RuntimeError("outside provider accepted")
            distribution = SimpleNamespace(
                version="0.4.0", locate_file=lambda path: outside.__file__
            )
            with patch("importlib.metadata.distribution", return_value=distribution):
                try:
                    verify("octetrail", "0.4.0")
                except ValueError as error:
                    if str(error) != "provider does not match installed distribution":
                        raise
                else:
                    raise RuntimeError("wrong distribution origin accepted")
            print("three origin controls passed")
            """)
        for optimized in (False, True):
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    *(["-O"] if optimized else []),
                    "-c",
                    script,
                    str(ROOT / "tools/ipv4_probe.py"),
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            with self.subTest(optimized=optimized):
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip(), "three origin controls passed")

    def test_version_differences_are_preserved_as_distinct_expectations(self):
        cases = CASES["cases"]()
        changed = next(c for c in cases if c["id"] == "retained_sum_length_change")
        old, new = (CASES["expected"](changed, v) for v in ("1.9.6", "1.9.8"))
        self.assertEqual(old["snapshots"][1]["after"]["len"], 25)
        self.assertEqual(new["snapshots"][1]["after"]["len"], 24)
        offset = next(c for c in cases if c["id"] == "offset_units")
        old, new = (CASES["expected"](offset, v) for v in ("1.9.6", "1.9.8"))
        self.assertEqual(old["snapshots"][0]["before"]["offset"], 24)
        self.assertEqual(new["snapshots"][0]["before"]["offset"], 3)
        setter = next(c for c in cases if c["id"] == "offset_setter_units")
        old, new = (CASES["expected"](setter, v) for v in ("1.9.6", "1.9.8"))
        for index, (old_flags, new_flags) in enumerate(((0x4003, 0x4018), (0x4001, 0x4008)), 1):
            self.assertEqual(old["snapshots"][index]["after"]["flags"], old_flags)
            self.assertEqual(new["snapshots"][index]["after"]["flags"], new_flags)
            self.assertEqual(
                bytes.fromhex(old["snapshots"][index]["hex"])[6:8], old_flags.to_bytes(2, "big")
            )
            self.assertEqual(
                bytes.fromhex(new["snapshots"][index]["hex"])[6:8], new_flags.to_bytes(2, "big")
            )


if __name__ == "__main__":
    unittest.main()
