"""Installed reader option tests against independent rational capture clocks."""

import importlib.metadata
import io
import json
import subprocess
import sys
import tempfile
import unittest
from decimal import (
    ROUND_CEILING,
    ROUND_DOWN,
    ROUND_HALF_EVEN,
    Decimal,
    Inexact,
    Overflow,
    Rounded,
    Subnormal,
    Underflow,
    localcontext,
)
from fractions import Fraction
from pathlib import Path

from octetrail import pcap, pcapng

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from timestamp_cases import cases, classic, interface, packet, section  # noqa: E402
from timestamp_differential import observe  # noqa: E402

MODULES = {"pcap": pcap, "pcapng": pcapng}
PROBE = ROOT / "tools/timestamp_differential.py"


class DecimalTimestampTests(unittest.TestCase):
    def test_reviewed_literals_have_exact_decimal_values_and_clock_quantum(self):
        for filename, module, expected in (
            ("little-micro.hex", pcap, [("1.250000", b"abc"), ("2.000000", b"")]),
            ("big-nano.hex", pcap, [("1700000000.123456789", b"rail")]),
            ("pcapng-little.hex", pcapng, [("1.250000", b"abc")]),
            ("pcapng-big-nano.hex", pcapng, [("-0.750000000", b"rail")]),
        ):
            raw = bytes.fromhex((ROOT / "tests/fixtures" / filename).read_text())
            actual = list(module.Reader(io.BytesIO(raw), decimal_timestamps=True))
            self.assertEqual([(str(t), d) for t, d in actual], expected)
            self.assertTrue(all(type(t) is Decimal for t, _ in actual))

    def test_independent_rational_clock_matrix_and_explicit_false_defaults(self):
        for case in cases():
            module, raw = MODULES[case["format"]], bytes.fromhex(case["hex"])
            with self.subTest(case=case["id"]):
                actual = list(module.Reader(io.BytesIO(raw), decimal_timestamps=True))
                self.assertEqual(len(actual), len(case["rows"]))
                for (timestamp, data), wanted in zip(actual, case["rows"], strict=True):
                    self.assertIs(type(timestamp), Decimal)
                    self.assertEqual(Fraction(timestamp), Fraction(*wanted["ratio"]))
                    self.assertEqual(data.hex(), wanted["data"])
                self.assertEqual(
                    observe(module.Reader, raw, {}),
                    observe(module.Reader, raw, {"decimal_timestamps": False}),
                )

    def test_exact_conversion_ignores_rounding_precision_traps_and_context_limits(self):
        payload = cases()
        for precision, rounding in ((2, ROUND_DOWN), (6, ROUND_CEILING), (28, ROUND_HALF_EVEN)):
            with localcontext() as context:
                context.prec, context.rounding = precision, rounding
                context.Emin, context.Emax = -5, 5
                for signal in (Inexact, Rounded, Underflow, Overflow, Subnormal):
                    context.traps[signal] = True
                context.clear_flags()
                before = context.copy()
                for case in payload:
                    reader = MODULES[case["format"]].Reader(
                        io.BytesIO(bytes.fromhex(case["hex"])), decimal_timestamps=True
                    )
                    for (timestamp, data), wanted in zip(reader, case["rows"], strict=True):
                        self.assertEqual(Fraction(timestamp), Fraction(*wanted["ratio"]))
                        self.assertEqual(data.hex(), wanted["data"])
                self.assertEqual(context.flags, before.flags)
                self.assertEqual(context.traps, before.traps)
                self.assertEqual(
                    (context.prec, context.rounding, context.Emin, context.Emax),
                    (before.prec, before.rounding, before.Emin, before.Emax),
                )

    def test_ordinary_epoch_microseconds_do_not_pass_through_float(self):
        raw = classic("<", False, [(1700000000123456, b"rail")])
        default = next(pcap.Reader(io.BytesIO(raw)))[0]
        exact = next(pcap.Reader(io.BytesIO(raw), decimal_timestamps=True))[0]
        self.assertEqual(exact, Decimal("1700000000.123456"))
        self.assertNotEqual(Fraction(default), Fraction(exact))

    def test_section_changes_and_interface_clocks_are_used_per_packet(self):
        raw = section("<") + interface("<", 6, 0) + interface("<", 0x8A, -2)
        raw += packet("<", 1250000, b"one") + packet("<", 1024, b"two", 1)
        raw += section(">") + interface(">", 9, 3) + packet(">", 2500000000, b"new")
        actual = list(pcapng.Reader(io.BytesIO(raw), decimal_timestamps=True))
        self.assertEqual(
            actual, [(Decimal("1.25"), b"one"), (Decimal("-1"), b"two"), (Decimal("5.5"), b"new")]
        )

    def test_convenience_methods_share_cursor_and_keep_decimal_type(self):
        for module, raw in (
            (pcap, classic("<", False, [(n * 1000000 + 1, bytes([n])) for n in range(5)])),
            (
                pcapng,
                section("<")
                + interface("<", 6, 0)
                + b"".join(packet("<", n * 1000000 + 1, bytes([n])) for n in range(5)),
            ),
        ):
            source = io.BytesIO(raw)
            reader = module.Reader(source, decimal_timestamps=True)
            observations = [next(iter(reader)), reader.next()]
            self.assertEqual(
                reader.dispatch(1, lambda ts, data, seen=observations: seen.append((ts, data))), 1
            )
            self.assertIsNone(
                reader.loop(lambda ts, data, seen=observations: seen.append((ts, data)))
            )
            self.assertEqual(observations, [(Decimal(f"{n}.000001"), bytes([n])) for n in range(5)])
            self.assertTrue(all(type(t) is Decimal for t, _ in observations))
            self.assertEqual(reader.readpkts(), [])
            reader.close()
            self.assertFalse(source.closed)

    def test_owned_open_and_universal_factory_forward_the_option(self):
        with tempfile.TemporaryDirectory() as directory:
            for case in (case for case in cases() if case["id"].startswith("literal.")):
                module, raw = MODULES[case["format"]], bytes.fromhex(case["hex"])
                path = Path(directory) / case["id"]
                path.write_bytes(raw)
                with module.open(path, decimal_timestamps=True) as reader:
                    actual = reader.readpkts()
                self.assertTrue(reader.closed)
                source = io.BytesIO(raw)
                selected = pcap.UniversalReader(source, decimal_timestamps=True)
                self.assertIs(type(selected), module.Reader)
                self.assertEqual(selected.readpkts(), actual)
                self.assertTrue(all(type(t) is Decimal for t, _ in actual))
                selected.close()
                self.assertFalse(source.closed)

    def test_nonboolean_option_is_rejected_before_consuming_a_stream(self):
        for factory in (pcap.Reader, pcapng.Reader, pcap.UniversalReader):
            for value in (None, 0, 1, "true"):
                source = io.BytesIO(b"ordinary")
                with self.subTest(factory=factory, value=value), self.assertRaises(TypeError):
                    factory(source, decimal_timestamps=value)
                self.assertEqual(source.tell(), 0)
                self.assertFalse(source.closed)

    def test_native_packet_limits_remain_active_in_decimal_mode(self):
        for module, raw in (
            (pcap, classic("<", False, [(1, b"rail")])),
            (pcapng, section("<") + interface("<", 6, 0) + packet("<", 1, b"rail")),
        ):
            reader = module.Reader(io.BytesIO(raw), decimal_timestamps=True, max_packet_bytes=3)
            with self.assertRaises(module.LimitError):
                next(reader)
            self.assertEqual(list(reader), [])

    def test_optimized_probe_rejects_wrong_version_and_module_origin(self):
        command = [
            sys.executable,
            "-B",
            "-I",
            "-O",
            str(PROBE),
            "--probe",
            "octetrail",
            "--version",
        ]
        good = subprocess.run(
            [*command, importlib.metadata.version("octetrail")],
            input="[]",
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        self.assertEqual(json.loads(good.stdout)["python_optimization"], 1)
        bad = subprocess.run(
            [*command, "wrong"], input="[]", capture_output=True, text=True, check=False, timeout=30
        )
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, "")
        self.assertIn("version mismatch", bad.stderr)
        code = "import importlib.metadata,runpy,sys,octetrail; version=importlib.metadata.version('octetrail'); octetrail.__file__='/outside-timestamp-venv/__init__.py'; runpy.run_path(sys.argv[1])['verify_provider']('octetrail',version)"
        bad = subprocess.run(
            [sys.executable, "-B", "-I", "-O", "-c", code, str(PROBE)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("outside venv", bad.stderr)

    def test_optimized_validator_rejects_bad_ratio_type_identity_and_coverage(self):
        code = """
import copy, importlib.metadata, sys
sys.path.insert(0, sys.argv[1])
from timestamp_cases import cases
from timestamp_differential import observe, validate
from octetrail import pcap
case=cases()[0]; raw=bytes.fromhex(case['hex'])
version=importlib.metadata.version('octetrail')
result={'default':observe(pcap.Reader,raw,{}),'explicit_false':observe(pcap.Reader,raw,{'decimal_timestamps':False}),'decimal':observe(pcap.Reader,raw,{'decimal_timestamps':True})}
good={'module':'octetrail','version':version,'origin_verified':True,'python_optimization':1,'cases_run':1,'results':{case['id']:result}}
validate(good,[case],'octetrail',version,1)
for change in ('ratio','value','kind','origin','version','coverage','optimization'):
    bad=copy.deepcopy(good)
    if change=='ratio': bad['results'][case['id']]['decimal'][1]['ratio']=[0,1]
    elif change=='value': bad['results'][case['id']]['decimal'][1]['value']='0'
    elif change=='kind': bad['results'][case['id']]['decimal'][0]['kind']='float'
    elif change=='origin': bad['origin_verified']=False
    elif change=='version': bad['version']='wrong'
    elif change=='coverage': bad['results']={}
    else: bad['python_optimization']=0
    try: validate(bad,[case],'octetrail',version,1)
    except ValueError: continue
    raise RuntimeError('optimized timestamp validator accepted '+change)
print('seven optimized controls passed')
"""
        result = subprocess.run(
            [sys.executable, "-B", "-I", "-O", "-c", code, str(ROOT / "tools")],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("seven optimized controls passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
