"""Packets nested past the recursion limit fail the way dpkt 1.9.8 does."""

import importlib.util
import unittest
from pathlib import Path

import octetrail
from octetrail import NestingError, UnpackError, ethernet, ip, ip6

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "nesting_fixture", ROOT / "tools/nesting_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CLASSES = {"IP": ip.IP, "IP6": ip6.IP6, "Ethernet": ethernet.Ethernet}


class NestingTests(unittest.TestCase):
    def test_error_is_unpack_and_recursion_error(self):
        self.assertIs(octetrail.NestingError, NestingError)
        self.assertTrue(issubclass(NestingError, UnpackError))
        self.assertTrue(issubclass(NestingError, RecursionError))

    def test_shallow_chains_decode(self):
        for kind in F.DEPTHS:
            with self.subTest(kind=kind):
                outer, raw = F.chain(kind, 100)
                found = F.walk(CLASSES[outer](raw))
                self.assertGreaterEqual(found["layers"], 100)
                self.assertEqual(found["inner"], b"payload!".hex())

    def test_deep_chains_reach_the_caller(self):
        # No payload decoder keeps the bytes of a chain that is too deep, even
        # though each one keeps them on other UnpackErrors.
        for kind, depths in F.DEPTHS.items():
            outer, raw = F.chain(kind, depths[-1])
            for cls, data in ((CLASSES[outer], raw), (ethernet.Ethernet, F.ether(0x0800, raw))):
                if cls is ethernet.Ethernet and outer != "IP":
                    continue
                with self.subTest(kind=kind, cls=cls.__name__), self.assertRaises(NestingError):
                    cls(data)

    def test_existing_handlers_still_catch_it(self):
        raw = F.chain("ipip", 2000)[1]
        for handler in (UnpackError, RecursionError):
            with self.subTest(handler=handler.__name__):
                try:
                    ip.IP(raw)
                except handler:
                    pass
                else:
                    self.fail("the chain decoded")


if __name__ == "__main__":
    unittest.main()
