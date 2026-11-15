"""Facade and test-only mapping boundaries, independent of consumer parity counts."""

import importlib
import importlib.metadata
import importlib.util
import runpy
import sys
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import octetrail
from octetrail import capture

ROOT = Path(__file__).resolve().parents[2]
SUPPORT = runpy.run_path(str(ROOT / "tools/capture_test_namespace.py"))
mapped = SUPPORT["mapped_capture_namespace"]


class CaptureFacadeTests(unittest.TestCase):
    def test_explicit_provider_has_no_import_alias_side_effect(self):
        self.assertIs(capture.pcap, octetrail.pcap)
        self.assertIs(capture.pcapng, octetrail.pcapng)
        self.assertIs(capture.NeedData, octetrail.NeedData)
        self.assertTrue(issubclass(capture.NeedData, capture.UnpackError))
        self.assertEqual(SUPPORT["dpkt_cache_keys"](), [])
        self.assertIsNone(importlib.util.find_spec("dpkt"))

    def test_closed_mapping_supports_only_capture_imports(self):
        with mapped():
            root = importlib.import_module("dpkt")
            classic = importlib.import_module("dpkt.pcap")
            generic = importlib.import_module("dpkt.pcapng")
            self.assertIs(root.pcap, classic)
            self.assertIs(classic, capture.pcap)
            self.assertIs(generic, capture.pcapng)
            self.assertEqual(root.__path__, [])
            self.assertEqual(Path(root.__file__).resolve(), Path(capture.__file__).resolve())
            with self.assertRaises(ModuleNotFoundError):
                importlib.import_module("dpkt.ip")
        self.assertEqual(SUPPORT["dpkt_cache_keys"](), [])

    def test_mapping_cleans_up_after_consumer_error(self):
        failure = RuntimeError("synthetic consumer stopped")
        with self.assertRaises(RuntimeError) as raised, mapped():
            raise failure
        self.assertIs(raised.exception, failure)
        self.assertEqual(SUPPORT["dpkt_cache_keys"](), [])
        self.assertIsNone(importlib.util.find_spec("dpkt"))

    def test_mapping_does_not_create_distribution_metadata(self):
        with mapped(), self.assertRaises(importlib.metadata.PackageNotFoundError):
            importlib.metadata.version("dpkt")

    def test_cached_upstream_is_never_masked(self):
        original = ModuleType("dpkt.already_loaded")
        with patch.dict(sys.modules, {"dpkt.already_loaded": original}):
            with self.assertRaisesRegex(RuntimeError, "cached dpkt"), mapped():
                self.fail("mapping should refuse cached upstream")
            self.assertIs(sys.modules["dpkt.already_loaded"], original)

    def test_installed_upstream_is_never_masked(self):
        with (
            patch("importlib.metadata.distribution", return_value=object()),
            self.assertRaisesRegex(RuntimeError, "installed dpkt"),
            mapped(),
        ):
            self.fail("mapping should refuse installed upstream")

    def test_nonisolated_process_is_refused(self):
        class Flags:
            isolated = False

        with (
            patch.object(sys, "flags", Flags()),
            self.assertRaisesRegex(RuntimeError, "require -I"),
            mapped(),
        ):
            self.fail("mapping should refuse a nonisolated process")


if __name__ == "__main__":
    unittest.main()
