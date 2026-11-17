"""Ethernet, LLC, IPX and STP on dpkt's vectors and generated offline frames."""

import importlib.util
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import octetrail
from octetrail import NeedData, UnpackError, ethernet, ip6, ipx, llc, stp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "ethernet_fixture", ROOT / "tools/ethernet_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(v) for k, v in F.cases().items()}


class EthernetTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("ii_ip6", "vlan_ip6", "mpls_teb", "isl_dpkt_stp", "llc_dpkt_trailer"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_ethernet_ii_and_round_trip(self):
        frame = ethernet.Ethernet(CASES["ii_ip6"])
        self.assertIsInstance(frame.data, ip6.IP6)
        self.assertIs(frame.ip6, frame.data)
        self.assertEqual(bytes(frame), CASES["ii_ip6"])
        opaque = ethernet.Ethernet(CASES["ii_opaque"])
        self.assertEqual((opaque.type, opaque.data), (0x88B5, b"octetrail"))
        self.assertEqual(len(opaque), 23)
        for raw in (b"", CASES["ii_short"]):
            with self.assertRaises(NeedData):
                ethernet.Ethernet(raw)

    def test_vlan_tags(self):
        frame = ethernet.Ethernet(CASES["qinq_ip6"])
        self.assertEqual([t.id for t in frame.vlan_tags], [7, 9])
        self.assertEqual((frame.vlanid, frame.priority, frame.cfi), (7, 0, 0))
        self.assertIsInstance(frame.data, ip6.IP6)
        self.assertEqual(bytes(frame), CASES["qinq_ip6"])
        single = ethernet.Ethernet(CASES["vlan_ip6"])
        self.assertEqual((single.vlanid, single.priority), (5, 3))
        with self.assertRaises(NeedData) as result:
            ethernet.Ethernet(CASES["vlan_short"])
        self.assertEqual(str(result.exception), "got 2, 4 needed at least")
        single.vlan_tags += [ethernet.VLANtag8021Q(), ethernet.VLANtag8021Q()]
        with self.assertRaises(octetrail.PackError):
            bytes(single)

    def test_mpls_labels_and_pseudowire(self):
        frame = ethernet.Ethernet(CASES["mpls_ip6"])
        self.assertEqual(frame.labels, [(16, 0, 64), (17, 0, 64)])
        self.assertEqual([lbl.s for lbl in frame.mpls_labels], [0, 1])
        self.assertIsInstance(frame.data, ip6.IP6)
        self.assertEqual(bytes(frame), CASES["mpls_ip6"])
        inner = ethernet.Ethernet(CASES["mpls_ecw_teb"]).data
        self.assertIsInstance(inner, ethernet.Ethernet)
        self.assertEqual(inner.data, b"x")
        with self.assertRaises(ethernet.MPLSIndexError) as result:
            ethernet.Ethernet(CASES["mpls_nothing_after"])
        self.assertIsInstance(result.exception, UnpackError)
        self.assertIsInstance(result.exception, IndexError)
        self.assertEqual(str(result.exception), "index out of range")

    def test_isl_keeps_innermost_tag(self):
        frame = ethernet.Ethernet(CASES["isl_twice"])
        self.assertEqual(len(frame.vlan_tags), 1)
        self.assertIsInstance(frame.vlan_tags[0], ethernet.VLANtagISL)
        self.assertIsInstance(frame.data, ip6.IP6)
        dpkt_vector = ethernet.Ethernet(CASES["isl_dpkt_stp"])
        self.assertIsInstance(dpkt_vector.data.data, stp.STP)
        self.assertEqual(dpkt_vector.padding, bytes(8))
        self.assertEqual(bytes(dpkt_vector), CASES["isl_dpkt_stp"])
        dpkt_vector.fcs = None
        self.assertEqual(bytes(dpkt_vector), CASES["isl_dpkt_stp"])
        with self.assertRaises(NeedData):
            ethernet.Ethernet(CASES["isl_short_tag"])
        with self.assertRaises(UnpackError):
            ethernet.Ethernet(CASES["isl_short_inner"])

    def test_deep_isl_chain_parses_in_one_pass(self):
        raw = F.ISL * 20000 + F.header(0x88B5) + b"note"
        start = time.perf_counter()
        frame = ethernet.Ethernet(raw)
        self.assertLess(time.perf_counter() - start, 5)
        self.assertEqual((len(frame.vlan_tags), frame.data), (1, b"note"))

    def test_8023_llc_padding_fcs_and_trailer(self):
        frame = ethernet.Ethernet(CASES["llc_dpkt_trailer"])
        self.assertEqual(frame.padding, bytes(7))
        self.assertEqual(frame.trailer, bytes.fromhex("5c1e5fba3aa547fa018e5203"))
        self.assertEqual(frame.fcs, 0x4DB98120)
        self.assertIsInstance(frame.llc, llc.LLC)
        self.assertIsInstance(frame.llc.stp, stp.STP)
        self.assertEqual(bytes(frame), CASES["llc_dpkt_trailer"])
        frame.fcs = None
        self.assertEqual(bytes(frame), CASES["llc_dpkt_trailer"])
        other = ethernet.Ethernet(CASES["llc_nonzero_padding"])
        self.assertFalse(hasattr(other, "padding"))
        self.assertEqual(other.fcs, 0x01010101)

    def test_llc_snap_and_saps(self):
        snap = ethernet.Ethernet(CASES["llc_snap_ip6"]).data
        self.assertTrue(snap.is_snap)
        self.assertEqual((snap.oui, snap.type), (0, 0x86DD))
        self.assertIsInstance(snap.data, ip6.IP6)
        self.assertIsInstance(ethernet.Ethernet(CASES["llc_ipx"]).llc.ipx, ipx.IPX)
        self.assertEqual(ethernet.Ethernet(CASES["llc_snap_unknown"]).data.data, b"hello")
        with self.assertRaises(UnpackError) as result:
            ethernet.Ethernet(CASES["llc_snap_short"])
        self.assertNotIsInstance(result.exception, NeedData)
        built = llc.LLC(data=ip6.IP6())
        self.assertEqual(bytes(built)[:8], b"\xaa\xaa\x03\x00\x00\x00\x86\xdd")
        self.assertEqual(len(built), 48)

    def test_novell_and_unknown_type(self):
        frame = ethernet.Ethernet(CASES["novell_ipx"])
        self.assertEqual(frame.type, ethernet.ETH_TYPE_IPX)
        self.assertIsInstance(frame.ipx, ipx.IPX)
        self.assertEqual(ethernet.Ethernet(CASES["unknown_type"]).data, b"note")

    def test_keywords_type_table_and_stp_timers(self):
        frame = ethernet.Ethernet(src=F.SRC, data=ip6.IP6(nxt=59))
        self.assertEqual(bytes(frame)[12:14], b"\x86\xdd")
        self.assertIsInstance(ethernet.Ethernet(type=0x86DD, data=F.ip6()).data, ip6.IP6)
        self.assertIs(ethernet.Ethernet.get_type(0x6558), ethernet.Ethernet)
        self.assertEqual(ethernet.Ethernet.get_type_rev(ipx.IPX), 0x8137)
        timers = stp.STP(bytes(range(35)))
        self.assertEqual((timers.age, timers.max_age, timers.hello, timers.fd), (27, 29, 31, 33))
        timers.age = 2
        self.assertEqual(timers._age, 0x200)
        self.assertEqual(ethernet.mac_to_str(F.DST), "02:aa:bb:cc:dd:ee")

    def test_payload_errors_other_than_parse_errors_propagate(self):
        for error in (ValueError("caller"), MemoryError("allocation")):
            with (
                patch.object(ip6._native, "_ipv6_unpack", side_effect=error),
                self.assertRaises(type(error)) as result,
            ):
                ethernet.Ethernet(CASES["ii_ip6"])
            self.assertIs(result.exception, error)

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/ethernet_differential.py",
                "--probe",
                "--module",
                "octetrail",
                "--version",
                "9.9.9",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wrong provider version", result.stderr)


if __name__ == "__main__":
    unittest.main()
