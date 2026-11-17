"""NetBIOS on dpkt's vectors and generated messages."""

import importlib.util
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, UnpackError, dns, netbios

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "netbios_fixture", ROOT / "tools/netbios_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class NetbiosTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("ns_query", "ns_positive", "ns_nbstat", "session_request", "datagram_direct"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_names(self):
        self.assertEqual(
            netbios.encode_name("The NetBIOS name"), "FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF"
        )
        self.assertEqual(netbios.encode_name("*"), "CK" + "A" * 30)
        self.assertEqual(
            netbios.decode_name("FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF"), "The NetBIOS name"
        )
        self.assertEqual(netbios.decode_name("CKAB"), "CKAB")
        self.assertEqual(netbios.node_to_service_name(("ISS", 0x00, 0x0800)), "Workstation Service")
        self.assertEqual(netbios.node_to_service_name(("ISS", 0xFF, 0x0800)), "")

    def test_name_service_is_dns(self):
        message = netbios.NS(CASES["ns_nbstat"])
        self.assertIsInstance(message, dns.DNS)
        self.assertIsInstance(message.qd[0], netbios.NS.Q)
        record = message.an[0]
        self.assertIsInstance(record, netbios.NS.RR)
        self.assertEqual(
            record.nodenames,
            [(b"ABCDEFGHIJKLMNO", 0x2F, 0x0102), (b"PQRSTUVWXYZABCD", 0x43, 0x0304)],
        )
        self.assertEqual(bytes(message), CASES["ns_nbstat"])
        positive = netbios.NS(CASES["ns_positive"])
        self.assertEqual(positive.an[0].rdata, b"\x60\x00\x0a\x00\x00\x01")
        self.assertEqual(netbios.NS(CASES["ns_a_record"]).an[0].ip, b"\x0a\x00\x00\x02")
        with self.assertRaises(UnpackError):
            netbios.NS(CASES["ns_nbstat_cut"])

    def test_empty_node_status_is_declared(self):
        with self.assertRaises(netbios.NodeStatusError) as caught:
            netbios.NS(CASES["ns_nbstat_empty"])
        self.assertIsInstance(caught.exception, UnpackError)
        self.assertIsInstance(caught.exception, IndexError)
        self.assertEqual(str(caught.exception), "index out of range")

    def test_session_and_datagram(self):
        session = netbios.Session(CASES["session_message"])
        self.assertEqual((session.type, session.len, session.data), (0, 4, b"\xffSMB"))
        datagram = netbios.Datagram(CASES["datagram_direct"])
        self.assertEqual((datagram.type, datagram.sport, datagram.data), (0x11, 138, b"hello"))
        with self.assertRaises(NeedData):
            netbios.Datagram(CASES["datagram_short"])


if __name__ == "__main__":
    unittest.main()
