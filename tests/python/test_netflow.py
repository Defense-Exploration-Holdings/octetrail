"""NetFlow exports parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import time
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, netflow

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "netflow_fixture", ROOT / "tools/netflow_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class NetflowTests(unittest.TestCase):
    def test_dpkt_v1(self):
        export = netflow.Netflow1(bytes.fromhex(F.DPKT_V1))
        self.assertIsInstance(export, Packet)
        self.assertEqual(len(export.data), 24)

    def test_dpkt_v5(self):
        export = netflow.Netflow5(F.V5)
        self.assertEqual((export.version, export.count, export.sys_uptime), (5, 29, 3053111760))
        self.assertEqual(export.unix_sec, 973816130)
        self.assertEqual(len(export.data), 4)
        self.assertEqual(bytes(export.data[0]), bytes.fromhex(F.DPKT_V5_RECORDS)[:48])
        # As in dpkt, packing sets count to the number of records.
        self.assertEqual(bytes(export)[2:4], b"\x00\x04")

    def test_cut_record(self):
        with self.assertRaisesRegex(NeedData, "^got 41, 48 needed at least$"):
            netflow.Netflow5(F.V5[:-7])

    def test_build(self):
        record = netflow.Netflow5.NetflowRecord(src_addr=1, dst_port=80)
        export = netflow.Netflow5(data=[record, record])
        raw = bytes(export)
        self.assertEqual(len(raw), 24 + 96)
        self.assertEqual(netflow.Netflow5(raw).data[1].dst_port, 80)

    def test_many_records_parse_in_linear_time(self):
        count = 40000
        raw = F.header(5, 0, bytes(8)) + F.record(48, 1) * count
        started = time.perf_counter()
        export = netflow.Netflow5(raw)
        self.assertEqual(len(export.data), count)
        self.assertLess(time.perf_counter() - started, 5)


if __name__ == "__main__":
    unittest.main()
