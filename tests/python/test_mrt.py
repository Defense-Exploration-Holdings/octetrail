"""MRT records parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import time
import unittest
from pathlib import Path

from octetrail import Packet, UnpackError, bgp, mrt

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("mrt_fixture", ROOT / "tools/mrt_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
RECORDS = {name: bytes.fromhex(wire) for name, (_, wire) in F.RECORDS.items()}


class MRTTests(unittest.TestCase):
    def test_dpkt_table_dump(self):
        record = mrt.TableDump(RECORDS["dpkt_table_dump"])
        self.assertIsInstance(record, Packet)
        self.assertEqual(
            (record.view, record.seq, record.prefix, record.prefix_len, record.status),
            (1, 2, 3, 4, 5),
        )
        self.assertEqual((record.originated_ts, record.peer_ip, record.peer_as), (6, 7, 8))
        self.assertEqual(record.attr_len, 2)
        [attr] = record.attributes
        self.assertIsInstance(attr, bgp.BGP.Update.Attribute)
        self.assertIsInstance(attr.data, bgp.BGP.Update.Attribute.Origin)

    def test_attributes_and_rest(self):
        record = mrt.TableDump(RECORDS["table_tail"])
        self.assertEqual(len(record.attributes), 1)
        self.assertEqual(record.data, b"\xbe\xef")
        record = mrt.TableDump(RECORDS["table_many"])
        self.assertEqual(
            [a.type for a in record.attributes],
            [bgp.ORIGIN, bgp.AS_PATH, bgp.NEXT_HOP, bgp.COMMUNITIES, bgp.ORIGIN, 255],
        )

    def test_headers(self):
        header = mrt.MRTHeader(RECORDS["header"])
        self.assertEqual((header.type, header.subtype, header.len), (mrt.TABLE_DUMP, 0, 22))
        self.assertEqual(mrt.BGP4MPMessage_32(RECORDS["bgp4mp_32"]).src_as, 65001)
        self.assertEqual(bytes(mrt.BGP4MPMessage(RECORDS["bgp4mp"])), RECORDS["bgp4mp"])

    def test_evpn_cut_off_is_unpack_and_index_error(self):
        with self.assertRaises(bgp.EVPNIndexError) as caught:
            mrt.TableDump(RECORDS["table_evpn_cut"])
        self.assertIsInstance(caught.exception, UnpackError)
        self.assertIsInstance(caught.exception, IndexError)

    def test_many_attributes_parse_in_linear_time(self):
        def best(n):
            raw = bytes.fromhex(F.TABLE) + (4 * n).to_bytes(2, "big") + b"\x40\x01\x01\x00" * n
            times = []
            for _ in range(3):
                start = time.perf_counter()
                self.assertEqual(len(mrt.TableDump(raw).attributes), n)
                times.append(time.perf_counter() - start)
            return min(times)

        self.assertLess(best(16000), 40 * best(2000))


if __name__ == "__main__":
    unittest.main()
