"""BGP messages parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import time
import unittest
from pathlib import Path

from octetrail import Packet, UnpackError, bgp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("bgp_fixture", ROOT / "tools/bgp_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
VECTORS = {name: bytes.fromhex(wire) for name, wire in F.VECTORS.items()}
PARTS = {name: bytes.fromhex(wire) for name, (_, wire) in F.PARTS.items()}


class BGPTests(unittest.TestCase):
    def test_dpkt_vectors_repack(self):
        for name, raw in VECTORS.items():
            with self.subTest(name=name):
                packet = bgp.BGP(raw)
                self.assertIsInstance(packet, Packet)
                self.assertEqual(bytes(packet), raw)

    def test_update_attributes(self):
        packet = bgp.BGP(VECTORS["mp_nlri_next_hop"])
        self.assertEqual(packet.type, bgp.UPDATE)
        update = packet.update
        self.assertEqual((len(update.withdrawn), len(update.announced)), (0, 0))
        self.assertEqual(
            [a.type for a in update.attributes],
            [bgp.ORIGIN, bgp.AS_PATH, bgp.MULTI_EXIT_DISC, bgp.MP_REACH_NLRI],
        )
        reach = update.attributes[3].mp_reach_nlri
        self.assertEqual((reach.afi, reach.safi, len(reach.next_hops)), (bgp.AFI_IPV6, 1, 2))
        self.assertEqual(len(reach.announced), 3)

    def test_attribute_flags(self):
        attribute = bgp.BGP.Update.Attribute(PARTS["attr_origin"])
        self.assertEqual((attribute.optional, attribute.transitive), (0, 1))
        attribute.optional = 1
        attribute.extended_length = 1
        self.assertEqual(attribute.flags, 0xD0)
        self.assertEqual(bytes(attribute), bytes.fromhex("d001000100"))

    def test_extended_routes_follow_dpkt_length_rule(self):
        # dpkt reads announced routes as ExtendedRouteIPV4 when what remains is
        # a multiple of 9 bytes.
        update = bgp.BGP.Update(PARTS["update_nlri_9"])
        self.assertEqual(
            [type(r).__name__ for r in update.announced],
            ["RouteIPV4", "ExtendedRouteIPV4"],
        )
        self.assertEqual(repr(update.announced[1]), "ExtendedRouteIPV4(5.5.5.5/32 PathId 1)")

    def test_evpn_cut_off_is_unpack_and_index_error(self):
        for name in ("evpn_mac_cut", "evpn_ip_cut"):
            with self.subTest(name=name), self.assertRaises(bgp.EVPNIndexError) as caught:
                bgp.RouteEVPN(PARTS[name])
            self.assertIsInstance(caught.exception, UnpackError)
            self.assertIsInstance(caught.exception, IndexError)
            self.assertEqual(str(caught.exception), "index out of range")

    def test_many_routes_parse_in_linear_time(self):
        def best(n):
            raw = b"\x00\x00\x00\x00" + b"\x18\x0a\x00\x00" * n
            times = []
            for _ in range(3):
                start = time.perf_counter()
                self.assertGreater(len(bgp.BGP.Update(raw).announced), n // 2)
                times.append(time.perf_counter() - start)
            return min(times)

        self.assertLess(best(64000), 80 * best(4000))


if __name__ == "__main__":
    unittest.main()
