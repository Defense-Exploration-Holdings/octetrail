"""DNS messages parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import octetrail
from octetrail import NeedData, PackError, dns, ip, ip6, udp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dns_fixture", ROOT / "tools/dns_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class DnsTests(unittest.TestCase):
    def test_independent_fixture_fields_bytes_construction_mutation(self):
        report = F.exercise(octetrail, "octetrail")
        # Through JSON, as the differential compares them: a tuple becomes a list.
        cases = json.loads(json.dumps(report["cases"]))
        self.assertEqual(cases, {c["id"]: F.expected(c, "octetrail") for c in F.cases()})
        self.assertEqual(len(report["constructors"]), 12)

    def test_explicit_dns_does_not_change_transport_dispatch(self):
        wire = bytes.fromhex(next(c["wire"] for c in F.cases() if c["id"] == "query"))
        for cls, fields in ((ip.IP, {"p": 17}), (ip6.IP6, {"nxt": 17, "plen": len(wire) + 8})):
            packet = cls(
                data=udp.UDP(sport=32000, dport=53, ulen=8 + len(wire), data=wire), **fields
            )
            decoded = cls(bytes(packet))
            self.assertIsInstance(decoded.data, udp.UDP)
            self.assertEqual(decoded.data.data, wire)
            self.assertEqual(dns.DNS(decoded.data.data).qd[0].name, F.QNAME)

    def test_long_names_and_large_messages(self):
        name = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 62))
        message = dns.DNS(qd=[dns.DNS.Q(name=name)])
        self.assertEqual(dns.DNS(bytes(message)).qd[0].name, name)
        with self.assertRaises(octetrail.UnpackError):
            dns.DNS(bytes(dns.DNS(qd=[dns.DNS.Q(name=name + "x")])))
        message = dns.DNS(qd=[dns.DNS.Q(name="") for _ in range(5000)])
        self.assertEqual(len(dns.DNS(bytes(message)).qd), 5000)
        raw = b"x" * 65535
        message = dns.DNS(an=[dns.DNS.RR(name="", type=dns.DNS_NULL, rdata=raw)])
        self.assertEqual(dns.DNS(bytes(message)).an[0].rdata, raw)
        # As in dpkt, struct reports fields that do not fit.
        with self.assertRaises(struct.error):
            bytes(dns.DNS(an=[dns.DNS.RR(name="", type=dns.DNS_NULL, rdata=raw + b"x")]))
        with self.assertRaises(struct.error):
            bytes(dns.DNS(qd=[dns.DNS.Q(name="x" * 256)]))

    def test_truncation_raises_the_dpkt_error_class(self):
        for n in range(12):
            with self.assertRaises(NeedData):
                dns.DNS(bytes(n))
        query = bytes.fromhex(next(c["wire"] for c in F.cases() if c["id"] == "query"))
        # Missing name bytes are NeedData; a short type or class is UnpackError.
        for n in range(12, len(query)):
            with self.assertRaises(octetrail.UnpackError) as result:
                dns.DNS(query[:n])
            self.assertEqual(type(result.exception) is NeedData, n < len(query) - 4)
        with self.assertRaises(NeedData):
            dns.DNS(struct.pack("!6H", 0, 0, 1025, 0, 0, 0))
        with self.assertRaises(TypeError):
            dns.DNS("text")

    def test_rdata_slices_and_trailing_bytes_follow_dpkt(self):
        case = next(c for c in F.cases() if c["id"] == "rr-1")
        wire = bytes.fromhex(case["wire"])
        short = dns.DNS(wire[:-1])
        self.assertEqual((short.an[0].rlen, short.an[0].rdata), (4, wire[-4:-1]))
        self.assertEqual(short.an[0].ip, wire[-4:-1])
        message = dns.DNS(wire + b"tail")
        self.assertEqual(message.data, b"")
        self.assertEqual(bytes(message), wire)
        message.data = b"ignored"
        self.assertEqual(bytes(message), wire)
        with self.assertRaises(octetrail.UnpackError):
            dns.DNS(F.header([0, 1, 0, 0]) + b"\0" + struct.pack("!HHIH", 99, 1, 0, 0))

    def test_parsed_records_repack_their_raw_rdata(self):
        case = next(c for c in F.cases() if c["id"] == "rr-5")
        message = dns.DNS(bytes.fromhex(case["wire"]))
        message.qd[0].name = "another.example"
        message.an[0].cname = "ignored.example"
        wire = F.header([1, 1, 0, 0]) + b"\x07another\x07example\0" + struct.pack("!HH", 5, 1)
        wire += b"\x04note\xc0\x14" + struct.pack("!HHIH", 5, 1, 60, 8) + b"\x05alias\xc0\x11"
        self.assertEqual(bytes(message), wire)
        message.an[0].rdata = b""
        message.an[0].cname = "alias.example"
        rebuilt = wire[:-8] + b"\x05alias\xc0\x14"
        self.assertEqual(bytes(message), rebuilt)
        self.assertEqual(dns.DNS(rebuilt).an[0].cname, "alias.example")

    def test_addresses_and_opaque_records(self):
        case = next(c for c in F.cases() if c["id"] == "rr-1")
        message = dns.DNS(bytes.fromhex(case["wire"]))
        message.an[0].ip = bytes.fromhex("c000020a")
        self.assertEqual(bytes(message).hex(), case["wire"])
        message.an[0].rdata = b""
        self.assertEqual(dns.DNS(bytes(message)).an[0].ip, bytes.fromhex("c000020a"))
        for kind in (10, 41):
            case = next(c for c in F.cases() if c["id"] == "rr-" + str(kind))
            self.assertEqual(bytes(dns.DNS(bytes.fromhex(case["wire"]))).hex(), case["wire"])
        built = dns.DNS(an=[dns.DNS.RR(name="", type=dns.DNS_A, rdata=b"x")])
        self.assertEqual(bytes(built)[-1:], b"x")
        with self.assertRaises(PackError):
            bytes(dns.DNS(an=[dns.DNS.RR(name="", type=65280)]))
        with self.assertRaises(AttributeError):
            bytes(dns.DNS(an=[dns.DNS.RR(name="", type=dns.DNS_A)]))

    def test_mx_preference_is_a_tuple_as_in_dpkt(self):
        case = next(c for c in F.cases() if c["id"] == "rr-15")
        message = dns.DNS(bytes.fromhex(case["wire"]))
        self.assertEqual(message.an[0].preference, (10,))
        message.an[0].rdata = b""
        # As in dpkt, the parsed tuple cannot be packed again.
        with self.assertRaises(struct.error):
            bytes(message)
        message.an[0].preference = 10
        self.assertEqual(bytes(message).hex(), case["wire"])
        message.an[0].preference = 20
        self.assertEqual(dns.DNS(bytes(message)).an[0].preference, (20,))

    def test_utf8_names_and_text(self):
        message = dns.DNS(
            qd=[dns.DNS.Q(name="café.example")],
            an=[dns.DNS.RR(name="", type=dns.DNS_TXT, text=["café".encode(), b"note"])],
        )
        parsed = dns.DNS(bytes(message))
        self.assertEqual(parsed.qd[0].name, "café.example")
        self.assertEqual(parsed.an[0].text, ["café", "note"])
        for raw in (
            b"\x02\xff\xfe\0\0\1\0\1",
            b"\0" + struct.pack("!HHIH", 16, 1, 0, 2) + b"\x01\xff",
        ):
            counts = [1, 0, 0, 0] if raw[0] else [0, 1, 0, 0]
            with self.assertRaises(dns.TextDecodeError) as caught:
                dns.DNS(F.header(counts) + raw)
            self.assertIsInstance(caught.exception, octetrail.UnpackError)
            self.assertIsInstance(caught.exception, UnicodeDecodeError)
            self.assertIn("'utf-8' codec can't decode byte 0xff", str(caught.exception))
        # Packing text and names fails the way it does in dpkt.
        with self.assertRaises(struct.error):
            bytes(dns.DNS(an=[dns.DNS.RR(name="", type=dns.DNS_TXT, text=[b"x" * 256])]))
        with self.assertRaises(TypeError):
            bytes(dns.DNS(an=[dns.DNS.RR(name="", type=dns.DNS_TXT, text=["text"])]))
        with self.assertRaises(TypeError):
            bytes(dns.DNS(qd=[dns.DNS.Q(name=b"bytes")]))

    def test_module_name_helpers(self):
        pointers = {}
        self.assertEqual(dns.pack_name("a.b", 12, pointers), b"\x01a\x01b\x00")
        self.assertEqual(pointers, {b"A.B.": 12, b"B.": 14})
        self.assertEqual(dns.pack_name("x.A.b", 30, pointers), b"\x01x\xc0\x0c")
        self.assertEqual(pointers[b"X.A.B."], 30)
        self.assertEqual(dns.unpack_name(b"\0\x01b\xc0\x00", 1), ("b", 5))
        with self.assertRaises(NeedData) as caught:
            dns.unpack_name(b"\x01a", 0)
        self.assertEqual(str(caught.exception), "")
        with self.assertRaises(octetrail.UnpackError):
            dns.unpack_name(b"\xc0\x00", 0)
        self.assertEqual((dns.DNS_RCODE_YXDOMAIN, dns.DNS_RCODE_NOTZONE), (6, 10))

    def test_header_counts_flags_and_independent_defaults(self):
        a, b = dns.DNS(), dns.DNS()
        a.qd.append(dns.DNS.Q(name=""))
        self.assertEqual(b.qd, [])
        a.opcode = 31
        a.rcode = 31
        a.ad = 1
        a.cd = 1
        self.assertEqual((a.opcode, a.rcode, a.ad, a.cd), (15, 15, 1, 1))
        self.assertEqual(bytes(a), struct.pack("!6H", 0, a.op, 1, 0, 0, 0) + b"\0\0\1\0\1")
        self.assertEqual(len(a), len(bytes(a)))
        with self.assertRaises(PackError):
            a.pack_hdr()  # As in dpkt, the sections are lists, not counts.
        for q in (dns.DNS.Q(name=""), dns.DNS.RR(name="")):
            with self.assertRaises(NotImplementedError):
                len(q)
        with self.assertRaises(struct.error):
            bytes(dns.DNS(id=65536))
        with self.assertRaises(AttributeError):
            bytes(dns.DNS(an=[dns.DNS.RR(name="", type=dns.DNS_MX)]))
        with self.assertRaises(AttributeError):
            bytes(dns.DNS(qd=[object()]))
        with self.assertRaises(TypeError):
            bytes(dns.DNS(qd=[dns.DNS.Q()]))  # The default name is b"", as in dpkt.

    def test_resource_and_programmer_errors_propagate(self):
        for error in (MemoryError("memory"), ValueError("caller")):
            with (
                patch.object(dns._native, "_dns_unpack_name", side_effect=error),
                self.assertRaises(type(error)) as result,
            ):
                dns.DNS(bytes(4) + b"\0\1" + bytes(6) + b"\0\0\1\0\1")
            self.assertIs(result.exception, error)

    def test_subclasses_replace_each_step(self):
        class Record(dns.DNS.RR):
            def unpack_rdata(self, buf, off):
                self.seen = off

        class Sub(dns.DNS):
            RR = Record

        wire = bytes.fromhex(next(c["wire"] for c in F.cases() if c["id"] == "rr-1"))
        message = Sub(wire)
        self.assertIsInstance(message, octetrail.Packet)
        self.assertIsInstance(message.an[0], Record)
        self.assertEqual(message.an[0].seen, len(wire) - 4)
        self.assertFalse(hasattr(message.an[0], "ip"))
        self.assertEqual(bytes(message), wire)

    def test_pointer_chains_share_one_budget(self):
        # Each owner name follows a chain of 7000 backward pointers.
        links, base = 7000, 12 + 1 + 10
        chain = b"\0" + b"".join(
            struct.pack("!H", 0xC000 | (base if i == 0 else base + 1 + 2 * (i - 1)))
            for i in range(links)
        )
        first = b"\0" + struct.pack("!HHIH", 10, 1, 0, len(chain)) + chain
        row = struct.pack("!HHHIH", 0xC000 | (base + 1 + 2 * (links - 1)), 10, 1, 0, 0)
        two = dns.DNS(struct.pack("!6H", 0, 0, 0, 2, 0, 0) + first + row)
        self.assertEqual(two.an[1].name, "")
        with self.assertRaises(dns.ParseLimitError):
            dns.DNS(struct.pack("!6H", 0, 0, 0, 3001, 0, 0) + first + row * 3000)

    def test_optimized_probe_rejects_wrong_installed_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/dns_differential.py",
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
