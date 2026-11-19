"""IPv4 datagrams run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same datagrams, including dpkt's own test vectors,
builds them from keywords, changes their fields and packs them again.
OctetRail must match dpkt 1.9.8 on every observation except the declared ones;
the keys where 1.9.6 differs are listed. The payloads only use protocols both
libraries decode. TCP and UDP payloads are compared by bytes and fields, not by
repr, since TCP and UDP parity is a separate module.
"""

import argparse
import contextlib
import importlib
import importlib.metadata
import importlib.util
import io
import json
import struct
import subprocess
import sys
import warnings

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 runs only the probes, which read no TOML.

    class tomllib:
        @staticmethod
        def loads(_text):
            raise SystemExit("reading pyproject.toml needs Python 3.11 or later")


from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "composition_fixture", Path(__file__).with_name("composition_differential.py")
)
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)

SRC = bytes.fromhex("c0000201")
DST = bytes.fromhex("c6336402")
# An ordinary datagram with protocol 253 and the payload "rail".
LITERAL = "450000181234400040fd3b7ec0000201c63364027261696c"
# dpkt's test_ip vector: UDP from port 111 to 222 carrying "foobar".
UDP_DPKT = "4500002200000000401172c00102030401020304006f00de000ebf35666f6f626172"
# dpkt's test_opt vector: a 60-byte header with options and an empty TCP segment.
OPTS_DPKT = (
    "4f00003cae08000040061810c0a80a26c0a80a010727080102030401000000000000000000000000"
    "0000000000000000000000000000000000000000"
)
# dpkt's test_iplen vector: UDP with a payload.
IPLEN_DPKT = (
    "450000a3b67a000080115e6fc0a803029747ca6ec73864df008f4afa26d815bed942ae66e1ce145f"
    "06794b1302ada48b691c7af6d53d45aabacd2477c2e75f6accb51f21fa62f0f332e1e4f0201f4761"
    "ecbcb10e6cf0b86d7f969b3503a17905c5fd2af7fa35e30e04d0c74e94723d075aa8532a5d03f704"
    "c4a8b8a1"
)
# dpkt's test_zerolen vector header: total length 0, as with segmentation offload.
ZEROLEN_DPKT = "4500000034ce4000800600007f0000017f000001cc4e0c3860ffc64e5f8a1298501840293aa30000"
# dpkt's test_frag vector: an Ethernet frame carrying an ICMP echo request.
FRAG_DPKT = (
    "002320d42a8c002320d42a8c080045000054000040004001258d0a00008f0a00008e08002ea001ff"
    "237320484a4d000000007885020000000000101112131415161718191a1b1c1d1e1f202122232425"
    "262728292a2b2c2d2e2f3031323334353637"
)
# IPv6 in IPv4 whose next header is 44 after an AH header.
IP6_FRAGMENT_AFTER_AH = (
    "4500005a0001000040290000010203040506070860000000001e2c40267dfba003257d76a397ad2d"
    "06dd272b093c18d34a5fda962ec0c9ec8a3655cc3351fb18cd83f2f91e5e0caa8cdbbf30f84e247e"
    "08df87dd91adc1dfcd49"
)
# dpkt's test_hl vector: a header length of 2 words.
HL_DPKT = (
    "42420300000000000000d000ecbca500000003800000d001f2aca522300100140002000f000000000000000000"
)


def header(p=253, body=b"", ihl=5, opts=b"", total=None, flags=0, version=4):
    total = 20 + len(opts) + len(body) if total is None else total
    raw = struct.pack(">BBHHHBBH4s4s", version << 4 | ihl, 0, total, 7, flags, 64, p, 0, SRC, DST)
    return raw + opts + body


def udp(body=b"note"):
    return struct.pack(">HHHH", 32000, 32001, 8 + len(body), 0) + body


def tcp(body=b""):
    return struct.pack(">HHIIBBHHH", 1000, 2000, 1, 0, 0x50, 0x18, 512, 0, 0) + body


def ip6(body=b"note"):
    return struct.pack(">IHBB16s16s", 0x60000000, len(body), 59, 64, bytes(16), bytes(16)) + body


def cases():
    """Datagrams by name, as hex."""
    found = {
        "literal": LITERAL,
        "literal_with_padding": LITERAL + "706164",
        "dpkt_udp": UDP_DPKT,
        "dpkt_options_tcp": OPTS_DPKT,
        "dpkt_iplen_udp": IPLEN_DPKT,
        "dpkt_zero_length_tcp": ZEROLEN_DPKT + "58" * 2048,
        "dpkt_header_length_2": HL_DPKT,
        "empty": "",
        "short": header()[:19].hex(),
        "header_only": header().hex(),
        "ihl_4": header(ihl=4).hex(),
        "ihl_0": header(ihl=0).hex(),
        "ihl_15_short_options": header(ihl=15, opts=b"\x01" * 8).hex(),
        "ihl_6_options": header(ihl=6, opts=b"\x94\x04\x00\x00", body=b"rail").hex(),
        "total_inside_header": header(ihl=6, opts=b"\x01" * 4, total=20, body=b"x").hex(),
        "total_beyond_buffer": header(total=200, body=b"cut").hex(),
        "total_zero_keeps_rest": header(total=0, body=b"offload").hex(),
        "version_6_nibble": header(version=6, body=b"rail").hex(),
        "version_0_nibble": header(version=0, body=b"rail").hex(),
        "udp": header(17, udp()).hex(),
        "udp_short": header(17, b"\x00\x01").hex(),
        "tcp": header(6, tcp(b"seg")).hex(),
        "tcp_short": header(6, b"\x00\x01\x02").hex(),
        "tcp_bad_offset": header(6, tcp()[:12] + b"\x10" + tcp()[13:]).hex(),
        "first_fragment_udp": header(17, udp(), flags=0x2000).hex(),
        "later_fragment_udp": header(17, udp(), flags=0x2001).hex(),
        "later_fragment_unknown": header(253, b"frag", flags=0x00B9).hex(),
        "df_reserved_bits": header(17, udp(), flags=0xC000).hex(),
        "ip_in_ip": header(4, header(17, udp())).hex(),
        "ip_in_ip_short": header(4, b"\x45\x00").hex(),
        "protocol_0_inner_ip": header(0, header(253, b"in")).hex(),
        "ipv6_in_ip": header(41, ip6()).hex(),
        "ipv6_in_ip_short": header(41, b"\x60").hex(),
        "unknown_protocol": header(253, b"opaque").hex(),
        "ipv6_fragment_after_ah": IP6_FRAGMENT_AFTER_AH,
        "dpkt_fragment_icmp": FRAG_DPKT[28:],
        "icmp_echo": header(1, b"\x08\x00\xf7\xfc\x00\x01\x00\x02").hex(),
        "icmp_unreach_quote": header(1, b"\x03\x03\x00\x00" + bytes(4) + header(17, udp())).hex(),
        "icmp_short": header(1, b"\x08").hex(),
        "igmp_query": header(2, b"\x11\x64\xee\x9b" + bytes(4)).hex(),
        "icmp6_in_ipv4": header(58, b"\x80\x00\x00\x00\x00\x07\x00\x01ping").hex(),
        "vrrp_advert": header(112, bytes.fromhex("210164010001ba52c0a80001") + bytes(8)).hex(),
        "stp_protocol_118": header(118, bytes(35)).hex(),
    }
    return found


def as_json(v):
    if isinstance(v, (bytes, bytearray)):
        return {"hex": bytes(v).hex()}
    if isinstance(v, (int, str, bool, type(None))):
        return v
    if isinstance(v, (list, tuple)):
        return [as_json(x) for x in v]
    if isinstance(v, dict):
        return {str(k): as_json(x) for k, x in v.items()}
    return {"repr": repr(v)}


def attempt(action):
    try:
        return as_json(action())
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}


def snapshot(packet):
    # TCP and UDP are not Packet subclasses yet, so their repr is not compared;
    # their bytes are.
    layer, transport = packet, False
    while not transport and hasattr(layer, "data"):
        layer = layer.data
        transport = type(layer).__name__ in ("TCP", "UDP")
    found = {"class": type(packet).__name__, "repr": None if transport else repr(packet)}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {
        k: type(v).__name__ if transport and k != "opts" else repr(v)
        for k, v in sorted(vars(packet).items())
        if k[0] != "_"
    }
    found["after"] = {
        name: getattr(packet, name)
        for name in ("v", "hl", "len", "sum", "rf", "df", "mf", "offset", "p")
        if hasattr(packet, name)
    }
    data = getattr(packet, "data", None)
    if data is not None and not isinstance(data, (bytes, bytearray, str)):
        found["data_class"] = type(data).__name__
        found["data_bytes"] = attempt(lambda: bytes(data).hex())
        if type(data).__name__ in ("IP", "IP6"):
            found["data"] = snapshot(data)
    return found


def warned(action):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        value = attempt(action)
    return [value, [(w.category.__name__, str(w.message)) for w in caught]]


def constructed(package):
    ip, udpm, tcpm, eth = package.ip, package.udp, package.tcp, package.ethernet

    def keyword_udp():
        packet = ip.IP(id=0, src=b"\x01\x02\x03\x04", dst=b"\x01\x02\x03\x04", p=17)
        child = udpm.UDP(sport=111, dport=222)
        child.data = b"foobar"
        child.ulen += len(child.data)
        packet.data = child
        packet.len += len(child)
        return [bytes(packet).hex(), packet.v, packet.hl, packet.len, packet.sum, child.sum]

    def fragment_keeps_sum():
        child = udpm.UDP(sport=1, dport=2, ulen=12, data=b"note")
        packet = ip.IP(src=SRC, dst=DST, p=17, mf=1, data=child)
        return [bytes(packet).hex(), child.sum]

    def setters():
        packet = ip.IP(src=SRC, dst=DST)
        packet.rf, packet.df, packet.mf, packet.offset = 1, 0, 1, 1480
        packet.v, packet.hl = 6, 7
        return [packet._flags_offset, packet._v_hl, bytes(packet).hex()]

    def stale_then_reset():
        packet = ip.IP(bytes.fromhex(LITERAL))
        packet.ttl = 63
        stale = bytes(packet).hex()
        packet.sum = 0
        packet.data = b"other"
        return [stale, bytes(packet).hex(), packet.len, packet.sum]

    def deleted_bit_field():
        packet = ip.IP(df=1, offset=9, v=6)
        del packet.df
        del packet.v
        return [packet._flags_offset, packet._v_hl]

    def printed():
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ip.IP(header(253, b"rail", ihl=6, opts=b"\x94\x04\x00\x00")).pprint()
        return out.getvalue()

    def buffer_types():
        found = []
        for kind in (bytearray, memoryview):
            packet = ip.IP(kind(header(253, b"rail", ihl=6, opts=b"\x01" * 4)))
            found.append([type(packet.opts).__name__, type(packet.data).__name__])
            found.append(bytes(packet.data).hex())
        return found

    def ethernet_frame():
        frame = eth.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6, data=ip.IP(p=17, data=udpm.UDP()))
        wire = bytes(frame)
        return [wire.hex(), type(eth.Ethernet(wire).ip.data).__name__]

    def tables():
        return [
            sorted((p, ip.IP.get_proto(p).__name__) for p in (0, 1, 2, 4, 6, 17, 41, 58, 112, 118)),
            package.ip6.IP6._protosw is ip.IP._protosw,
            ip.get_ip_proto_name(6),
            ip.get_ip_proto_name(0),
            ip.get_ip_proto_name(999),
            len(ip._ip_proto_names),
            sorted(k for k in vars(ip) if k.startswith("IP_PROTO_"))[:5],
            len([k for k in vars(ip) if k.startswith("IP_")]),
        ]

    return {
        "default": attempt(lambda: snapshot(ip.IP())),
        "default_len": attempt(lambda: [ip.IP().len, ip.IP(data=b"rail").len]),
        "keyword_udp": attempt(keyword_udp),
        "hello_world": attempt(
            lambda: [
                bytes(ip.IP(data=b"Hello world!")).hex(),
                bytes(ip.IP(data=b"Hello world!", len=0)).hex(),
            ]
        ),
        "explicit_sum_kept": attempt(lambda: snapshot(ip.IP(sum=1, len=99, data=b"rail"))),
        "udp_checksum_all_ones": attempt(
            lambda: [
                bytes(
                    p := ip.IP(
                        src=b"\x00\x00\x00\x01",
                        dst=b"\x00\x00\x00\x01",
                        p=17,
                        data=udpm.UDP(sport=1, dport=0xFFDB),
                    )
                ).hex(),
                p.data.sum,
            ]
        ),
        "tcp_checksum_filled": attempt(
            lambda: snapshot(
                ip.IP(src=SRC, dst=DST, p=6, data=tcpm.TCP(sport=1, dport=2, data=b"seg"))
            )
        ),
        "tcp_class_under_udp_protocol": attempt(
            lambda: snapshot(ip.IP(src=SRC, dst=DST, p=17, data=tcpm.TCP(sport=1, dport=2)))
        ),
        "fragment_keeps_transport_sum": attempt(fragment_keeps_sum),
        "setters": attempt(setters),
        "setter_too_large": attempt(lambda: setattr(ip.IP(), "offset", 1 << 13)),
        "stale_then_reset": attempt(stale_then_reset),
        "deleted_bit_field": attempt(deleted_bit_field),
        "off_get": warned(lambda: ip.IP(bytes.fromhex(LITERAL)).off),
        "off_set": warned(lambda: [(p := ip.IP()), setattr(p, "off", 3), p._flags_offset][2]),
        "options_as_assigned": attempt(lambda: bytes(ip.IP(hl=15, opts=b"\x01" * 44)).hex()),
        "odd_options_checksum": attempt(
            lambda: snapshot(ip.IP(hl=6, opts=b"\x01\x02\x03", data=b"r"))
        ),
        "source_not_bytes": attempt(lambda: bytes(ip.IP(src="abcd"))),
        "too_long": attempt(lambda: bytes(ip.IP(data=b"x" * 65516))),
        "too_long_explicit_sum": attempt(lambda: len(bytes(ip.IP(sum=1, data=b"x" * 65516)))),
        "dict": attempt(lambda: sorted(dict(ip.IP(bytes.fromhex(LITERAL))).items())),
        "pprint": attempt(printed),
        "buffer_types": attempt(buffer_types),
        "ethernet_frame": attempt(ethernet_frame),
        "layer_lookup": attempt(
            lambda: [
                type(ip.IP(bytes.fromhex(UDP_DPKT))[udpm.UDP]).__name__,
                udpm.UDP in ip.IP(bytes.fromhex(UDP_DPKT)),
                tcpm.TCP in ip.IP(bytes.fromhex(UDP_DPKT)),
            ]
        ),
        "repack_iplen": attempt(lambda: ip.IP(bytes(ip.IP(bytes.fromhex(IPLEN_DPKT)))).len),
        "tables": attempt(tables),
        "constants": attempt(
            lambda: [
                ip.IP_HDR_LEN,
                ip.IP_HDR_LEN_MAX,
                ip.IP_ADDR_BROADCAST,
                ip.IP_TOS_PREC_NETCONTROL,
                ip.IP_OFFMASK,
                ip.IP_TTL_DEFAULT,
                ip.IP_PROTO_RAW,
                ip.IP_PROTO_MAX,
            ]
        ),
    }


def exercise(package):
    return {
        "cases": {
            name: attempt(lambda h=h: snapshot(package.ip.IP(bytes.fromhex(h))))
            for name, h in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for member in ("ip", "ip6", "tcp", "udp", "ethernet"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified IPv4 module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. dpkt raises
# AttributeError out of IP when an IPv6 payload has next header 44 after a header
# that is not a fragment header. OctetRail raises FragmentOffsetError, an
# UnpackError, inside the payload, so IP keeps it as bytes, as Ethernet, IP6 and
# ICMP6 keep such a payload.
_INNER = bytes.fromhex(IP6_FRAGMENT_AFTER_AH)[20:]
# OctetRail fixes dpkt here (address constants are bytes, protocol 118 is not Spanning Tree). These keys are not compared;
# tests/python checks the fixed results.
FIXED = {
    "cases.stp_protocol_118",
    "constructed.constants",
    "constructed.tables",
}

DECLARED = {
    "cases.ipv6_fragment_after_ah": {
        "class": "IP",
        "repr": "IP(len=90, id=1, p=41, src=b'\\x01\\x02\\x03\\x04', "
        "dst=b'\\x05\\x06\\x07\\x08', opts=b'', data=%r)" % _INNER,
        "len": 90,
        "bytes": "4500005a0001000040296a670102030405060708" + _INNER.hex(),
        "fields": {"opts": "b''"},
        "after": {
            "v": 4,
            "hl": 5,
            "len": 90,
            "sum": 27239,
            "rf": 0,
            "df": 0,
            "mf": 0,
            "offset": 0,
            "p": 41,
        },
    },
}


def flatten(report):
    return {
        section + "." + key: found
        for section, entries in report.items()
        for key, found in entries.items()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--module", choices=("dpkt", "octetrail"))
    parser.add_argument("--version")
    parser.add_argument("--oracle-196")
    parser.add_argument("--oracle-198")
    parser.add_argument("--python", action="append", default=[])
    args = parser.parse_args()
    if args.probe:
        print(json.dumps(exercise(provenance(args.module, args.version))))
        return
    C.require(
        args.oracle_196 and args.oracle_198 and args.python,
        "both pins and an installed provider are required",
    )
    version = tomllib.loads((C.ROOT / "pyproject.toml").read_text())["project"]["version"]
    providers = [
        (args.oracle_196, "dpkt", "1.9.6"),
        (args.oracle_198, "dpkt", "1.9.8"),
        *((p, "octetrail", version) for p in args.python),
    ]
    reports = []
    for python, module, v in providers:
        result = subprocess.run(
            [python, "-B", "-I", "-O", __file__, "--probe", "--module", module, "--version", v],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        reports.append(flatten(json.loads(result.stdout)))
    reference = reports[1]
    for (_, module, v), report in zip(providers[2:], reports[2:], strict=True):
        wrong = sorted(
            k
            for k in reference
            if k not in FIXED and report.get(k) != DECLARED.get(k, reference[k])
        )
        C.require(not wrong, "IPv4 mismatch " + module + v + ": " + ", ".join(wrong))
    print(
        json.dumps(
            {
                "cases": len(cases()),
                "observations": len(reference),
                "providers": len(providers),
                "dpkt_196_differs_on": sorted(
                    k for k in reference if reports[0].get(k) != reference[k]
                ),
                "declared_differences": sorted(DECLARED),
                "fixed_dpkt_bugs": sorted(FIXED),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
