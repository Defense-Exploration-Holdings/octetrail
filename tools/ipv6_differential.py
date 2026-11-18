"""IPv6 packets and extension headers run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same hand-assembled packets, builds the same packets
from fields, changes them and packs them. OctetRail must match dpkt 1.9.8 on
every observation; the keys where 1.9.6 differs are listed. The payloads are
protocols both libraries decode (TCP, UDP, IPv4 and IPv6) or bytes.
"""

import argparse
import importlib
import importlib.metadata
import importlib.util
import json
import struct
import subprocess
import sys

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

SRC = bytes.fromhex("20010db8000000000000000000000001")
DST = bytes.fromhex("20010db8000000000000000000000002")
TCP = struct.pack(">HHIIBBHHH", 49152, 80, 1, 2, 0x50, 0x18, 1024, 0, 0)
UDP = struct.pack(">HHHH", 53, 53, 12, 0) + b"note"
V4 = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 32, 0, 0, 64, 17, 0, b"\x0a\0\0\1", b"\x0a\0\0\2")


def base(nxt, payload, plen=None, first=0x60000000):
    size = len(payload) if plen is None else plen
    return struct.pack(">IHBB16s16s", first, size, nxt, 64, SRC, DST) + payload


def opts(nxt, body=b"\x01\x04\0\0\0\0"):
    return bytes([nxt, (len(body) + 2) // 8 - 1]) + body


def routing(nxt, addresses=1, segs=1):
    return bytes([nxt, addresses * 2, 0, segs]) + b"\0\0\0\0" + SRC * addresses


def fragment(nxt, offset=0, more=0, ident=7):
    return bytes([nxt, 0]) + struct.pack(">HI", offset << 3 | more, ident)


def ah(nxt, auth=b"xxxxxxxx", length=None):
    n = (len(auth) + 12) // 4 - 2 if length is None else length
    return bytes([nxt, n]) + b"\0\0" + struct.pack(">II", 0x2020202, 0x1010101) + auth


def cases():
    """Hex packets, by name. The dpkt test vectors are included."""
    found = {
        "dpkt_tcp": "6000000000280640fe80000000000000021124fffe8c11defe8000000000000002b0d0ff"
        "fee18072cdca0016048446d500000000a002fffff8090000020405a0010303000101080a7d1835"
        "3f00000000",
        "dpkt_routing": "60000000003c2b402048000000000000000000000000deca2047000000000000000000"
        "000000cafe06040002000000002001000000000000000000000000deca2022000000000000000000"
        "000000deca00140050000000000000000050022000917f0000",
        "dpkt_fragment": "6000000000102c0002220000000000000000000000000002033300000000000000000000"
        "0000000329000001000000006000000000102c00",
    }
    built = {
        "tcp": base(6, TCP),
        "udp": base(17, UDP),
        "ipv4_in_ipv6": base(4, V4),
        "ipv6_in_ipv6": base(41, base(17, UDP)),
        "unknown_protocol": base(253, b"opaque"),
        "no_next_header": base(59, b"tail"),
        "plen_zero_reads_all": base(17, UDP, plen=0),
        "plen_short": base(17, UDP, plen=10),
        "plen_long": base(17, UDP, plen=200),
        "trailing_bytes": base(17, UDP + b"pad", plen=len(UDP)),
        "version_four": base(17, UDP, first=0x4ABCDEF1),
        "hop_by_hop": base(0, opts(17) + UDP),
        "options_listed": base(60, opts(6, b"\x05\x02ab\0\xc2\x04\0\0\0\0\x01\0" + bytes(8)) + TCP),
        "options_past_length": base(0, opts(59, b"\0\0\0\0\x05\x09") + b"ninebytes"),
        "options_need_data": base(0, opts(59, b"\0\0\0\0\0\x05")[:7]),
        "routing_two": base(43, routing(6, 2) + TCP),
        "routing_short": base(43, routing(6, 2)[:30]),
        "atomic_fragment": base(44, fragment(17) + UDP),
        "first_fragment": base(44, fragment(17, 0, 1) + UDP),
        "later_fragment": base(44, fragment(17, 5, 1) + UDP),
        "fragment_then_options": base(44, fragment(0, 5) + opts(17) + UDP),
        "options_then_fragment": base(0, opts(44) + fragment(17, 5) + UDP),
        "ah": base(51, ah(6) + TCP),
        "ah_zero_length": base(51, ah(17, b"", length=0) + UDP),
        "ah_chain": base(51, ah(51) + ah(51) + ah(17) + UDP),
        "esp": base(50, struct.pack(">II", 256, 68) + b"ciphertext"),
        "esp_after_options": base(0, opts(50) + struct.pack(">II", 1, 2) + b"data"),
        "every_extension": base(
            0,
            opts(43) + routing(44) + fragment(51) + ah(60) + opts(6) + TCP,
        ),
        "duplicate_options": base(60, opts(60) + opts(17) + UDP),
        "short_header": base(17, UDP)[:39],
        "short_extension": base(44, fragment(0) + b"\x11"),
        "empty": b"",
    }
    found.update({k: v.hex() for k, v in built.items()})
    return found


def attempt(action):
    try:
        value = action()
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}
    return as_json(value)


def as_json(v):
    if isinstance(v, (bytes, bytearray)):
        return {"hex": bytes(v).hex()}
    if isinstance(v, (int, str, bool, type(None))):
        return v
    if isinstance(v, (list, tuple)):
        return [as_json(x) for x in v]
    if isinstance(v, dict):
        return {str(k): as_json(x) for k, x in v.items()}
    return {"type": type(v).__name__}


def extension(ext):
    found = {"class": type(ext).__name__}
    for name in ext.__hdr_fields__:
        found[name] = getattr(ext, name)
    for name in ("length", "options", "addresses", "auth_data", "data"):
        found[name] = as_json(getattr(ext, name, None))
    for name in ("frag_off", "m_flag", "sl_bits"):
        if hasattr(type(ext), name):
            found[name] = getattr(ext, name)
    found["bytes"] = attempt(lambda: bytes(ext).hex())
    found["packed_len"] = attempt(lambda: len(ext))
    found["repr"] = attempt(lambda: repr(ext))
    return found


def snapshot(packet):
    found = {
        name: as_json(getattr(packet, name))
        for name in ("v", "fc", "flow", "plen", "nxt", "hlim", "src", "dst")
    }
    found["p"] = as_json(getattr(packet, "p", None))
    found["data_class"] = type(packet.data).__name__
    found["data"] = attempt(lambda: bytes(packet.data).hex())
    found["layers"] = sorted(n for n in ("tcp", "udp", "ip", "ip6") if hasattr(packet, n))
    found["extensions"] = [extension(e) for e in getattr(packet, "all_extension_headers", [])]
    found["extension_keys"] = sorted(getattr(packet, "extension_hdrs", {}))
    inner = packet.data
    while type(inner).__name__ == "IP6":
        inner = inner.data
    # TCP and UDP objects have their own repr in OctetRail, so only packets
    # that end in bytes compare repr.
    if isinstance(inner, bytes):
        found["repr"] = attempt(lambda: repr(packet))
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["p_after_pack"] = as_json(getattr(packet, "p", None))
    found["sum_after_pack"] = as_json(getattr(packet.data, "sum", None))
    return found


def parse(ip6, raw):
    try:
        packet = ip6.IP6(raw)
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}
    return snapshot(packet)


def constructed(package):
    ip6, tcp, udp = package.ip6, package.tcp, package.udp
    r = {}
    r["default"] = snapshot(ip6.IP6())
    r["fields"] = snapshot(ip6.IP6(src=SRC, dst=DST, nxt=17, hlim=9, plen=12, data=b"payload"))
    r["tcp_checksum"] = snapshot(ip6.IP6(src=SRC, dst=DST, nxt=6, data=tcp.TCP(TCP)))
    r["udp_checksum"] = snapshot(ip6.IP6(src=SRC, dst=DST, nxt=17, data=udp.UDP(UDP)))
    kept = udp.UDP(UDP)
    kept.sum = 0x1234
    r["udp_kept_sum"] = snapshot(ip6.IP6(src=SRC, dst=DST, nxt=17, data=kept))
    r["bits"] = attempt(lambda: bytes(ip6.IP6(v=6, fc=0xAB, flow=0xBCDEF)).hex())
    r["bits_too_large"] = attempt(lambda: ip6.IP6(flow=1 << 20))
    r["bad_src"] = attempt(lambda: bytes(ip6.IP6(src="text")))
    r["big_plen"] = attempt(lambda: bytes(ip6.IP6(plen=65536)))
    r["short_src"] = attempt(lambda: bytes(ip6.IP6(src=b"\1")).hex())

    packet = ip6.IP6(bytes.fromhex(cases()["dpkt_routing"]))
    packet.extension_hdrs[0] = ip6.IP6HopOptsHeader(opts(43))
    packet.extension_hdrs[44] = ip6.IP6FragmentHeader(fragment(6, 0, 1))
    packet.all_extension_headers = []
    r["extension_hdrs_order"] = attempt(lambda: [packet.headers_str()[0], bytes(packet).hex()])
    packet = ip6.IP6(bytes.fromhex(cases()["udp"]))
    packet.data.sum = 0
    packet.hlim = 1
    r["repacked_udp"] = attempt(lambda: [bytes(packet).hex(), packet.data.sum])
    packet = ip6.IP6(bytes.fromhex(cases()["esp"]))
    r["esp_pack"] = attempt(lambda: bytes(packet).hex())
    packet = ip6.IP6(bytes.fromhex(cases()["ah"]))
    packet.all_extension_headers[0].data = b"replaced"
    r["ah_replaced_data"] = attempt(lambda: [bytes(packet).hex(), repr(packet.extension_hdrs[51])])
    packet = ip6.IP6(src=SRC, dst=DST, data=b"x")
    packet.extension_hdrs = {60: ip6.IP6DstOptsHeader(opts(17))}
    r["constructed_extensions"] = attempt(lambda: [bytes(packet).hex(), len(packet)])

    r["opts_direct"] = extension(
        ip6.IP6OptsHeader(
            bytes.fromhex(
                "3b04010200" + "00c910" + "00" * 16 + "0100c2040000000005020000010200" + "00"
            )
        )
    )
    r["fragment_direct"] = extension(ip6.IP6FragmentHeader(b"\x06\xee\xff\xf9\x00\x00\xff\xff"))
    frag = ip6.IP6FragmentHeader(b"\x06\xee\xff\xf9\x00\x00\xff\xff")
    frag._frag_off_resv_m = 0
    frag.frag_off, frag.m_flag = 8191, 1
    r["fragment_bits"] = attempt(lambda: bytes(frag).hex())
    r["ah_direct"] = extension(ip6.IP6AHHeader(b"\x3b\x04\0\0" + b"\2" * 4 + b"\1" * 4 + b"x" * 8))
    r["esp_direct"] = extension(ip6.IP6ESPHeader(bytes(8) + b"rest"))
    r["routing_direct"] = extension(ip6.IP6RoutingHeader(routing(6, 2)))
    r["routing_default"] = extension(ip6.IP6RoutingHeader())
    for name, cls, raw in (
        ("opts_short", ip6.IP6OptsHeader, b"\x3b"),
        ("opts_options_short", ip6.IP6DstOptsHeader, b"\x3b\x00\x05"),
        ("routing_short", ip6.IP6RoutingHeader, b"\0" * 7),
        ("fragment_short", ip6.IP6FragmentHeader, b"\0" * 7),
        ("ah_short", ip6.IP6AHHeader, b"\0" * 11),
        ("esp_short", ip6.IP6ESPHeader, b"\0" * 7),
        ("base_class", ip6.IP6ExtensionHeader, b"\0"),
    ):
        r[name] = attempt(lambda cls=cls, raw=raw: repr(cls(raw)))
    r["protosw"] = sorted(
        k for k in (0, 4, 6, 17, 41) if ip6.IP6.get_proto(k).__name__ in ("IP", "TCP", "UDP", "IP6")
    )
    r["ext_hdrs"] = [ip6.EXT_HDRS, sorted((k, v.__name__) for k, v in ip6.EXT_HDRS_CLS.items())]
    r["buffer_types"] = buffer_types(ip6)
    return r


def buffer_types(ip6):
    """Type names of the parsed slices for bytearray and memoryview input."""

    def names(ext):
        return [
            type(ext).__name__,
            type(getattr(ext, "data", None)).__name__,
            [type(o["data"]).__name__ for o in getattr(ext, "options", [])],
            [type(a).__name__ for a in getattr(ext, "addresses", [])],
            type(getattr(ext, "auth_data", None)).__name__,
        ]

    found = {}
    for kind in (bytearray, memoryview):
        for name, raw in cases().items():
            packet = attempt(lambda kind=kind, raw=raw: ip6.IP6(kind(bytes.fromhex(raw))))
            if isinstance(packet, dict) and "error" in packet:
                continue
            packet = ip6.IP6(kind(bytes.fromhex(raw)))
            found[kind.__name__ + "." + name] = [
                type(packet.data).__name__,
                [names(e) for e in packet.all_extension_headers],
            ]
        for cls, raw in (
            (ip6.IP6HopOptsHeader, opts(17)),
            (ip6.IP6RoutingHeader, routing(6, 2)),
            (ip6.IP6FragmentHeader, fragment(6)),
            (ip6.IP6AHHeader, ah(59)),
            (ip6.IP6ESPHeader, bytes(8) + b"rest"),
        ):
            found[kind.__name__ + "." + cls.__name__] = names(cls(kind(raw)))
    return found


def exercise(package):
    return {
        "cases": {name: parse(package.ip6, bytes.fromhex(raw)) for name, raw in cases().items()},
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".ip6").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/ip6.py")).resolve(),
        "unverified IPv6 module origin",
    )
    return package


# Observations where OctetRail differs from 1.9.8 on purpose: dpkt's
# AttributeError is raised as FragmentOffsetError, a subclass of both
# UnpackError and AttributeError.
DECLARED = {
    "cases.fragment_then_options": {
        "error": "FragmentOffsetError",
        "message": "'IP6HopOptsHeader' object has no attribute 'frag_off'",
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
        wrong = sorted(k for k in reference if report.get(k) != DECLARED.get(k, reference[k]))
        C.require(not wrong, "IPv6 mismatch " + module + v + ": " + ", ".join(wrong))
    print(
        json.dumps(
            {
                "packets": len(cases()),
                "observations": len(reference),
                "providers": len(providers),
                "dpkt_196_differs_on": sorted(
                    k for k in reference if reports[0].get(k) != reference[k]
                ),
                "declared_differences": sorted(DECLARED),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
