"""TCP segments and UDP datagrams run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same segments and datagrams, alone and inside IPv6,
including dpkt's own TCP test vectors, builds them from keywords, changes
their fields, splits TCP options and packs them again. OctetRail must match
dpkt 1.9.8 on every observation except the declared ones; the keys where 1.9.6
differs are listed.
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

# dpkt's test_tcp_unpack vector: a SYN-ACK with MSS, two NOPs and SACK permitted.
SYNACK_DPKT = "00500d2c114c618b38affe14701216d05bdc00000204056401010402"
# dpkt's test_offset vector: a 20-byte header.
OFFSET_DPKT = "01bbc0d7b656a8b9d1acaab15018400056f80000"
# dpkt's test_tcp_pack result.
PACK_DPKT = "0d2c005038affe130000000070022238c30c0000020405b401010402"
# dpkt's test_parse_opts buffers.
OPTS_DPKT = ("0204230001010402", "0101050a37f8197037f82978", "020001", "ff")


def tcp(off=5, opts=b"", body=b"", flags=0x18):
    return struct.pack(">HHIIHHHH", 1000, 2000, 1, 2, off << 12 | flags, 512, 0, 0) + opts + body


def udp(body=b"note", ulen=None):
    return struct.pack(">HHHH", 32000, 32001, 8 + len(body) if ulen is None else ulen, 0) + body


def ip6(nxt, body):
    return struct.pack(">IHBB16s16s", 0x60000000, len(body), nxt, 64, bytes(16), bytes(16)) + body


def cases():
    """(target, hex) by name."""
    return {
        "tcp_dpkt_synack": ("tcp", SYNACK_DPKT),
        "tcp_dpkt_offset": ("tcp", OFFSET_DPKT),
        "tcp_dpkt_pack": ("tcp", PACK_DPKT),
        "tcp_plain": ("tcp", tcp(body=b"seg").hex()),
        "tcp_options": ("tcp", tcp(6, b"\x02\x04\x05\xb4", b"x").hex()),
        "tcp_offset_15_short": ("tcp", tcp(15, b"\x01" * 8).hex()),
        "tcp_offset_4": ("tcp", tcp(4).hex()),
        "tcp_offset_0": ("tcp", tcp(0).hex()),
        "tcp_reserved_and_nonce": ("tcp", tcp(flags=0xFFF).hex()),
        "tcp_short": ("tcp", tcp()[:19].hex()),
        "tcp_empty": ("tcp", ""),
        "udp_plain": ("udp", udp().hex()),
        "udp_header_only": ("udp", udp(b"").hex()),
        "udp_ulen_short": ("udp", udp(b"payload", ulen=8).hex()),
        "udp_ulen_long": ("udp", udp(b"x", ulen=400).hex()),
        "udp_ulen_zero": ("udp", udp(b"x", ulen=0).hex()),
        "udp_short": ("udp", udp()[:7].hex()),
        "udp_large": ("udp", udp(b"x" * 70000, ulen=0).hex()),
        "ip6_tcp": ("ip6", ip6(6, tcp(body=b"seg")).hex()),
        "ip6_tcp_bad_offset": ("ip6", ip6(6, tcp(3)).hex()),
        "ip6_udp": ("ip6", ip6(17, udp()).hex()),
        "ip6_udp_short": ("ip6", ip6(17, b"\x00\x01").hex()),
    }


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
    found = {"class": type(packet).__name__, "repr": repr(packet)}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {k: repr(v) for k, v in sorted(vars(packet).items()) if k[0] != "_"}
    data = getattr(packet, "data", None)
    if data is not None and not isinstance(data, (bytes, bytearray, str)):
        found["data"] = snapshot(data)
    return found


def kind(action):
    # struct error messages differ between Python versions, so only the class is kept.
    found = attempt(action)
    return found.get("error", "packed") if isinstance(found, dict) else found


def constructed(package):
    tcpm, udpm, ip6m = package.tcp, package.udp, package.ip6

    def dpkt_pack():
        segment = tcpm.TCP(
            sport=3372,
            dport=80,
            seq=951057939,
            ack=0,
            off=7,
            flags=tcpm.TH_SYN,
            win=8760,
            sum=0xC30C,
            urp=0,
            opts=b"\x02\x04\x05\xb4\x01\x01\x04\x02",
        )
        return [bytes(segment).hex(), len(segment), repr(segment)]

    def dpkt_offset():
        segment = tcpm.TCP(bytes.fromhex(OFFSET_DPKT))
        segment.off = 8
        return [bytes(segment).hex(), segment.off, segment._off_flags]

    def printed(packet):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            packet.pprint()
        return out.getvalue()

    def buffer_types():
        found = []
        for kind in (bytearray, memoryview):
            segment = tcpm.TCP(kind(tcp(6, b"\x01" * 4, b"seg")))
            datagram = udpm.UDP(kind(udp()))
            found.append([type(segment.opts).__name__, type(segment.data).__name__])
            found.append([type(datagram.data).__name__, bytes(datagram.data).hex()])
        return found

    def ip6_checksums():
        segment = tcpm.TCP(sport=1, dport=2, data=b"seg")
        datagram = udpm.UDP(sport=1, dport=0xFFDB)
        wires = [
            bytes(ip6m.IP6(nxt=6, plen=len(segment), data=segment)).hex(),
            bytes(ip6m.IP6(nxt=17, plen=8, data=datagram)).hex(),
        ]
        return [wires, segment.sum, datagram.sum]

    return {
        "default_tcp": attempt(lambda: snapshot(tcpm.TCP())),
        "default_udp": attempt(lambda: snapshot(udpm.UDP())),
        "dpkt_pack": attempt(dpkt_pack),
        "dpkt_offset": attempt(dpkt_offset),
        "dpkt_parse_opts": attempt(lambda: [tcpm.parse_opts(bytes.fromhex(h)) for h in OPTS_DPKT]),
        "parse_opts_more": attempt(
            lambda: [
                tcpm.parse_opts(b)
                for b in (b"", b"\x00", b"\x08\x0a" + bytes(8), b"\x02\x01xyz", b"\x05\x09ab")
            ]
        ),
        "flags_to_str": attempt(
            lambda: [tcpm.tcp_flags_to_str(v) for v in (0, 0x18, 0x12, 0x1FF, 0x200)]
        ),
        "keywords_and_extras": attempt(
            lambda: snapshot(tcpm.TCP(sport=1, flags=tcpm.TH_ACK, opts=b"\x01", note="kept"))
        ),
        "udp_keywords": attempt(lambda: snapshot(udpm.UDP(sport=53, data=b"q", extra=1))),
        "udp_ulen_not_inferred": attempt(lambda: bytes(udpm.UDP(data=b"payload")).hex()),
        "flag_setters": attempt(
            lambda: [
                (s := tcpm.TCP()),
                setattr(s, "flags", 0x1FF),
                setattr(s, "off", 15),
                setattr(s, "_rsv", 7),
                s._off_flags,
            ][-1]
        ),
        "flag_too_large": attempt(lambda: setattr(tcpm.TCP(), "flags", 0x200)),
        "pack_errors": attempt(
            lambda: [
                kind(lambda: bytes(tcpm.TCP(sport=70000))),
                kind(lambda: bytes(tcpm.TCP(seq=-1))),
                kind(lambda: bytes(udpm.UDP(ulen="8"))),
                kind(lambda: bytes(tcpm.TCP(opts="text"))),
                kind(lambda: bytes(udpm.UDP(data=[1]))),
            ]
        ),
        "pprint_tcp": attempt(lambda: printed(tcpm.TCP(bytes.fromhex(SYNACK_DPKT)))),
        "pprint_udp": attempt(lambda: printed(udpm.UDP(udp()))),
        "dict": attempt(
            lambda: [
                sorted(dict(tcpm.TCP(bytes.fromhex(SYNACK_DPKT))).items()),
                sorted(dict(udpm.UDP(udp())).items()),
            ]
        ),
        "buffer_types": attempt(buffer_types),
        "ip6_checksums": attempt(ip6_checksums),
        "nested_layer": attempt(
            lambda: [
                bytes(tcpm.TCP(data=udpm.UDP(data=b"in"))).hex(),
                len(tcpm.TCP(data=udpm.UDP(data=b"in"))),
                type(tcpm.TCP(data=udpm.UDP())[udpm.UDP]).__name__,
            ]
        ),
        "constants": attempt(
            lambda: [
                tcpm.TH_NS,
                tcpm.TCP_PORT_MAX,
                tcpm.TCP_WIN_MAX,
                tcpm.TCP_OPT_TCPCOMP,
                tcpm.TCP_OPT_MAX,
                udpm.UDP_HDR_LEN,
                udpm.UDP_PORT_MAX,
            ]
        ),
    }


def exercise(package):
    targets = {"tcp": package.tcp.TCP, "udp": package.udp.UDP, "ip6": package.ip6.IP6}
    return {
        "cases": {
            name: attempt(lambda t=t, h=h: snapshot(targets[t](bytes.fromhex(h))))
            for name, (t, h) in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for member in ("tcp", "udp", "ip6"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified TCP or UDP module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose.
DECLARED = {}


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
        C.require(not wrong, "TCP or UDP mismatch " + module + v + ": " + ", ".join(wrong))
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
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
