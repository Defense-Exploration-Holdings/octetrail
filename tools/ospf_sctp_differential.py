"""OSPF and SCTP packets run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same packets, alone and inside IPv4 and IPv6,
including dpkt's own test vectors, builds them from keywords and packs them
again. OctetRail must match dpkt 1.9.8 on every observation except the
declared ones; the keys where 1.9.6 differs are listed. dpkt 1.9.6 loops
forever on a chunk of length zero, so those cases are not run on it.
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

# dpkt's SCTP test vectors. The DATA chunk one carries an HTTP request and
# one padding byte.
SCTP_INIT_DPKT = (
    "804400500000000030baef540100003c3bb99c460001a000000affff2b2d7eb2"
    "000500089be6189b000500089be6189c000c00060005000080000004c0000004c006000800000000"
)
HTTP_GET = (
    b"GET / HTTP/1.1\r\nHost: 203.255.252.194\r\nUser-Agent: Mozilla/5.0 (X11; U; Linux"
    b" i686; ko-KR; rv:1.7.12) Gecko/20051007 Debian/1.7.12-1\r\nAccept: text/xml,"
    b"application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,"
    b"*/*;q=0.5\r\nAccept-Language: ko,en-us;q=0.7,en;q=0.3\r\nAccept-Encoding: gzip,"
    b"deflate\r\nAccept-Charset: EUC-KR,utf-8;q=0.7,*;q=0.7\r\nKeep-Alive: 300\r\n"
    b"Connection: keep-alive\r\n\r\n"
)
SCTP_DATA_DPKT = (
    bytes.fromhex("80440050d26ac1e570e55b4c000301a32b2d7eb20000000000000000") + HTTP_GET + b"\0"
).hex()
SCTP_MALFORMED_DPKT = "270fe1c3c2734d324f54278c0b00000400000000000000000000"

# Cases with a zero-length chunk, which dpkt 1.9.6 never finishes reading.
ZERO_LENGTH = {
    "sctp_dpkt_malformed",
    "sctp_zero_length_first",
    "sctp_overlapping_data",
    "ip_sctp_zero_length",
    "ip6_sctp_zero_length",
    "built_zero_length",
}


def ip4(p, body):
    head = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, p, 0, bytes(4), bytes(4))
    return head + body


def ip6(nxt, body):
    return struct.pack(">IHBB16s16s", 0x60000000, len(body), nxt, 64, bytes(16), bytes(16)) + body


def sctp(chunks, sport=5000, dport=80, vtag=7, checksum=0):
    return struct.pack(">HHII", sport, dport, vtag, checksum) + chunks


def chunk(kind, length, body=b"", flags=0):
    return struct.pack(">BBH", kind, flags, length) + body


def ospf(body=b"", version=2, kind=1, checksum=0):
    head = struct.pack(">BBHIIHH8s", version, kind, 24 + len(body), 0x0A000001, 0, checksum, 0, b"")
    return head + body


def cases():
    """(target, hex) by name."""
    found = {
        "sctp_dpkt_init": ("sctp", bytes.fromhex(SCTP_INIT_DPKT)),
        "sctp_dpkt_data": ("sctp", bytes.fromhex(SCTP_DATA_DPKT)),
        "sctp_dpkt_malformed": ("sctp", bytes.fromhex(SCTP_MALFORMED_DPKT)),
        "sctp_header_only": ("sctp", sctp(b"")),
        "sctp_two_chunks": ("sctp", sctp(chunk(4, 8, b"beat") + chunk(11, 4))),
        "sctp_data_padding": ("sctp", sctp(chunk(0, 5, b"x\0\0\0") + chunk(14, 4))),
        "sctp_data_padding_cut": ("sctp", sctp(chunk(0, 6, b"xy\0"))),
        "sctp_length_beyond": ("sctp", sctp(chunk(1, 40, b"short"))),
        "sctp_length_one": ("sctp", sctp(chunk(11, 1, b"abcdefg"))),
        "sctp_length_two_data": ("sctp", sctp(chunk(0, 2, b"abcdefgh"))),
        "sctp_length_three_end": ("sctp", sctp(chunk(9, 3, b"z"))),
        "sctp_zero_length_first": ("sctp", sctp(chunk(1, 0, b"rest of it"))),
        "sctp_overlapping_data": ("sctp", sctp(b"\x00\x02" * 10 + bytes(4))),
        "sctp_short_chunk": ("sctp", sctp(chunk(11, 4) + b"\x0b\x00")),
        "sctp_short_header": ("sctp", b"\x00\x50\x00\x50\x00"),
        "sctp_empty": ("sctp", b""),
        "ospf_hello": ("ospf", ospf(bytes.fromhex("ffffff00000a0201000000280000000000000000"))),
        "ospf_header_only": ("ospf", ospf()),
        "ospf_v3_sum": ("ospf", ospf(b"lsa", version=3, kind=4, checksum=0x1234)),
        "ospf_short": ("ospf", b"\x02\x01\x00\x18\x0a"),
        "ip_sctp": ("ip", ip4(132, bytes.fromhex(SCTP_INIT_DPKT))),
        "ip_sctp_short_chunk": ("ip", ip4(132, sctp(b"\x01\x00"))),
        "ip_sctp_zero_length": ("ip", ip4(132, sctp(chunk(0, 0, b"pad!")))),
        "ip_ospf": ("ip", ip4(89, ospf(b"hello"))),
        "ip_ospf_short": ("ip", ip4(89, b"\x02\x01")),
        "ip6_sctp": ("ip6", ip6(132, sctp(chunk(0, 7, b"abc\0")))),
        "ip6_sctp_zero_length": ("ip6", ip6(132, sctp(chunk(3, 0)))),
        "ip6_ospf": ("ip6", ip6(89, ospf(version=3))),
    }
    return {k: (t, v.hex()) for k, (t, v) in found.items()}


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
    for name in ("data", "type", "len", "flags"):
        found["attr_" + name] = attempt(lambda name=name: repr(getattr(packet, name)))
    chunks = getattr(packet, "chunks", None)
    if isinstance(chunks, list):
        found["chunks"] = [snapshot(c) for c in chunks]
    data = getattr(packet, "data", None)
    if data is not None and not isinstance(data, (bytes, bytearray, str)):
        found["data"] = snapshot(data)
    return found


def constructed(package, skip):
    sctp_m, ospf_m, crc = package.sctp, package.ospf, package.crc32c
    ipm, ip6m = package.ip, package.ip6

    def refreshed():
        packet = sctp_m.SCTP(bytes.fromhex(SCTP_INIT_DPKT))
        packet.sum = 0
        first = bytes(packet).hex()
        packet.chunks[0].data = b"changed"
        packet.sum = 0
        return [first, bytes(packet).hex(), len(packet)]

    def lazy_data_mutation():
        packet = sctp_m.SCTP(sctp(chunk(11, 1, b"abcdefg")))
        first = packet.chunks[1]
        first.data = b"set"
        return [repr(first), bytes(packet).hex(), [repr(c.data) for c in packet.chunks]]

    def bytearray_parse():
        packet = sctp_m.SCTP(bytearray(sctp(chunk(0, 5, b"x\1\2\3") + chunk(11, 4))))
        return [repr(packet.data)] + [[repr(c.data), repr(c.padding)] for c in packet.chunks]

    found = {
        "default_sctp": attempt(lambda: snapshot(sctp_m.SCTP())),
        "default_chunk": attempt(lambda: snapshot(sctp_m.Chunk())),
        "default_ospf": attempt(lambda: snapshot(ospf_m.OSPF())),
        "sctp_keywords": attempt(
            lambda: snapshot(
                sctp_m.SCTP(
                    sport=1,
                    dport=2,
                    vtag=3,
                    chunks=[sctp_m.Chunk(type=0, len=5, data=b"x", padding=b"\0\0\0")],
                )
            )
        ),
        "sctp_sum_kept": attempt(
            lambda: bytes(sctp_m.SCTP(sum=0x1234, chunks=[sctp_m.Chunk(len=4, padding=b"")])).hex()
        ),
        "chunk_without_padding": attempt(lambda: bytes(sctp_m.SCTP(chunks=[sctp_m.Chunk()]))),
        "sctp_refresh": attempt(refreshed),
        "lazy_data_mutation": attempt(lazy_data_mutation),
        "bytearray_parse": attempt(bytearray_parse),
        "chunk_alone": attempt(lambda: snapshot(sctp_m.Chunk(chunk(0, 6, b"ab\0\0tail")))),
        "chunk_alone_short_length": attempt(lambda: snapshot(sctp_m.Chunk(chunk(1, 2, b"abc")))),
        "chunk_short": attempt(lambda: snapshot(sctp_m.Chunk(b"\x01\x00"))),
        "ospf_keywords": attempt(
            lambda: snapshot(ospf_m.OSPF(v=2, type=1, len=24, router=1, area=2, auth=b"pw"))
        ),
        "ospf_sum_kept": attempt(lambda: bytes(ospf_m.OSPF(sum=0x1234, data=b"x")).hex()),
        "ospf_auth_constants": attempt(
            lambda: [ospf_m.AUTH_NONE == 0, ospf_m.AUTH_PASSWORD == 1, ospf_m.AUTH_CRYPTO == 2]
        ),
        "sctp_constants": attempt(
            lambda: [
                getattr(sctp_m, n)
                for n in (
                    "DATA",
                    "INIT",
                    "INIT_ACK",
                    "SACK",
                    "HEARTBEAT",
                    "HEARTBEAT_ACK",
                    "ABORT",
                    "SHUTDOWN",
                    "SHUTDOWN_ACK",
                    "ERROR",
                    "COOKIE_ECHO",
                    "COOKIE_ACK",
                    "ECNE",
                    "CWR",
                    "SHUTDOWN_COMPLETE",
                )
            ]
        ),
        "crc32c_values": attempt(
            lambda: [
                crc.cksum(b""),
                crc.cksum(b"123456789"),
                crc.cksum(bytearray(b"abc")),
                crc.cksum([1, 2, 3]),
                crc.add(2**40, b"wide"),
                crc.add(0, memoryview(b"view")),
                crc.done(-5),
                crc.done(2**33 + 7),
                len(crc.crc32c_table),
                crc.crc32c_table[:4],
                crc.crc32c_table[-1],
            ]
        ),
        "crc32c_bad_input": attempt(lambda: crc.cksum("text")),
        "ip_table": attempt(lambda: [ipm.IP.get_proto(p).__name__ for p in (89, 132)]),
        "ip6_table": attempt(lambda: [ip6m.IP6.get_proto(p).__name__ for p in (89, 132)]),
        "ip_sctp_packed": attempt(
            lambda: snapshot(
                ipm.IP(
                    p=132,
                    data=sctp_m.SCTP(sport=9, chunks=[sctp_m.Chunk(type=11, len=4, padding=b"")]),
                )
            )
        ),
        "ip6_ospf_packed": attempt(lambda: snapshot(ip6m.IP6(nxt=89, data=ospf_m.OSPF(v=3)))),
    }
    if "built_zero_length" in skip:
        found["built_zero_length"] = {"skipped": "dpkt 1.9.6 never finishes"}
    else:
        found["built_zero_length"] = attempt(
            lambda: snapshot(sctp_m.SCTP(sctp(chunk(11, 4) + chunk(0, 0, b"ab"))))
        )
    return found


def exercise(package, skip=()):
    targets = {
        "sctp": package.sctp.SCTP,
        "ospf": package.ospf.OSPF,
        "ip": package.ip.IP,
        "ip6": package.ip6.IP6,
    }
    found = {}
    for name, (t, h) in cases().items():
        if name in skip:
            found[name] = {"skipped": "dpkt 1.9.6 never finishes"}
        else:
            found[name] = attempt(lambda t=t, h=h: snapshot(targets[t](bytes.fromhex(h))))
    return {"cases": found, "constructed": constructed(package, skip)}


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for member in ("sctp", "ospf", "crc32c", "ip", "ip6"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified OSPF or SCTP module origin",
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
        skip = ZERO_LENGTH if (args.module, args.version) == ("dpkt", "1.9.6") else ()
        print(json.dumps(exercise(provenance(args.module, args.version), skip)))
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
        C.require(not wrong, "OSPF or SCTP mismatch " + module + v + ": " + ", ".join(wrong))
    print(
        json.dumps(
            {
                "cases": len(cases()),
                "observations": len(reference),
                "providers": len(providers),
                "dpkt_196_differs_on": sorted(
                    k for k in reference if reports[0].get(k) != reference[k]
                ),
                "not_run_on_196": sorted(ZERO_LENGTH),
                "declared_differences": sorted(DECLARED),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
