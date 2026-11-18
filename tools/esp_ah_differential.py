"""AH and ESP packets run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same packets, alone and inside IPv4 and IPv6,
including dpkt's own test vectors, builds them from keywords and packs them
again. OctetRail must match dpkt 1.9.8 on every observation except the
declared ones; the keys where 1.9.6 differs are listed.
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

# dpkt's AH test vectors: an IPv4 datagram after the header, and the same
# bytes after an unregistered next header.
AH_IP_DPKT = (
    "04" + "00" * 11 + "4500002200000000401172c00102030401020304006f00de000ebf35666f6f626172"
)
AH_NOT_IP_DPKT = "37" + AH_IP_DPKT[2:]


# An AH header carrying IPv6 (next header 41) whose hop-by-hop header is
# followed by next header 44 with a nonzero offset.
FRAGMENT_AFTER_HOP = (
    "2902e20ac1c476ab142a900fc0d2cb7160a88eafed7c2cd342833d6b185bb7750a0b156555f240768256cc6b"
    "aaf550e5a934aa38ee62788300095a037d157de89a0e24e32ec11225ebbdb2fe0c7b9393d72dfd9482decfa83f"
)


def ip4(p, body):
    head = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, p, 0, bytes(4), bytes(4))
    return head + body


def ip6(nxt, body):
    return struct.pack(">IHBB16s16s", 0x60000000, len(body), nxt, 64, bytes(16), bytes(16)) + body


def ah(nxt, words, auth=b"", body=b"", spi=0x100, seq=1):
    return struct.pack(">BBHII", nxt, words, 0, spi, seq) + auth + body


def esp(body=b"", spi=0x200, seq=2):
    return struct.pack(">II", spi, seq) + body


def udp(body=b"u"):
    return struct.pack(">HHHH", 53, 53, 8 + len(body), 0) + body


def tcp(body=b""):
    return struct.pack(">HHIIBBHHH", 80, 81, 1, 0, 0x50, 0x18, 512, 0, 0) + body


def cases():
    """(target, hex) by name."""
    found = {
        "ah_dpkt_ip": ("ah", bytes.fromhex(AH_IP_DPKT)),
        "ah_dpkt_not_ip": ("ah", bytes.fromhex(AH_NOT_IP_DPKT)),
        "ah_words_zero": ("ah", ah(59, 0, body=b"rest")),
        "ah_words_one": ("ah", ah(59, 1, body=b"rest")),
        "ah_words_four": ("ah", ah(17, 4, b"icv-twelve!!", udp())),
        "ah_auth_cut": ("ah", ah(6, 9, b"short")),
        "ah_tcp": ("ah", ah(6, 1, body=tcp(b"seg"))),
        "ah_tcp_short": ("ah", ah(6, 1, body=b"\x00\x50")),
        "ah_esp": ("ah", ah(50, 2, b"icv!", esp(b"cipher"))),
        "ah_ah_ip": ("ah", ah(51, 1, body=ah(4, 2, b"icv!", ip4(59, b"in")))),
        "ah_ipv6": ("ah", ah(41, 1, body=ip6(59, b"v6"))),
        "ah_ipv6_short": ("ah", ah(41, 1, body=b"\x60\x00")),
        "ah_short": ("ah", b"\x04\x00\x00\x00\x00"),
        "ah_empty": ("ah", b""),
        "ah_fragment_after_hop": ("ah", bytes.fromhex(FRAGMENT_AFTER_HOP)),
        "ip_ah_fragment_after_hop": ("ip", ip4(51, bytes.fromhex(FRAGMENT_AFTER_HOP))),
        "ip6_ah_fragment_after_hop": ("ip6", ip6(51, bytes.fromhex(FRAGMENT_AFTER_HOP))),
        "esp_plain": ("esp", esp(b"encrypted payload")),
        "esp_header_only": ("esp", esp()),
        "esp_short": ("esp", b"\x00\x00\x01"),
        "ip_ah": ("ip", ip4(51, ah(17, 2, b"icv!", udp()))),
        "ip_ah_short": ("ip", ip4(51, b"\x11\x00")),
        "ip_esp": ("ip", ip4(50, esp(b"secret"))),
        "ip_esp_short": ("ip", ip4(50, b"\x00\x01")),
        "ip6_ah": ("ip6", ip6(51, ah(17, 1, body=udp()))),
        "ip6_esp": ("ip6", ip6(50, esp(b"secret"))),
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
    found["auth"] = attempt(lambda: repr(getattr(packet, "auth", None)))
    data = getattr(packet, "data", None)
    if data is not None and not isinstance(data, (bytes, bytearray, str)):
        found["data"] = snapshot(data)
    return found


def constructed(package):
    ah_m, esp_m, ipm, ip6m = package.ah, package.esp, package.ip, package.ip6

    def mutated():
        packet = ah_m.AH(bytes.fromhex(AH_IP_DPKT))
        packet.data.ttl = 1
        packet.data.sum = 0
        return [bytes(packet).hex(), len(packet), repr(packet.ip)]

    def bytearray_parse():
        packet = ah_m.AH(bytearray(ah(59, 2, b"icv!", b"tail")))
        return [repr(packet.auth), repr(packet.data)]

    return {
        "default_ah": attempt(lambda: snapshot(ah_m.AH())),
        "default_esp": attempt(lambda: snapshot(esp_m.ESP())),
        "ah_class_auth": attempt(lambda: repr(ah_m.AH.auth)),
        "ah_keywords": attempt(
            lambda: snapshot(ah_m.AH(nxt=17, len=2, spi=5, seq=6, auth=b"icv!", data=b"x"))
        ),
        "ah_layer_data": attempt(
            lambda: snapshot(ah_m.AH(nxt=4, len=1, data=ipm.IP(p=59, data=b"in")))
        ),
        "ah_mutated": attempt(mutated),
        "bytearray_parse": attempt(bytearray_parse),
        "esp_keywords": attempt(lambda: snapshot(esp_m.ESP(spi=1, seq=2, data=b"cipher"))),
        "ip_ah_packed": attempt(
            lambda: snapshot(ipm.IP(p=51, data=ah_m.AH(nxt=59, len=1, data=b"z")))
        ),
        "ip_esp_packed": attempt(lambda: snapshot(ipm.IP(p=50, data=esp_m.ESP(spi=9)))),
        "ip_table": attempt(lambda: [ipm.IP.get_proto(p).__name__ for p in (50, 51)]),
        "ip6_table": attempt(lambda: [ip6m.IP6.get_proto(p).__name__ for p in (50, 51)]),
        "ip6_ah_packed": attempt(
            lambda: snapshot(ip6m.IP6(nxt=59, data=ah_m.AH(nxt=59, data=b"a")))
        ),
    }


def exercise(package):
    targets = {
        "ah": package.ah.AH,
        "esp": package.esp.ESP,
        "ip": package.ip.IP,
        "ip6": package.ip6.IP6,
    }
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
    for member in ("ah", "esp", "ip", "ip6"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified AH or ESP module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


def _kept_as_bytes(cls, wire, depth):
    """The outcome OctetRail declares: `cls` parses (an AH repacks to `wire`),
    and the layer `depth` levels down keeps the inner IPv6 packet as bytes.
    That layer must hold every byte of the inner packet, the part of the AH
    header after its 16 bytes, so a lost or cut payload fails."""
    kept = "data=" + repr(bytes.fromhex(FRAGMENT_AFTER_HOP)[16:]) + ")"

    def check(found):
        layer = found
        for _ in range(depth):
            layer = layer.get("data", {})
        return (
            found.get("class") == cls
            and (cls != "AH" or found.get("bytes") == wire.hex())
            and layer.get("class") in ("AH", "IP6")
            and "data" not in layer
            and layer.get("repr", "").endswith(kept)
        )

    return check


# Observations where OctetRail differs from 1.9.8 on purpose. When an AH header
# carries IPv6 whose next header is 44 after a header that is not a fragment
# header, dpkt raises AttributeError out of AH, and out of the IPv4 or IPv6
# packet around it. OctetRail raises FragmentOffsetError, an UnpackError, for
# the inner packet, so AH keeps it as bytes, as IP and ICMP6 do.
DECLARED = {
    "cases." + name: _kept_as_bytes(cls, raw, depth)
    for name, cls, raw, depth in (
        ("ah_fragment_after_hop", "AH", bytes.fromhex(FRAGMENT_AFTER_HOP), 0),
        ("ip_ah_fragment_after_hop", "IP", ip4(51, bytes.fromhex(FRAGMENT_AFTER_HOP)), 1),
        ("ip6_ah_fragment_after_hop", "IP6", ip6(51, bytes.fromhex(FRAGMENT_AFTER_HOP)), 0),
    )
}


def _matches(key, found, reference):
    expected = DECLARED.get(key, reference.get(key))
    return expected(found) if callable(expected) else found == expected


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
        wrong = sorted(k for k in reference if not _matches(k, report.get(k), reference))
        C.require(not wrong, "AH or ESP mismatch " + module + v + ": " + ", ".join(wrong))
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
