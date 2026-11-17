"""SLL, SLL2 and loopback headers run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same captured link-layer headers, including dpkt's
own test vectors, builds them from keywords and packs them again. OctetRail
must match dpkt 1.9.8 on every observation except the declared ones; the keys
where 1.9.6 differs are listed. The loopback family is in the byte order of the
machine, as in dpkt, so both byte orders are tried.
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

# dpkt's test vectors.
SLL_DPKT = "000000010006000bdb520e08f67f080045000034cc6c40004006740882d9fa8e82d9fa0d"
SLL_UNKNOWN_DPKT = "000000010006000bdb520e08f67f123445000034cc6c40004006740882d9fa8e82d9fa0d"
SLL2_DPKT = "080000000000000300010006000bdb520e08f67f45000034cc6c40004006740882d9fa8e82d9fa0d"
SLL2_UNKNOWN_DPKT = (
    "123400000000000300010006000bdb520e08f67f45000034cc6c40004006740882d9fa8e82d9fa0d"
)
IP4_DPKT = "45000034bd04400040067fbd7f0000027f000001"
IP6_DPKT = "60000000001406382607f8b0400c0c03000000000000001a20010470e5bfdead49572174e82c4887"
ETH_DPKT = "0102030405060708090a0b0c0800"

# An IPv6 packet whose next header is 44 after a hop-by-hop header. dpkt
# raises AttributeError reading frag_off; OctetRail raises FragmentOffsetError.
FRAGMENT_AFTER_HOP = (
    "60a88eafed7c2cd342833d6b185bb7750a0b156555f240768256cc6baaf550e5a934aa38ee62"
    "788300095a037d157de89a0e24e32ec11225ebbdb2fe0c7b9393d72dfd9482decfa83f"
)


def ip4_p(p, body):
    head = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, p, 0, bytes(4), bytes(4))
    return head + body


ARP = bytes.fromhex("000108000604000102020202020200000000") + bytes(10)


def sll(ethtype, body, kind=0):
    return struct.pack(">HHH8sH", kind, 1, 6, b"\x02" * 6, ethtype) + body


def sll2(ethtype, body, kind=0, index=3):
    return struct.pack(">HHiHBB8s", ethtype, 0, index, 1, kind, 6, b"\x02" * 6) + body


def cases():
    """(target, hex) by name."""
    ip4 = bytes.fromhex(IP4_DPKT)
    ip6 = bytes.fromhex(IP6_DPKT)
    found = {
        "sll_dpkt": ("sll", bytes.fromhex(SLL_DPKT)),
        "sll_dpkt_unknown": ("sll", bytes.fromhex(SLL_UNKNOWN_DPKT)),
        "sll_ipv6": ("sll", sll(0x86DD, ip6, kind=4)),
        "sll_arp": ("sll", sll(0x0806, ARP, kind=1)),
        "sll_ip_short": ("sll", sll(0x0800, b"\x45\x00")),
        "sll_header_only": ("sll", sll(0x0800, b"")),
        "sll_short": ("sll", b"\x00\x00\x00\x01"),
        "sll2_dpkt": ("sll2", bytes.fromhex(SLL2_DPKT)),
        "sll2_dpkt_unknown": ("sll2", bytes.fromhex(SLL2_UNKNOWN_DPKT)),
        "sll2_ipv6": ("sll2", sll2(0x86DD, ip6, kind=2)),
        "sll2_negative_index": ("sll2", sll2(0x0806, ARP, index=-1)),
        "sll2_ip_short": ("sll2", sll2(0x0800, b"\x45")),
        "sll2_short": ("sll2", b"\x08\x00\x00\x00"),
        "loop_ip_little": ("loop", b"\x02\x00\x00\x00" + ip4),
        "loop_ip_big": ("loop", b"\x00\x00\x00\x02" + ip4),
        "loop_ip6_24": ("loop", b"\x18\x00\x00\x00" + ip6),
        "loop_ip6_28_big": ("loop", b"\x00\x00\x00\x1c" + ip6),
        "loop_ip6_30": ("loop", b"\x1e\x00\x00\x00" + ip6),
        "loop_ethernet": ("loop", b"\x00\x00\x00\x00" + bytes.fromhex(ETH_DPKT)),
        "loop_ip_short": ("loop", b"\x02\x00\x00\x00\x45\x00"),
        "loop_ethernet_short": ("loop", b"\x07\x00\x00\x00\x01\x02"),
        "loop_short": ("loop", b"\x02\x00"),
    }
    inner = bytes.fromhex(FRAGMENT_AFTER_HOP)
    found.update(
        {
            "sll_fragment_after_hop": ("sll", sll(0x86DD, inner)),
            "sll_ip_fragment_after_hop": ("sll", sll(0x0800, ip4_p(41, inner))),
            "sll2_fragment_after_hop": ("sll2", sll2(0x86DD, inner)),
            "loop_fragment_after_hop": ("loop", b"\x18\x00\x00\x00" + inner),
            "loop_ip_fragment_after_hop": ("loop", b"\x02\x00\x00\x00" + ip4_p(41, inner)),
            "loop_ethernet_fragment_after_hop": (
                "loop",
                b"\x00\x00\x00\x00" + bytes.fromhex(ETH_DPKT)[:12] + b"\x86\xdd" + inner,
            ),
        }
    )
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
    data = getattr(packet, "data", None)
    if data is not None and not isinstance(data, (bytes, bytearray, str)):
        found["data"] = snapshot(data)
    return found


def constructed(package):
    sll_m, sll2_m, loop_m = package.sll, package.sll2, package.loopback
    ipm, eth_m = package.ip, package.ethernet

    return {
        "default_sll": attempt(lambda: snapshot(sll_m.SLL())),
        "default_sll2": attempt(lambda: snapshot(sll2_m.SLL2())),
        "default_loopback": attempt(lambda: snapshot(loop_m.Loopback())),
        "sll_layer_data": attempt(
            lambda: snapshot(sll_m.SLL(type=4, hdr=b"\x02" * 6, data=ipm.IP(p=59)))
        ),
        "sll2_layer_data": attempt(lambda: snapshot(sll2_m.SLL2(intindex=-5, data=ipm.IP(p=59)))),
        "sll2_index_too_wide": attempt(lambda: bytes(sll2_m.SLL2(intindex=2**31))),
        "loopback_ip": attempt(lambda: snapshot(loop_m.Loopback(family=2, data=ipm.IP(p=59)))),
        "loopback_ethernet": attempt(
            lambda: snapshot(loop_m.Loopback(family=7, data=eth_m.Ethernet()))
        ),
        "loopback_layout": attempt(
            lambda: [loop_m.Loopback.__hdr_fmt__, loop_m.Loopback.__hdr_len__]
        ),
        "shared_table": attempt(
            lambda: [
                sll_m.SLL._typesw is eth_m.Ethernet._typesw,
                sll2_m.SLL2._typesw is eth_m.Ethernet._typesw,
            ]
        ),
    }


def exercise(package):
    targets = {
        "sll": package.sll.SLL,
        "sll2": package.sll2.SLL2,
        "loop": package.loopback.Loopback,
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
    for member in ("sll", "sll2", "loopback", "ip", "ethernet"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified SLL or loopback module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose.
def _kept_as_bytes(path):
    """dpkt raises AttributeError; OctetRail keeps the IPv6 bytes at the end of path."""

    def check(found):
        layer = found
        for i, cls in enumerate(path):
            if not isinstance(layer, dict) or layer.get("class") != cls:
                return False
            if i < len(path) - 1:
                layer = layer.get("data")
        return "data" not in layer

    return check


DECLARED = {
    "cases." + name: _kept_as_bytes(path)
    for name, path in (
        ("sll_fragment_after_hop", ("SLL",)),
        ("sll_ip_fragment_after_hop", ("SLL", "IP")),
        ("sll2_fragment_after_hop", ("SLL2",)),
        ("loop_ip_fragment_after_hop", ("Loopback", "IP")),
        ("loop_ethernet_fragment_after_hop", ("Loopback", "Ethernet")),
    )
}
# Loopback decodes IPv6 without a try, so the error escapes, as in dpkt. It is
# FragmentOffsetError, which subclasses AttributeError, with dpkt's message.
DECLARED["cases.loop_fragment_after_hop"] = {
    "error": "FragmentOffsetError",
    "message": "'IP6HopOptsHeader' object has no attribute 'frag_off'",
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
        C.require(not wrong, "SLL or loopback mismatch " + module + v + ": " + ", ".join(wrong))
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
