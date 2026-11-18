"""PPP and PPPoE frames run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same frames, alone and inside Ethernet, builds them
from keywords and packs them again. OctetRail must match dpkt 1.9.8 on every
observation except the declared ones; the keys where 1.9.6 differs are listed.
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


def ip4(body=b"in"):
    head = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, 59, 0, bytes(4), bytes(4)
    )
    return head + body


# An IPv6 packet whose next header is 44 after a hop-by-hop header. dpkt
# raises AttributeError reading frag_off; OctetRail raises FragmentOffsetError.
FRAGMENT_AFTER_HOP = (
    "60a88eafed7c2cd342833d6b185bb7750a0b156555f240768256cc6baaf550e5a934aa38ee62"
    "788300095a037d157de89a0e24e32ec11225ebbdb2fe0c7b9393d72dfd9482decfa83f"
)


def ip4_p(p, body):
    head = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, p, 0, bytes(4), bytes(4))
    return head + body


def ip6(body=b"v6"):
    return struct.pack(">IHBB16s16s", 0x60000000, len(body), 59, 64, bytes(16), bytes(16)) + body


def pppoe(code, body, session=0x11, v_type=0x11):
    return struct.pack(">BBHH", v_type, code, session, len(body)) + body


def eth(kind, body):
    return b"\x02" * 6 + b"\x04" * 6 + struct.pack(">H", kind) + body


def cases():
    """(target, hex) by name."""
    found = {
        "ppp_ip": ("ppp", b"\xff\x03\x21" + ip4()),
        "ppp_ip_two_byte": ("ppp", b"\xff\x03\x00\x21" + ip4()),
        "ppp_ip6": ("ppp", b"\xff\x03\x57" + ip6()),
        "ppp_ip6_two_byte": ("ppp", b"\xff\x03\x00\x57" + ip6()),
        "ppp_ip_short": ("ppp", b"\xff\x03\x21\x45\x00"),
        "ppp_ip_bad_ihl": ("ppp", b"\xff\x03\x21\x41" + bytes(19)),
        "ppp_lcp": ("ppp", b"\xff\x03\xc0\x21\x01\x01\x00\x04"),
        "ppp_odd_unknown": ("ppp", b"\xff\x03\xc1rest"),
        "ppp_two_byte_cut": ("ppp", b"\xff\x03\x00"),
        "ppp_short": ("ppp", b"\xff\x03"),
        "ppp_empty": ("ppp", b""),
        "pppoe_session_ip": ("pppoe", pppoe(0, b"\x00\x21" + ip4())),
        "pppoe_session_compressed": ("pppoe", pppoe(0, b"\x21" + ip4())),
        "pppoe_session_ip6": ("pppoe", pppoe(0, b"\x00\x57" + ip6())),
        "pppoe_session_lcp": ("pppoe", pppoe(0, b"\xc0\x21\x09\x01\x00\x04")),
        "pppoe_session_empty": ("pppoe", pppoe(0, b"")),
        "pppoe_session_cut": ("pppoe", pppoe(0, b"\x00")),
        "pppoe_padi": ("pppoe", pppoe(9, b"\x01\x01\x00\x00", session=0)),
        "pppoe_padt": ("pppoe", pppoe(0xA7, b"", session=0x1234)),
        "pppoe_version_bits": ("pppoe", pppoe(0, b"\x21" + ip4(), v_type=0x23)),
        "pppoe_short": ("pppoe", b"\x11\x00\x00"),
        "eth_pppoe_session": ("eth", eth(0x8864, pppoe(0, b"\x00\x21" + ip4()))),
        "eth_pppoe_discovery": ("eth", eth(0x8863, pppoe(9, b"\x01\x01\x00\x00", session=0))),
        "eth_pppoe_short": ("eth", eth(0x8864, b"\x11")),
        "eth_ppp": ("eth", eth(0x880B, b"\xff\x03\x00\x21" + ip4())),
        "eth_ppp_cut": ("eth", eth(0x880B, b"\xff\x03\x00")),
    }
    inner = bytes.fromhex(FRAGMENT_AFTER_HOP)
    found.update(
        {
            "ppp_fragment_after_hop": ("ppp", b"\xff\x03\x00\x57" + inner),
            "ppp_fragment_after_hop_compressed": ("ppp", b"\xff\x03\x57" + inner),
            "ppp_ip_fragment_after_hop": ("ppp", b"\xff\x03\x21" + ip4_p(41, inner)),
            "pppoe_fragment_after_hop": ("pppoe", pppoe(0, b"\x00\x57" + inner)),
            "pppoe_fragment_after_hop_compressed": ("pppoe", pppoe(0, b"\x57" + inner)),
            "eth_pppoe_fragment_after_hop": ("eth", eth(0x8864, pppoe(0, b"\x00\x57" + inner))),
            "eth_ppp_fragment_after_hop": ("eth", eth(0x880B, b"\xff\x03\x00\x57" + inner)),
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
    found["p"] = attempt(lambda: repr(getattr(packet, "p", None)))
    data = getattr(packet, "data", None)
    if data is not None and not isinstance(data, (bytes, bytearray, str)):
        found["data"] = snapshot(data)
    return found


def constructed(package):
    ppp_m, pppoe_m, eth_m = package.ppp, package.pppoe, package.ethernet

    def bits():
        packet = pppoe_m.PPPoE()
        found = [packet.v, packet.type]
        packet.v, packet.type = 2, 3
        found += [packet.v, packet.type, bytes(packet).hex()]
        return found

    def table():
        found = [ppp_m.PPP.get_p(p).__name__ for p in (0x21, 0x57)]
        found.append(attempt(lambda: ppp_m.PPP.get_p(0xC021)))
        found.append(pppoe_m.PPP._protosw is ppp_m.PPP._protosw)
        return found

    def ethernet_types():
        return [
            attempt(lambda t=t: eth_m.Ethernet.get_type(t).__name__)
            for t in (0x880B, 0x8863, 0x8864)
        ]

    return {
        "default_ppp": attempt(lambda: snapshot(ppp_m.PPP())),
        "default_pppoe": attempt(lambda: snapshot(pppoe_m.PPPoE())),
        "default_pppoe_ppp": attempt(lambda: snapshot(pppoe_m.PPP())),
        "ppp_two_byte_packed": attempt(lambda: snapshot(ppp_m.PPP(p=0xC021, data=b"lcp"))),
        "ppp_too_wide": attempt(lambda: bytes(ppp_m.PPP(p=0x10000))),
        "ppp_bad_type": attempt(lambda: bytes(ppp_m.PPP(p="x"))),
        "pppoe_ppp_two_byte": attempt(lambda: snapshot(pppoe_m.PPP(p=0x0057, data=b"v6"))),
        "pppoe_ppp_too_wide": attempt(lambda: bytes(pppoe_m.PPP(p=0x10000))),
        "pppoe_layer_data": attempt(
            lambda: snapshot(pppoe_m.PPPoE(len=3, data=pppoe_m.PPP(p=0x21, data=b"ip")))
        ),
        "eth_pppoe_packed": attempt(
            lambda: snapshot(eth_m.Ethernet(type=0x8864, data=pppoe_m.PPPoE(data=b"x")))
        ),
        "bits": attempt(bits),
        "table": attempt(table),
        "ethernet_types": attempt(ethernet_types),
        "constants": attempt(
            lambda: [
                ppp_m.PPP_IP,
                ppp_m.PPP_IP6,
                ppp_m.PFC_BIT,
                pppoe_m.PPPoE_PADI,
                pppoe_m.PPPoE_PADO,
                pppoe_m.PPPoE_PADR,
                pppoe_m.PPPoE_PADS,
                pppoe_m.PPPoE_PADT,
                pppoe_m.PPPoE_SESSION,
            ]
        ),
    }


def exercise(package):
    targets = {
        "ppp": package.ppp.PPP,
        "pppoe": package.pppoe.PPPoE,
        "eth": package.ethernet.Ethernet,
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
    for member in ("ppp", "pppoe", "ethernet"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified PPP or PPPoE module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose.
def _kept_as_bytes(path):
    """dpkt raises AttributeError; OctetRail keeps the IPv6 bytes at the end of path.

    The last layer must hold every byte of the inner IPv6 packet, so a lost or
    cut payload fails, not only a payload that is not bytes.
    """
    kept = "data=" + repr(bytes.fromhex(FRAGMENT_AFTER_HOP)) + ")"

    def check(found):
        layer = found
        for i, cls in enumerate(path):
            if not isinstance(layer, dict) or layer.get("class") != cls:
                return False
            if i < len(path) - 1:
                layer = layer.get("data")
        return "data" not in layer and layer.get("repr", "").endswith(kept)

    return check


DECLARED = {
    "cases." + name: _kept_as_bytes(path)
    for name, path in (
        ("ppp_fragment_after_hop", ("PPP",)),
        ("ppp_fragment_after_hop_compressed", ("PPP",)),
        ("ppp_ip_fragment_after_hop", ("PPP", "IP")),
        ("pppoe_fragment_after_hop", ("PPPoE", "PPP")),
        ("pppoe_fragment_after_hop_compressed", ("PPPoE", "PPP")),
        ("eth_pppoe_fragment_after_hop", ("Ethernet", "PPPoE", "PPP")),
        ("eth_ppp_fragment_after_hop", ("Ethernet", "PPP")),
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
        C.require(not wrong, "PPP or PPPoE mismatch " + module + v + ": " + ", ".join(wrong))
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
