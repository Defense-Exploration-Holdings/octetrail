"""Deeply nested packets run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses chains of IPv4 in IPv4, IPv6 in IPv4, AH and GRE headers,
alone and inside Ethernet and PPPoE, at depths that decode and at depths past
the Python recursion limit, and packs what it decodes again. OctetRail must match dpkt 1.9.8 on every
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


SRC4, DST4 = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
SRC6, DST6 = bytes(15) + b"\x01", bytes(15) + b"\x02"


def ip4(p, payload):
    return (
        struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(payload), 0, 0, 64, p, 0) + SRC4 + DST4 + payload
    )


def ip6(nxt, payload):
    return struct.pack(">IHBB", 0x60000000, len(payload), nxt, 64) + SRC6 + DST6 + payload


def ah(nxt, payload):
    return struct.pack(">BBHII", nxt, 4, 0, 1, 1) + bytes(12) + payload


def gre(payload):
    return b"\x00\x00\x08\x00" + payload


def pppoe(payload):
    # PPPoE session data carrying PPP with IPv4.
    return struct.pack(">BBHH", 0x11, 0, 1, 2 + len(payload)) + b"\x00\x21" + payload


def ether(t, payload):
    return b"\x02" * 6 + b"\x04" * 6 + struct.pack(">H", t) + payload


def chain(kind, depth):
    """(outer class, bytes) for a chain of depth nested headers."""
    data = b"payload!"
    for _ in range(depth):
        if kind == "ipip":
            data = ip4(4, data)
        elif kind == "ip6_in_ip":
            data = ip4(41, ip6(4, data))
        elif kind == "ip_in_ip6":
            data = ip6(4, ip4(41, data))
        elif kind == "ah":
            data = ah(51, data)
        elif kind == "gre":
            data = ip4(47, gre(data))
        elif kind == "pppoe":
            data = ip4(4, data)
    if kind == "ah":
        return "IP", ip4(51, data)
    if kind == "ip_in_ip6":
        return "IP6", data
    if kind == "pppoe":
        # IPv4 in IPv4 inside PPPoE, whose PPP decoder keeps bytes on an
        # UnpackError.
        return "Ethernet", ether(0x8864, pppoe(data))
    return "IP", data


# Depths that decode on every supported Python version, and one past the
# recursion limit on all of them. Depths near the limit are left out: where it
# falls depends on the interpreter, for dpkt as for OctetRail.
DEPTHS = {
    "ipip": (1, 10, 100, 2000),
    "ip6_in_ip": (1, 10, 100, 1000),
    "ip_in_ip6": (1, 10, 100, 1000),
    "ah": (1, 10, 100, 1500),
    "gre": (1, 10, 100, 1500),
    "pppoe": (1, 10, 100, 2000),
}


def cases():
    """(class, hex) by name."""
    found = {}
    for kind, depths in DEPTHS.items():
        for depth in depths:
            outer, raw = chain(kind, depth)
            found["%s_%04d" % (kind, depth)] = (outer, raw.hex())
            # The same chain inside Ethernet, whose payload decoder also keeps
            # bytes on an UnpackError.
            if outer == "IP":
                found["eth_%s_%04d" % (kind, depth)] = ("Ethernet", ether(0x0800, raw).hex())
    return found


def resolve(package, kind):
    return {
        "IP": package.ip.IP,
        "IP6": package.ip6.IP6,
        "Ethernet": package.ethernet.Ethernet,
    }[kind]


def attempt(action):
    try:
        return action()
    except RecursionError as error:
        # Recursion messages differ between Python versions; the class is kept.
        return {
            "error": "NestingError" if type(error).__name__ == "NestingError" else "RecursionError"
        }
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}


def walk(packet):
    """The class names down the chain and the innermost bytes, without recursion."""
    names = []
    while hasattr(packet, "__hdr__"):
        names.append(type(packet).__name__)
        packet = packet.data
    return {"layers": len(names), "classes": sorted(set(names)), "inner": bytes(packet).hex()}


def observe(cls, raw):
    packet = cls(raw)
    found = walk(packet)
    found["repack"] = attempt(lambda: bytes(packet) == raw)
    found["len"] = attempt(lambda: len(packet) == len(raw))
    return found


def exercise(package):
    return {
        "cases": {
            name: attempt(lambda k=kind, w=w: observe(resolve(package, k), bytes.fromhex(w)))
            for name, (kind, w) in cases().items()
        },
        "catch": {
            "unpack_error": attempt(lambda: catches(package, "UnpackError")),
            "recursion_error": attempt(lambda: catches(package, "RecursionError")),
        },
    }


def catches(package, name):
    """Whether an except clause for name stops a chain past the recursion limit."""
    top = importlib.import_module(package.ip.__name__.split(".")[0])
    cls = top.UnpackError if name == "UnpackError" else RecursionError
    try:
        package.ip.IP(chain("ipip", 2000)[1])
    except cls:
        return "caught"
    except RecursionError:
        return "escaped"
    return "decoded"


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".ip").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/ip.py")).resolve(),
        "unverified ip module origin",
    )
    for name in ("ethernet", "ip", "ip6", "ah", "gre", "pppoe"):
        setattr(package, name, importlib.import_module(module + "." + name))
    return package


# dpkt decodes each payload in a nested call, so a chain deeper than the
# recursion limit raises RecursionError, which no payload decoder catches.
# OctetRail raises errors.NestingError, both an UnpackError and a
# RecursionError, and it reaches the caller in the same way.
RECURSION = {"error": "RecursionError"}


def declared(key, found):
    """OctetRail's expected observation where it differs from dpkt on purpose."""
    if key == "catch.unpack_error":
        return "caught"
    return {"error": "NestingError"} if found == RECURSION else None


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
        expected = {k: declared(k, found) or found for k, found in reference.items()}
        wrong = sorted(k for k in reference if report.get(k) != expected[k])
        C.require(not wrong, "nesting mismatch " + module + v + ": " + ", ".join(wrong))
    print(
        json.dumps(
            {
                "cases": len(cases()),
                "observations": len(reference),
                "providers": len(providers),
                "dpkt_196_differs_on": sorted(
                    k for k in reference if reports[0].get(k) != reference[k]
                ),
                "declared_differences": len([k for k, f in reference.items() if declared(k, f)]),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
