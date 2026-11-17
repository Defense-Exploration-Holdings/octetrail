"""ARP messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same messages, alone and inside Ethernet II, 802.1Q
and LLC/SNAP frames, builds them from keywords and packs them again. OctetRail
must match dpkt 1.9.8 on every observation except the declared ones; the keys
where 1.9.6 differs are listed.
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

MAC = bytes.fromhex("02aabbccddee")
PEER = bytes.fromhex("021122334455")


def arp(op=1, hrd=1, hln=6, pln=4, sha=MAC, tha=bytes(6)):
    return (
        struct.pack(">HHBBH", hrd, 0x0800, hln, pln, op) + sha + b"\x0a\0\0\1" + tha + b"\x0a\0\0\2"
    )


def frame(kind, body):
    return b"\xff" * 6 + MAC + struct.pack(">H", kind) + body


def cases():
    """(target, hex) by name."""
    snap = b"\xaa\xaa\x03\x00\x00\x00\x08\x06" + arp()
    found = {
        "request": ("arp", arp()),
        "reply_with_padding": ("arp", arp(op=2, tha=PEER) + bytes(18)),
        "ieee802_long_lengths": ("arp", arp(hrd=6, hln=8, pln=16)),
        "short": ("arp", arp()[:27]),
        "header_only": ("arp", arp()[:8]),
        "ethernet": ("ethernet", frame(0x0806, arp())),
        "ethernet_padded": ("ethernet", frame(0x0806, arp(op=2, tha=PEER) + bytes(18))),
        "ethernet_short": ("ethernet", frame(0x0806, arp()[:20])),
        "vlan": ("ethernet", frame(0x8100, b"\x00\x05\x08\x06" + arp())),
        "llc_snap": ("ethernet", frame(len(snap), snap)),
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
    data = getattr(packet, "data", None)
    if data is not None and not isinstance(data, (bytes, str)):
        found["data"] = snapshot(data)
    return found


def constructed(package):
    arp_m, eth = package.arp, package.ethernet
    return {
        "default": attempt(lambda: snapshot(arp_m.ARP())),
        "keywords": attempt(lambda: snapshot(arp_m.ARP(op=2, sha=MAC, tha=PEER))),
        "ethernet_type_from_data": attempt(
            lambda: snapshot(eth.Ethernet(src=MAC, data=arp_m.ARP()))
        ),
        "ethernet_keyword_bytes": attempt(lambda: snapshot(eth.Ethernet(type=0x0806, data=arp()))),
        "type_table": attempt(
            lambda: [eth.Ethernet.get_type(0x0806).__name__, eth.Ethernet.get_type_rev(arp_m.ARP)]
        ),
        "constants": attempt(
            lambda: [
                arp_m.ARP_HRD_ETH,
                arp_m.ARP_HRD_IEEE802,
                arp_m.ARP_PRO_IP,
                arp_m.ARP_OP_REQUEST,
                arp_m.ARP_OP_REPLY,
                arp_m.ARP_OP_REVREQUEST,
                arp_m.ARP_OP_REVREPLY,
            ]
        ),
    }


def exercise(package):
    targets = {"arp": package.arp.ARP, "ethernet": package.ethernet.Ethernet}
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
    for member in ("arp", "ethernet"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified ARP module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# No declared differences: ARP raises only dpkt's own errors.
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
        C.require(not wrong, "ARP mismatch " + module + v + ": " + ", ".join(wrong))
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
