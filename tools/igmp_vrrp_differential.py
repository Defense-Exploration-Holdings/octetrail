"""IGMP and VRRP messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same messages, alone and inside IPv6, including
dpkt's own test vectors, builds them from keywords and packs them again.
OctetRail must match dpkt 1.9.8 on every observation except the declared ones;
the keys where 1.9.6 differs are listed.
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

# dpkt's test_vrrp vector.
VRRP_DPKT = "210164010001ba52c0a80001" + "00" * 8


def ip6(nxt, body):
    return struct.pack(">IHBB16s16s", 0x60000000, len(body), nxt, 64, bytes(16), bytes(16)) + body


def vrrp(count, body, version=0x21, checksum=0):
    return struct.pack(">BBBBBBH", version, 7, 100, count, 1, 1, checksum) + body


def cases():
    """(target, hex) by name."""
    addrs = b"\x0a\x00\x00\x01\x0a\x00\x00\x02"
    found = {
        "igmp_query": ("igmp", b"\x11\x64\xee\x9b\x00\x00\x00\x00"),
        "igmp_report": ("igmp", b"\x16\x00\x00\x00\xe0\x00\x00\xfbtail"),
        "igmp_short": ("igmp", b"\x11\x64\x00"),
        "igmp_empty": ("igmp", b""),
        "vrrp_dpkt": ("vrrp", bytes.fromhex(VRRP_DPKT)),
        "vrrp_two": ("vrrp", vrrp(2, addrs + b"auth")),
        "vrrp_zero_count": ("vrrp", vrrp(0, b"skipauth")),
        "vrrp_short_addrs": ("vrrp", vrrp(3, addrs[:6])),
        "vrrp_header_only": ("vrrp", vrrp(1, b"")),
        "vrrp_v3": ("vrrp", vrrp(1, addrs[:4], version=0x31, checksum=0x1234)),
        "vrrp_short": ("vrrp", b"\x21\x07\x64"),
        "ip6_igmp": ("ip6", ip6(2, b"\x11\x64\x00\x00\xe0\x00\x00\x01")),
        "ip6_igmp_short": ("ip6", ip6(2, b"\x11\x64")),
        "ip6_vrrp": ("ip6", ip6(112, vrrp(2, addrs))),
        "ip6_vrrp_short": ("ip6", ip6(112, b"\x21")),
        "ip6_proto_118": ("ip6", ip6(118, bytes(35))),
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
    igmp, vrrp_m, ip6m = package.igmp, package.vrrp, package.ip6
    r = {
        "default_igmp": attempt(lambda: snapshot(igmp.IGMP())),
        "default_vrrp_repr": attempt(lambda: repr(vrrp_m.VRRP())),
        "default_vrrp_bytes": attempt(lambda: bytes(vrrp_m.VRRP()).hex()),
        "igmp_sum_kept": attempt(lambda: snapshot(igmp.IGMP(type=0x11, sum=0x1234))),
        "igmp_sum_computed": attempt(lambda: snapshot(igmp.IGMP(type=0x16, group=b"\xe0\0\0\1"))),
        "vrrp_keywords": attempt(
            lambda: snapshot(vrrp_m.VRRP(count=1, addrs=[b"\x0a\0\0\1"], auth=b"pw"))
        ),
        "vrrp_bits": attempt(lambda: (lambda v: [v.v, v.type])(vrrp_m.VRRP(b"\x31" + bytes(7)))),
        "ip6_igmp_packed": attempt(lambda: snapshot(ip6m.IP6(nxt=2, data=igmp.IGMP()))),
        "ip6_vrrp_packed": attempt(
            lambda: snapshot(ip6m.IP6(nxt=112, data=vrrp_m.VRRP(addrs=[], auth=b"")))
        ),
        "ip6_table": attempt(lambda: [ip6m.IP6.get_proto(p).__name__ for p in (2, 112, 118)]),
    }
    return r


def exercise(package):
    targets = {"igmp": package.igmp.IGMP, "vrrp": package.vrrp.VRRP, "ip6": package.ip6.IP6}
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
    for member in ("igmp", "vrrp", "ip6"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified IGMP or VRRP module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# No declared differences: IGMP and VRRP raise only dpkt's own errors.
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
        C.require(not wrong, "IGMP or VRRP mismatch " + module + v + ": " + ", ".join(wrong))
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
