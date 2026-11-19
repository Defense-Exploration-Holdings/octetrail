"""GRE and PIM packets run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same packets, alone and inside IPv4 and IPv6, including
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

# dpkt's GRE and PIM test vectors.
GRE_V1_DPKT = "3081880a0067178000068fb100083a76" + "41" * 103
GRE_V1_SHORT_DPKT = "3001880a00b2001100083ab8" + "41" * 178
GRE_SRE_DPKT = "400008000001000200030402ffff00060000"
GRE_IPX_DPKT = "000081370000000102030102030405060708090a0b0cc0b0a0908070605040302010"
PIM_DPKT = "2000df93000100020069"


def ip6(nxt, body):
    return struct.pack(">IHBB16s16s", 0x60000000, len(body), nxt, 64, bytes(16), bytes(16)) + body


def ip4(p, body):
    return (
        struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, p, 0, bytes(4), bytes(4))
        + body
    )


def gre(flags, p, rest=b""):
    return struct.pack(">HH", flags, p) + rest


def frame(body=b"teb"):
    return b"\x02" * 6 + b"\x04" * 6 + b"\x88\xb5" + body


def cases():
    """(target, hex) by name."""
    found = {
        "gre_dpkt_v1": ("gre", bytes.fromhex(GRE_V1_DPKT)),
        "gre_dpkt_v1_no_ack": ("gre", bytes.fromhex(GRE_V1_SHORT_DPKT)),
        "gre_dpkt_nested_sre": ("gre", bytes.fromhex(GRE_SRE_DPKT)),
        "gre_dpkt_ipx": ("gre", bytes.fromhex(GRE_IPX_DPKT)),
        "gre_plain_unknown": ("gre", gre(0, 0x88B5, b"opaque")),
        "gre_key_seq": ("gre", gre(0x3000, 0x88B5, b"\x00\x00\x00\x07\x00\x00\x00\x09x")),
        "gre_checksum_only": ("gre", gre(0x8000, 0x88B5, b"\x12\x34\x00\x00x")),
        "gre_all_v0": ("gre", gre(0xB080, 0x88B5, bytes(2 + 2 + 4 + 4 + 4) + b"x")),
        "gre_ipv6": ("gre", gre(0, 0x86DD, ip6(59, b"in"))),
        "gre_ipv6_short": ("gre", gre(0, 0x86DD, b"\x60\x00")),
        "gre_teb": ("gre", gre(0x2000, 0x6558, b"\x00\x00\x00\x01" + frame())),
        "gre_short_options": ("gre", gre(0xB000, 0x88B5, b"\x00\x01")),
        "gre_sre_cut": ("gre", gre(0x4000, 0x88B5, bytes(4) + b"\x00\x01\x00\x09abc")),
        "gre_sre_missing_end": ("gre", gre(0x4000, 0x88B5, bytes(4) + b"\x00\x01\x00\x02ab\x00")),
        "gre_sre_none": ("gre", gre(0x4000, 0x88B5, bytes(4))),
        "gre_version_7": ("gre", gre(0x1087, 0x880B, bytes(12) + b"ppp")),
        "gre_recursion_bits": ("gre", gre(0x00E0, 0x88B5, b"r")),
        "gre_short": ("gre", b"\x00\x00\x08"),
        "pim_dpkt": ("pim", bytes.fromhex(PIM_DPKT)),
        "pim_hello": ("pim", b"\x20\x00\x00\x00\x00\x01\x00\x02\x00\x69"),
        "pim_register": ("pim", b"\x21\x00\x12\x34" + bytes(4) + b"inner"),
        "pim_short": ("pim", b"\x20\x00\x00"),
        "ip6_gre": ("ip6", ip6(47, gre(0, 0x86DD, ip6(59, b"x")))),
        "ip6_gre_short": ("ip6", ip6(47, b"\x00")),
        "ip6_gre_short_options": ("ip6", ip6(47, gre(0x8000, 0x88B5))),
        "ip6_gre_sre_missing": ("ip6", ip6(47, gre(0x4000, 0x88B5, bytes(4) + b"\x00"))),
        "ip6_pim": ("ip6", ip6(103, bytes.fromhex(PIM_DPKT))),
        "ip6_pim_short": ("ip6", ip6(103, b"\x20")),
        "ip_gre": ("ip", ip4(47, gre(0x2000, 0x0800, b"\x00\x00\x00\x05" + ip4(59, b"in")))),
        "ip_gre_short_options": ("ip", ip4(47, gre(0x8000, 0x88B5))),
        "ip_gre_sre_missing": ("ip", ip4(47, gre(0x4000, 0x88B5, bytes(4) + b"\x00"))),
        "ip_pim": ("ip", ip4(103, bytes.fromhex(PIM_DPKT))),
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
    gre_m, pim_m, ip6m, ipm = package.gre, package.pim, package.ip6, package.ip

    def accessors():
        found = []
        packet = gre_m.GRE()
        for attr in ("v", "recur"):
            found.append(getattr(packet, attr))
            setattr(packet, attr, 1)
            found.append(getattr(packet, attr))
        packet.v, packet.recur = 15, 15
        found.append(packet.flags)
        return found

    def pim_setters():
        message = pim_m.PIM(bytes.fromhex(PIM_DPKT))
        message.sum = 0
        first = bytes(message).hex()
        message.v, message.type = 3, 1
        return [first, bytes(message).hex(), message.v, message.type]

    return {
        "default_gre": attempt(lambda: snapshot(gre_m.GRE())),
        "default_pim": attempt(lambda: snapshot(pim_m.PIM())),
        "gre_keywords_v1": attempt(
            lambda: snapshot(
                gre_m.GRE(flags=0x3081, p=0x880B, len=3, callid=9, seq=1, ack=2, data=b"ppp")
            )
        ),
        "gre_keywords_key": attempt(lambda: snapshot(gre_m.GRE(flags=0x2000, key=5, data=b"k"))),
        "gre_missing_option": attempt(lambda: bytes(gre_m.GRE(flags=0x2000))),
        "gre_with_sre": attempt(
            lambda: snapshot(
                gre_m.GRE(
                    flags=0x4000,
                    sum=1,
                    off=2,
                    sre=[gre_m.GRE.SRE(family=3, len=2, data=b"ab"), gre_m.GRE.SRE()],
                )
            )
        ),
        "sre_creation": attempt(lambda: snapshot(gre_m.GRE.SRE(bytes.fromhex("00000002ffff")))),
        "sre_cut": attempt(lambda: snapshot(gre_m.GRE.SRE(bytes.fromhex("0000000affff")))),
        "accessors": attempt(accessors),
        "opt_fields_fmts": attempt(
            lambda: [
                gre_m.GRE(flags=f).opt_fields_fmts()
                for f in (0, 0x8000, 0x4000, 0xB080, 0x3081, 0x0001)
            ]
        ),
        "gre_ipv6_packed": attempt(lambda: snapshot(gre_m.GRE(p=0x86DD, data=ip6m.IP6(nxt=59)))),
        "pim_setters": attempt(pim_setters),
        "pim_sum_kept": attempt(lambda: bytes(pim_m.PIM(sum=0x1234, data=b"x")).hex()),
        "ip6_gre_packed": attempt(
            lambda: snapshot(ip6m.IP6(nxt=47, data=gre_m.GRE(p=0x88B5, data=b"g")))
        ),
        "ip6_table": attempt(lambda: [ip6m.IP6.get_proto(p).__name__ for p in (47, 103)]),
        "ip_table": attempt(lambda: [ipm.IP.get_proto(p).__name__ for p in (47, 103)]),
        "ip_gre_packed": attempt(
            lambda: snapshot(ipm.IP(p=47, data=gre_m.GRE(p=0x88B5, data=b"g")))
        ),
        "constants": attempt(
            lambda: [
                gre_m.GRE_CP,
                gre_m.GRE_RP,
                gre_m.GRE_KP,
                gre_m.GRE_SP,
                gre_m.GRE_SS,
                gre_m.GRE_AP,
            ]
        ),
    }


def exercise(package):
    targets = {
        "gre": package.gre.GRE,
        "pim": package.pim.PIM,
        "ip6": package.ip6.IP6,
        "ip": package.ip.IP,
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
    for member in ("gre", "pim", "ip6", "ip"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified GRE or PIM module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose.
# Missing option fields pack as 0, and an IPv6 packet built from fields gets
# its payload length on pack.
FIXED = {"constructed.gre_missing_option", "constructed.ip6_gre_packed"}

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
        wrong = sorted(
            k
            for k in reference
            if k not in FIXED and report.get(k) != DECLARED.get(k, reference[k])
        )
        C.require(not wrong, "GRE or PIM mismatch " + module + v + ": " + ", ".join(wrong))
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
