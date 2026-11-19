"""Diameter messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same messages and AVPs, builds them from keywords and
packs them again. OctetRail must match dpkt
1.9.8 on every observation except the declared ones; the keys where 1.9.6
differs are listed.
"""

import argparse
import importlib
import importlib.metadata
import importlib.util
import json
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


DPKT_S = "010000288000011800000000000041c80000000c000001084000000c683030320000012840000008"
DPKT_T = "0100002c8000011800000000000041c80000000c00000108c0000010deadbeef683030320000012840000008"


def avp(code, flags, length, body):
    return code.to_bytes(4, "big") + bytes([flags]) + length.to_bytes(3, "big") + body


def diameter(avps, flags=0x80, cmd=280, length=None):
    size = 20 + len(avps) if length is None else length
    return (
        bytes([1])
        + size.to_bytes(3, "big")
        + bytes([flags])
        + cmd.to_bytes(3, "big")
        + bytes(12)
        + avps
    )


HOST = avp(264, 0x40, 12, b"h002")
VENDOR = avp(264, 0xC0, 16, b"\xde\xad\xbe\xefh002")


def cases():
    """Hex by name."""
    found = {
        "dpkt_s": bytes.fromhex(DPKT_S),
        "dpkt_t": bytes.fromhex(DPKT_T),
        "no_avps": diameter(b""),
        "host_vendor": diameter(HOST + VENDOR),
        "trailing_bytes": diameter(HOST) + b"next message",
        "len_short": diameter(HOST + VENDOR, length=32),
        "len_below_header": diameter(HOST, length=8),
        "len_zero": diameter(HOST, length=0),
        "avp_padding_not_skipped": diameter(avp(1, 0x40, 9, b"a\0\0\0") + HOST),
        "avp_len_past_end": diameter(avp(1, 0, 99, b"abc")),
        "avp_len_below_header": diameter(avp(1, 0, 4, b"abcdefgh")),
        "avp_len_zero": diameter(avp(1, 0, 0, b"abcdefghijkl")),
        "avp_vendor_len_zero": diameter(avp(1, 0x80, 0, b"vendabcdefghijklmnop")),
        "avp_vendor_len_ten": diameter(avp(1, 0x80, 10, b"vendrest")),
        "avp_vendor_cut": diameter(avp(1, 0x80, 12, b"ve")),
        "avp_header_cut": diameter(HOST + b"\x00\x00\x01"),
        "flags_all": diameter(HOST, flags=0xF0),
        "header_short": bytes.fromhex("0100001c80"),
        "many_avps": diameter(avp(7, 0, 8, b"") * 300),
    }
    return {k: v.hex() for k, v in found.items()}


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
    # The fields are read before packing: dpkt leaves the 24-bit fields as
    # bytes after a pack, and OctetRail keeps them as ints.
    found["fields"] = {
        k: snapshot(v) if hasattr(v, "__hdr__") else repr(v)
        for k, v in sorted(vars(packet).items())
        if k[0] != "_"
    }
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    return found


def decoded(cls, raw):
    # dpkt cannot pack an AVP twice, and packing the message packs its AVPs,
    # so the AVPs are read from a second parse of the same bytes.
    packet, again = cls(raw), cls(raw)
    found = snapshot(packet)
    found["flags"] = [
        packet.request_flag,
        packet.proxiable_flag,
        packet.error_flag,
        packet.retransmit_flag,
    ]
    found["avps"] = [
        [
            snapshot(a),
            attempt(lambda a=a: [a.vendor_flag, a.mandatory_flag, a.protected_flag]),
            attempt(lambda a=a: a.vendor),
        ]
        for a in getattr(again, "avps", [])
    ]
    return found


def constructed(package):
    d = package.diameter
    raw = bytes.fromhex(cases()["host_vendor"])

    def flag_setters():
        found = []
        message, attr = d.Diameter(), d.AVP()
        for name in ("request_flag", "proxiable_flag", "error_flag", "retransmit_flag"):
            setattr(message, name, 1)
            found.append(message.flags)
        for name in ("vendor_flag", "mandatory_flag", "protected_flag"):
            setattr(attr, name, 1)
            found.append(attr.flags)
        return found

    def built():
        first = d.AVP(code=264, flags=0x40, len=12, data=b"h002")
        second = d.AVP(code=1, flags=0x80, len=16, data=b"abcd")
        second.vendor = 9
        message = d.Diameter(len=48, cmd=257, flags=0x80, data=[first, second])
        return [bytes(message).hex(), len(message), len(second)]

    def repack():
        message = d.Diameter(raw)
        once = bytes(message)
        return [once.hex(), bytes(message).hex(), len(message)]

    return {
        "default_diameter": attempt(lambda: repr(d.Diameter())),
        "default_avp": attempt(lambda: snapshot(d.AVP())),
        "flag_setters": attempt(flag_setters),
        "built": attempt(built),
        "repack": attempt(repack),
        "bytearray": attempt(lambda: decoded(d.Diameter, bytearray(raw))),
        "avp_alone": attempt(lambda: snapshot(d.AVP(bytes.fromhex(cases()["host_vendor"])[20:]))),
        "constants": attempt(
            lambda: sorted(
                (k, getattr(d, k)) for k in dir(d) if k.isupper() and isinstance(getattr(d, k), int)
            )
        ),
    }


def _raised(action):
    try:
        action()
    except Exception as error:  # noqa: BLE001 - the error is the observation.
        return error
    return None


def exercise(package):
    return {
        "cases": {
            name: attempt(lambda h=h: decoded(package.diameter.Diameter, bytes.fromhex(h)))
            for name, h in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".diameter").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/diameter.py")).resolve(),
        "unverified Diameter module origin",
    )
    package.diameter = importlib.import_module(module + ".diameter")
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. There are none.
# Packing keeps the 24-bit fields as ints, so a message packs twice, and a
# zero len is filled in on a message built from fields.
FIXED = {"constructed.default_avp", "constructed.repack"}

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
        C.require(not wrong, "Diameter mismatch " + module + v + ": " + ", ".join(wrong))
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
