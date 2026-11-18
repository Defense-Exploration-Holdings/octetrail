"""MRT records run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same records, including dpkt's TABLE_DUMP test
vector, every prefix of them and byte edits of them, builds records from
keywords and packs them again. OctetRail must match dpkt 1.9.8 on every
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


TABLE = "0001000200000003040500000006000000070008"
ATTRS = {
    "origin": "01010102",
    "as_path": "40020402010001",
    "next_hop": "4003040a000001",
    "communities": "c00808ffffff01ffffff02",
    "ext": "5001000100",
    "unknown": "c0ff03abcdef",
}

# Records by name: (class, hex).
RECORDS = {
    "dpkt_table_dump": ("TableDump", TABLE + "0002" + ATTRS["origin"]),
    "table_no_attrs": ("TableDump", TABLE + "0000" + "abcd"),
    "table_many": ("TableDump", TABLE + "0028" + "".join(ATTRS.values())),
    "table_attr_len_short": ("TableDump", TABLE + "0001" + ATTRS["as_path"] + "ff"),
    "table_attr_len_long": ("TableDump", TABLE + "00ff" + ATTRS["origin"]),
    "table_tail": ("TableDump", TABLE + "0004" + ATTRS["origin"] + "beef"),
    "table_cut": ("TableDump", TABLE + "0004" + "4001"),
    "table_evpn_cut": (
        "TableDump",
        TABLE + "0024" + "800e21001946040101010100" + "0216" + "11" * 8 + "22" * 10 + "33" * 4,
    ),
    "header": ("MRTHeader", "5c1b4a00000c0000000000160102"),
    "bgp4mp": ("BGP4MPMessage", "fde9fdea0000000101020304050607080b"),
    "bgp4mp_32": ("BGP4MPMessage_32", "0000fde90000fdea0000000101020304050607080b"),
}


def edits(raw):
    """Byte edits of the attribute length and attributes, at a stride."""
    found = {}
    for at in range(20, len(raw), 3):
        for value in (0x00, 0xFF, 0x10, (at * 37) & 0xFF):
            changed = bytearray(raw)
            changed[at] = value
            found["%04d_%02x" % (at, value)] = bytes(changed)
    return found


def cases():
    """(class, hex) by name."""
    found = {}
    for name, (kind, value) in RECORDS.items():
        raw = bytes.fromhex(value)
        found[name] = (kind, value)
        for n in range(len(raw)):
            found["%s_prefix_%03d" % (name, n)] = (kind, raw[:n].hex())
        if kind == "TableDump":
            for key, changed in edits(raw).items():
                found["%s_edit_%s" % (name, key)] = (kind, changed.hex())
    return found


CLASSES = ("MRTHeader", "TableDump", "BGP4MPMessage", "BGP4MPMessage_32")


def resolve(module, kind):
    return getattr(module, kind)


def as_json(v):
    if isinstance(v, (bytes, bytearray)):
        return {"hex": bytes(v).hex()}
    if isinstance(v, (int, str, bool, type(None))):
        return v
    if isinstance(v, (list, tuple)):
        return [as_json(x) for x in v]
    if isinstance(v, dict):
        return {str(k): as_json(x) for k, x in v.items()}
    if hasattr(v, "__hdr__"):
        return snapshot(v)
    return {"repr": repr(v)}


def attempt(action):
    try:
        return as_json(action())
    except struct.error as error:
        # struct messages differ between Python versions, so only the class is kept.
        return {"error": type(error).__name__}
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}


FLAGS = ("optional", "transitive", "partial", "extended_length")


def snapshot(packet):
    found = {"class": type(packet).__name__, "repr": attempt(lambda: repr(packet))}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {k: as_json(v) for k, v in sorted(vars(packet).items()) if k[0] != "_"}
    for name in FLAGS:
        if hasattr(type(packet), name):
            found["fields"][name] = attempt(lambda n=name: getattr(packet, n))
    return found


def constructed(package):
    m = package.mrt

    def edited():
        record = m.TableDump(bytes.fromhex(RECORDS["table_many"][1]))
        record.attributes[0].origin.type = 0
        record.peer_as = 65001
        return [bytes(record).hex(), len(record), len(record.attributes)]

    def built():
        found = []
        for make in (
            lambda: m.MRTHeader(ts=1, type=m.TABLE_DUMP, subtype=m.AFI_IPv4, len=22),
            lambda: m.TableDump(view=1, seq=2, prefix_len=24, attr_len=0),
            lambda: m.BGP4MPMessage(src_as=1, dst_as=2, family=m.AFI_IPv6),
            lambda: m.BGP4MPMessage_32(src_as=70000, dst_as=2),
        ):
            found.append(attempt(lambda f=make: snapshot(f())))
        return found

    return {
        "defaults": {n: attempt(lambda n=n: snapshot(getattr(m, n)())) for n in CLASSES},
        "edited": attempt(edited),
        "built": attempt(built),
        "bytearray": attempt(
            lambda: snapshot(m.TableDump(bytearray.fromhex(RECORDS["table_many"][1])))
        ),
        "constants": attempt(
            lambda: sorted(
                (k, getattr(m, k))
                for k in dir(m)
                if k[0].isupper() and isinstance(getattr(m, k), int)
            )
        ),
    }


def exercise(package):
    return {
        "cases": {
            name: attempt(lambda k=kind, w=w: snapshot(resolve(package.mrt, k)(bytes.fromhex(w))))
            for name, (kind, w) in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".mrt").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/mrt.py")).resolve(),
        "unverified mrt module origin",
    )
    package.mrt = importlib.import_module(module + ".mrt")
    return package


# dpkt reads an EVPN route's MAC and IP address length bytes with buf[0],
# which raises IndexError when the route ends first. These are the only
# IndexErrors dpkt's BGP module raises. OctetRail raises bgp.EVPNIndexError,
# which is both an UnpackError and an IndexError, with the same message.
INDEX_ERROR = '"error": "IndexError"'


def declared(found):
    """OctetRail's expected observation where it differs from dpkt on purpose."""
    text = json.dumps(found)
    if INDEX_ERROR not in text:
        return None
    return json.loads(text.replace(INDEX_ERROR, '"error": "EVPNIndexError"'))


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
        expected = {k: declared(found) or found for k, found in reference.items()}
        wrong = sorted(k for k in reference if report.get(k) != expected[k])
        C.require(not wrong, "mrt mismatch " + module + v + ": " + ", ".join(wrong))
    print(
        json.dumps(
            {
                "cases": len(cases()),
                "observations": len(reference),
                "providers": len(providers),
                "dpkt_196_differs_on": sorted(
                    k for k in reference if reports[0].get(k) != reference[k]
                ),
                "declared_differences": len([f for f in reference.values() if declared(f)]),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
