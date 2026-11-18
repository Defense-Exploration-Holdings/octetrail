"""ASN.1 BER decoding run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider decodes the same buffers, including every prefix of dpkt's LDAP
test vector, and converts UTCTime strings. OctetRail must match dpkt 1.9.8 on
every observation except the declared ones; the keys where 1.9.6 differs are
listed.
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


# dpkt's LDAP search request test vector.
LDAP = (
    b"0\x82\x02Q\x02\x01\x0bc\x82\x02J\x04xcn=Douglas J Song 1, ou=Information Technology Division,"
    b" ou=Faculty and Staff, ou=People, o=University of Michigan, c=US\n\x01\x00\n\x01\x03\x02\x01"
    b"\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectclass0\x82\x01\xb0\x04\rmemberOfGroup\x04\x03acl"
    b"\x04\x02cn\x04\x05title\x04\rpostalAddress\x04\x0ftelephoneNumber\x04\x04mail\x04\x06member"
    b"\x04\thomePhone\x04\x11homePostalAddress\x04\x0bobjectClass\x04\x0bdescription\x04\x18"
    b"facsimileTelephoneNumber\x04\x05pager\x04\x03uid\x04\x0cuserPassword\x04\x08joinable\x04\x10"
    b"associatedDomain\x04\x05owner\x04\x0erfc822ErrorsTo\x04\x08ErrorsTo\x04\x10rfc822RequestsTo\x04\n"
    b"RequestsTo\x04\tmoderator\x04\nlabeledURL\x04\nonVacation\x04\x0fvacationMessage\x04\x05drink\x04\x0e"
    b"lastModifiedBy\x04\x10lastModifiedTime\x04\rmodifiersname\x04\x0fmodifytimestamp\x04\x0ccreatorsname"
    b"\x04\x0fcreatetimestamp"
)


def cases():
    """Hex by name."""
    found = {
        "ldap": LDAP,
        "empty": b"",
        "one_byte": b"\x02",
        "int_0": b"\x02\x00",
        "int_1": b"\x02\x01\xff",
        "int_1_cut": b"\x02\x01",
        "int_2": b"\x02\x02\x01\x02",
        "int_2_cut": b"\x02\x02\x01",
        "int_3_reads_4": b"\x02\x03\x01\x02\x03\x04\x05",
        "int_3_cut": b"\x02\x03\x01\x02\x03",
        "int_4": b"\x02\x04\xff\xff\xff\xff",
        "int_5": b"\x02\x05\x01\x02\x03\x04\x05",
        "int_context": b"\x82\x01\x07",
        "long_1": b"\x04\x81\x03abc",
        "long_1_cut": b"\x04\x81",
        "long_2": b"\x04\x82\x00\x02ab",
        "long_2_cut": b"\x04\x82\x00",
        "long_3": b"\x04\x83\x00\x00\x05abcde",
        "long_3_short": b"\x04\x83\x00\x00",
        "long_4": b"\x04\x84\x00\x00\x00\x02ab",
        "long_4_huge": b"\x04\x84\xff\xff\xff\xffab",
        "long_5": b"\x04\x85\x00\x00\x00\x00\x01a",
        "long_127": b"\x04\xff",
        "primitive_indefinite": b"\x04\x80ab",
        "constructed_indefinite": b"\x30\x80\x02\x01\x05",
        "dpkt_indefinite": b"\x20\x80",
        "indefinite_nested": b"\x30\x80\x30\x80\x04\x01a",
        "constructed_runs_to_end": b"\x30\x03\x02\x01\x05\x04\x01x",
        "constructed_siblings": b"\x30\x00" * 12,
        "set_of_strings": b"\x31\x06\x04\x01a\x04\x01b",
        "content_past_end": b"\x04\x10abc",
        "constructed_past_end": b"\x30\x10\x04\x01a",
        "null": b"\x05\x00",
        "oid": b"\x06\x03\x2a\x86\x48",
        "bit_string": b"\x03\x02\x00\xff",
        "high_tag": b"\x1f\x01a",
        "utc_seconds_z": b"\x17\x0d991231235959Z",
        "utc_minutes_z": b"\x17\x0b9912312359Z",
        "utc_plus": b"\x17\x11991231235959+0130",
        "utc_minus": b"\x17\x11991231235959-0130",
        "utc_cut_to_12": b"\x17\x0c991231235959",
        "utc_empty": b"\x17\x00",
        "utc_letters": b"\x17\x02ab",
        "utc_bad_month": b"\x17\x0d991331235959Z",
        "utc_context": b"\x97\x0d201005012345Z",
        "deep_nesting": b"\x30\x84\xff\xff\xff\xff" * 1200,
        "nesting_100": b"\x30\x84\xff\xff\xff\xff" * 100 + b"\x04\x01a",
        "dpkt_utc": bytes.fromhex("170d") + b"201005012345Z",
    }
    for n in range(1, len(LDAP)):
        found["ldap_prefix_%03d" % n] = LDAP[:n]
    return {k: v.hex() for k, v in found.items()}


def as_json(v):
    if isinstance(v, (bytes, bytearray, memoryview)):
        return {type(v).__name__: bytes(v).hex()}
    if isinstance(v, float):
        return {"float": v.hex()}
    if isinstance(v, (int, str, bool, type(None))):
        return v
    if isinstance(v, (list, tuple)):
        return [type(v).__name__] + [as_json(x) for x in v]
    if isinstance(v, dict):
        return {str(k): as_json(x) for k, x in v.items()}
    return {"repr": repr(v)}


def attempt(action):
    try:
        return as_json(action())
    except RecursionError as error:
        # The depth and message of dpkt's RecursionError depend on the interpreter.
        return {"error": type(error).__name__}
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}


def builtin_classes(action):
    try:
        action()
    except Exception as error:  # noqa: BLE001 - the error is the observation.
        return [c.__name__ for c in type(error).__mro__ if c.__module__ == "builtins"]
    return None


def other_inputs(asn1):
    raw = bytes.fromhex(cases()["set_of_strings"])
    return {
        "bytearray": attempt(lambda: asn1.decode(bytearray(raw))),
        "memoryview": attempt(lambda: asn1.decode(memoryview(raw))),
        "bytearray_cut": attempt(lambda: asn1.decode(bytearray(b"\x04\x02ab\x02"))),
        "memoryview_cut": attempt(lambda: asn1.decode(memoryview(b"\x04\x02ab\x30"))),
        "memoryview_utc": attempt(lambda: asn1.decode(memoryview(b"\x17\x0d991231235959Z"))),
        "none": attempt(lambda: asn1.decode(None)),
        "empty_str": attempt(lambda: asn1.decode("")),
        "str": attempt(lambda: asn1.decode("abc")),
        "index_classes": attempt(lambda: builtin_classes(lambda: asn1.decode(b"\x02"))),
        "struct_classes": attempt(lambda: builtin_classes(lambda: asn1.decode(b"\x04\x82\x00"))),
        "value_classes": attempt(lambda: builtin_classes(lambda: asn1.decode(b"\x17\x02ab"))),
        "type_classes": attempt(
            lambda: builtin_classes(lambda: asn1.decode(memoryview(b"\x17\x02ab")))
        ),
    }


def utctimes(asn1):
    texts = {
        "dpkt_plus": "201005012345+1234",
        "dpkt_minus": "201005012345-1234",
        "z_str": "201005012345Z",
        "bytes_plus": b"201005012345+1234",
        "minutes_str": "2010050123Z",
        "short_str": "2010050123",
        "letters": "20100501ab45Z",
        "bad_offset": "201005012345+ab",
        "bytes_empty_tail": b"201005012345",
    }
    return {name: attempt(lambda t=t: asn1.utctime(t)) for name, t in texts.items()}


def constants(asn1):
    names = [
        "CLASSMASK",
        "UNIVERSAL",
        "APPLICATION",
        "CONTEXT",
        "PRIVATE",
        "CONSTRUCTED",
        "TAGMASK",
        "INTEGER",
        "BIT_STRING",
        "OCTET_STRING",
        "NULL",
        "OID",
        "SEQUENCE",
        "SET",
        "PRINT_STRING",
        "T61_STRING",
        "IA5_STRING",
        "UTC_TIME",
    ]
    return {"constants": attempt(lambda: [[n, getattr(asn1, n)] for n in names])}


def exercise(package):
    asn1 = package.asn1
    return {
        "cases": {
            name: attempt(lambda h=h: asn1.decode(bytes.fromhex(h))) for name, h in cases().items()
        },
        "inputs": other_inputs(asn1),
        "utctime": utctimes(asn1),
        "module": constants(asn1),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".asn1").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/asn1.py")).resolve(),
        "unverified asn1 module origin",
    )
    package.asn1 = importlib.import_module(module + ".asn1")
    return package


# Where dpkt's decode fails with a builtin error, OctetRail raises a class that
# is both an UnpackError and that builtin, with dpkt's message. Deep nesting
# raises NestingError, an UnpackError and RecursionError, at a fixed depth.
DECLARED_CLASSES = {
    "IndexError": "ShortIndexError",
    "error": "ShortStructError",
    "ValueError": "TimeValueError",
    "TypeError": "TimeTypeError",
}
UNDECLARED = {"inputs.str"}  # A str is a caller error, raised as dpkt raises it.


def declared(key, found):
    """OctetRail's expected observation where it differs from dpkt on purpose."""
    if not key.startswith(("cases.", "inputs.")) or key in UNDECLARED:
        return None
    if not isinstance(found, dict) or set(found) - {"error", "message"}:
        return None
    if found.get("error") == "RecursionError":
        return {"error": "NestingError"}
    name = DECLARED_CLASSES.get(found.get("error"))
    return None if name is None else {"error": name, "message": found["message"]}


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
        C.require(not wrong, "asn1 mismatch " + module + v + ": " + ", ".join(wrong))
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
