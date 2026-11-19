"""Gzip headers run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same headers and optional fields, builds them from
keywords, packs them again and compresses and decompresses payloads. OctetRail must match dpkt
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


# dpkt's vector, made with the gzip command line tool.
DPKT_HELLO = (
    "1f8b080880c18556000368656c6c6f2e74787400f348cdc9c95728cf2fca4951e4020041e4a9b20d000000"
)


def header(flags, method=8, os=3):
    return b"\x1f\x8b" + bytes([method, flags]) + bytes.fromhex("80c18556") + bytes([0, os])


def cases():
    """Hex by name."""
    found = {
        "dpkt_hello": bytes.fromhex(DPKT_HELLO),
        "plain": header(0) + b"deflated",
        "extra_short": header(0x04),
        "extra_cut": header(0x04) + b"\x04\x00ID",
        "extra": header(0x04) + bytes.fromhex("0400494401000102"),
        "extra_long_len": header(0x04) + bytes.fromhex("0600494409000102abcd") + b"body",
        "extra_two_bytes": header(0x04) + bytes.fromhex("0200ab"),
        "name_unterminated": header(0x08) + b"hello.txt",
        "name": header(0x08) + b"hello.txt\x00body",
        "name_not_utf8": header(0x08) + b"\xff\xfe\x00body",
        "comment_unterminated": header(0x10) + b"note",
        "comment": header(0x10) + b"note\x00body",
        "encrypt_short": header(0x20) + bytes(11),
        "encrypt": header(0x20) + bytes(range(12)) + b"body",
        "hcrc_short": header(0x02) + b"\x01",
        "hcrc": header(0x02) + b"\x01\x02body",
        "all_flags": header(0x3F)
        + bytes.fromhex("0400494400000000")[:6]
        + b"n\x00c\x00"
        + bytes(12)
        + b"\xaa\xbb"
        + b"body",
        "reserved_flags": header(0xC0) + b"body",
        "bad_magic": b"PK\x03\x04" + bytes(6) + b"body",
        "header_short": header(0)[:9],
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
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {
        k: snapshot(v) if hasattr(v, "__hdr__") else repr(v)
        for k, v in sorted(vars(packet).items())
        if k[0] != "_"
    }
    return found


def decoded(packet):
    found = snapshot(packet)
    found["optional"] = [repr(packet.extra), repr(packet.filename), repr(packet.comment)]
    return found


def constructed(package):
    gz = package.gzip
    raw = bytes.fromhex(DPKT_HELLO)

    def built():
        found = []
        for keywords in (
            {},
            {"filename": "hello.txt"},
            {"comment": b"note"},
            {"extra": gz.GzipExtra(id=b"ID", len=1, data=b"\x01")},
            {"filename": "", "comment": b""},
            {"flags": 0x02, "data": b"x"},
        ):
            packet = gz.Gzip(**keywords)
            found.append([bytes(packet).hex(), packet.flags, len(packet)])
        return found

    def compressed():
        packet = gz.Gzip(data=b"Hello world!\n" * 3)
        packet.compress()
        return [packet.data.hex(), packet.decompress().hex()]

    return {
        "default": attempt(lambda: decoded(gz.Gzip())),
        "default_extra": attempt(lambda: snapshot(gz.GzipExtra())),
        "decompress": attempt(lambda: gz.Gzip(raw).decompress()),
        "decompress_garbage": attempt(lambda: gz.Gzip(header(0) + b"\xff\xff").decompress()),
        "built": attempt(built),
        "compressed": attempt(compressed),
        "repack": attempt(lambda: bytes(gz.Gzip(raw)).hex()),
        "bytearray": attempt(lambda: decoded(gz.Gzip(bytearray(raw)))),
        "filename_error_classes": attempt(
            lambda: [
                c.__name__
                for c in type(_raised(lambda: gz.Gzip(header(0x08) + b"\xff\x00"))).__mro__
                if c.__module__ == "builtins"
            ]
        ),
        "constants": attempt(
            lambda: sorted(
                (k, getattr(gz, k))
                for k in dir(gz)
                if k.startswith("GZIP_") and isinstance(getattr(gz, k), (int, bytes))
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
            name: attempt(lambda h=h: decoded(package.gzip.Gzip(bytes.fromhex(h))))
            for name, h in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".gzip").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/gzip.py")).resolve(),
        "unverified gzip module origin",
    )
    package.gzip = importlib.import_module(module + ".gzip")
    return package


# Observations where OctetRail differs from 1.9.8 on purpose: a file name that
# is not UTF-8 raises an error that is also an UnpackError, with dpkt's message.
# OctetRail fixes dpkt here (the magic and method are checked). These keys are not compared;
# tests/python checks the fixed results.
FIXED = {
    "cases.bad_magic",
}

DECLARED = {
    "cases.name_not_utf8": {
        "error": "FilenameDecodeError",
        "message": "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
    },
}


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
        C.require(not wrong, "gzip mismatch " + module + v + ": " + ", ".join(wrong))
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
