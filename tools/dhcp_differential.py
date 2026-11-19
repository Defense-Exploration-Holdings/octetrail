"""DHCP messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same messages, including dpkt's own test vector,
builds them from keywords and packs them again. OctetRail must match dpkt
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

# dpkt's test vector.
DHCP_DPKT = "01010600ad53c863b88780000000000000000000000000000000000000025582f3a60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363350101fb01013d070100025582f3a632040a0001650c094775696e65766572653c084d53465420352e30370a010f03062c2e2f1f212bff0000000000"
HEADER = bytes.fromhex(DHCP_DPKT)[:240]


def cases():
    """Hex by name."""
    found = {
        "dpkt": bytes.fromhex(DHCP_DPKT),
        "header_only": HEADER,
        "pads_only": HEADER + bytes(5),
        "end_then_tail": HEADER + b"\x35\x01\x05\xfftail",
        "no_end": HEADER + b"\x35\x01\x05\x33\x04\x00\x01\x51\x80",
        "option_cut": HEADER + b"\x0c\x09ab",
        "zero_length": HEADER + b"\x50\x00\xff",
        "missing_length": HEADER + b"\x35",
        "pad_then_missing_length": HEADER + b"\x00\x00\x0c",
        "end_only": HEADER + b"\xff",
        "short_chaddr": bytes([1, 1, 2, 0]) + HEADER[4:] + b"\xff",
        "long_hln": bytes([1, 1, 40, 0]) + HEADER[4:] + b"\xff",
        "short_header": HEADER[:239],
        "empty": b"",
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
    found["opts"] = attempt(lambda: [[t, repr(d)] for t, d in packet.opts])
    found["fields"] = {k: repr(v) for k, v in sorted(vars(packet).items()) if k[0] != "_"}
    found["data"] = repr(packet.data)
    return found


def constructed(package):
    dhcp = package.dhcp

    def built():
        message = dhcp.DHCP(
            op=dhcp.DHCP_OP_REPLY,
            xid=0x1234,
            chaddr=b"\x02" * 6,
            opts=[
                (dhcp.DHCP_OPT_MSGTYPE, bytes([dhcp.DHCPOFFER])),
                (dhcp.DHCP_OPT_SERVER_ID, b"\x0a\x00\x00\x01"),
            ],
        )
        return [bytes(message).hex(), len(message), message.pack_opts().hex()]

    def repacked():
        message = dhcp.DHCP(bytes.fromhex(DHCP_DPKT))
        message.opts.append((dhcp.DHCP_OPT_HOSTNAME, b"note"))
        message.data = b"x"
        return [bytes(message).hex(), len(message)]

    return {
        "default": attempt(lambda: [repr(dhcp.DHCP()), len(dhcp.DHCP())]),
        "default_bytes": attempt(lambda: bytes(dhcp.DHCP())),
        "default_opts": attempt(lambda: [[t, repr(d)] for t, d in dhcp.DHCP().opts]),
        "built": attempt(built),
        "repacked": attempt(repacked),
        "no_opts": attempt(lambda: snapshot(dhcp.DHCP(opts=[]))),
        "str_opts": attempt(lambda: bytes(dhcp.DHCP(opts=[(1, "x")]))),
        "bytearray": attempt(lambda: snapshot(dhcp.DHCP(bytearray(bytes.fromhex(DHCP_DPKT))))),
        "bytearray_missing_length": attempt(lambda: dhcp.DHCP(bytearray(HEADER + b"\x35"))),
        "memoryview": attempt(
            lambda: [
                [t, repr(bytes(d))] for t, d in dhcp.DHCP(memoryview(bytes.fromhex(DHCP_DPKT))).opts
            ]
        ),
        "error_classes": attempt(
            lambda: sorted(
                c.__name__
                for c in type(_raised(lambda: dhcp.DHCP(HEADER + b"\x35"))).__mro__
                if c.__module__ == "builtins"
            )
        ),
        # error_classes compares builtin bases only, so the UnpackError base
        # OctetRail adds is checked here, as a declared difference.
        "missing_length_is_unpack_error": attempt(
            lambda: any(
                c.__name__ == "UnpackError"
                for c in type(_raised(lambda: dhcp.DHCP(HEADER + b"\x35"))).__mro__
            )
        ),
        "constants": attempt(
            lambda: sorted(
                (k, getattr(dhcp, k))
                for k in dir(dhcp)
                if k.startswith("DHCP") and isinstance(getattr(dhcp, k), int)
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
            name: attempt(lambda h=h: snapshot(package.dhcp.DHCP(bytes.fromhex(h))))
            for name, h in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".dhcp").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/dhcp.py")).resolve(),
        "unverified DHCP module origin",
    )
    package.dhcp = importlib.import_module(module + ".dhcp")
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. An option type in
# the last byte, with no length byte after it, raises IndexError in dpkt;
# OctetRail raises dhcp.MissingLengthError, which is both an UnpackError and an
# IndexError, with the same message.
_MISSING = {"error": "MissingLengthError", "message": "index out of range"}
# OctetRail fixes dpkt here (default options are bytes and pack). These keys are not compared;
# tests/python checks the fixed results.
FIXED = {
    "constructed.default_bytes",
    "constructed.default_opts",
}

DECLARED = {
    "cases.missing_length": _MISSING,
    "cases.pad_then_missing_length": _MISSING,
    "constructed.bytearray_missing_length": {
        "error": "MissingLengthError",
        "message": "bytearray index out of range",
    },
    "constructed.missing_length_is_unpack_error": True,
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
        C.require(not wrong, "DHCP mismatch " + module + v + ": " + ", ".join(wrong))
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
