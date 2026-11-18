"""SCCP messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same Skinny messages, builds them from keywords and
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


DPKT_SCCP = "080000000000000003000000abcdef0123456789"


def sccp(msgid, msg, tail=b"", length=None):
    size = len(msg) + 4 if length is None else length
    return size.to_bytes(4, "little") + bytes(4) + msgid.to_bytes(4, "little") + msg + tail


def u32(*values):
    return b"".join(v.to_bytes(4, "little") for v in values)


IP = bytes([10, 0, 0, 1])


def cases():
    """Hex by name."""
    found = {
        "dpkt": bytes.fromhex(DPKT_SCCP),
        "dpkt_long": bytes.fromhex("888800000000000000000003abcdef01"),
        "dpkt_unknown": bytes.fromhex("080000000000000000000003abcdef01"),
        "keypad": sccp(0x03, u32(5)),
        "open_receive_ack": sccp(0x22, u32(0) + IP + u32(20000, 9)),
        "open_receive_ack_short": sccp(0x22, u32(0) + IP + u32(20000)),
        "start_tone": sccp(0x82, u32(0x21)),
        "set_lamp": sccp(0x86, u32(1, 2, 3)),
        "start_media": sccp(
            0x8A, u32(7, 8, 0) + IP.ljust(16, b"\0") + u32(16384, 20, 4, 0, 0, 1, 0, 0)
        ),
        "stop_media": sccp(0x8B, u32(7, 8)),
        "call_info": sccp(
            0x8F,
            b"caller".ljust(40, b"\0")
            + b"1001".ljust(24, b"\0")
            + bytes(64)
            + u32(1, 2, 3)
            + bytes(64),
        ),
        "display_text": sccp(0x99, b"hello".ljust(36, b"\0")),
        "open_receive": sccp(0x105, u32(7, 8, 20, 4, 0, 0)),
        "close_receive": sccp(0x106, u32(7, 8)),
        "call_state": sccp(0x111, u32(1, 2, 3)),
        "display_prompt": sccp(0x112, u32(5) + b"wait".ljust(32, b"\0") + u32(1, 2)),
        "clear_prompt": sccp(0x113, u32(1, 2)),
        "activate_plane": sccp(0x116, u32(1)),
        "select_softkeys": sccp(0x110, u32(1, 2, 3, 4)),
        "msg_short": sccp(0x99, b"short"),
        "unknown": sccp(0x94, b"time"),
        "tail": sccp(0x116, u32(1), b"next"),
        "len_too_long": sccp(0x03, u32(5), length=99),
        "len_zero": sccp(0x03, u32(5), length=0),
        "len_two": sccp(0x03, u32(5), length=2),
        "header_only": sccp(0x03, b"", length=4),
        "short": b"\x08\x00\x00\x00",
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
    found["msg_classes"] = sorted(
        k for k, v in vars(packet).items() if k[0] != "_" and hasattr(v, "__hdr__")
    )
    return found


def constructed(package):
    sccp_m = package.sccp
    return {
        "default": attempt(lambda: snapshot(sccp_m.SCCP())),
        "keywords": attempt(lambda: snapshot(sccp_m.SCCP(len=8, msgid=3, msg=b"abcd", data=b"x"))),
        "message_defaults": attempt(
            lambda: {
                name: snapshot(getattr(sccp_m, name)())
                for name in sorted(dir(sccp_m))
                if isinstance(getattr(sccp_m, name), type)
                and getattr(sccp_m, name).__module__ == sccp_m.__name__
            }
        ),
        "bytearray": attempt(lambda: decoded(sccp_m.SCCP(bytearray(bytes.fromhex(DPKT_SCCP))))),
        "msgsw": attempt(lambda: sorted((k, v.__name__) for k, v in sccp_m.SCCP._msgsw.items())),
        "constants": attempt(
            lambda: sorted(
                (k, getattr(sccp_m, k))
                for k in dir(sccp_m)
                if k.isupper() and isinstance(getattr(sccp_m, k), int)
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
            name: attempt(lambda h=h: decoded(package.sccp.SCCP(bytes.fromhex(h))))
            for name, h in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".sccp").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/sccp.py")).resolve(),
        "unverified SCCP module origin",
    )
    package.sccp = importlib.import_module(module + ".sccp")
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. There are none.
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
        C.require(not wrong, "SCCP mismatch " + module + v + ": " + ", ".join(wrong))
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
