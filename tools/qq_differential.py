"""QQ headers run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same QQ headers, builds them from keywords, packs
them again and reads the command tables. OctetRail must match dpkt
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


BASIC = bytes([2]) + bytes.fromhex("0f5a00220001") + (123456).to_bytes(4, "big")
QQ3 = bytes([3, 0x0B]) + bytes.fromhex("0007") + bytes(36) + bytes([1, 0, 0]) + b"\x0f\x5a\x00"
QQ5 = bytes([5]) + bytes.fromhex("0f5a00000022000a") + (654321).to_bytes(4, "big")


def cases():
    """(class, hex) by name."""
    found = {
        "basic": ("QQBasicPacket", BASIC + b"payload"),
        "basic_exact": ("QQBasicPacket", BASIC),
        "basic_short": ("QQBasicPacket", BASIC[:10]),
        "qq3": ("QQ3Packet", QQ3 + b"tail"),
        "qq3_short": ("QQ3Packet", QQ3[:20]),
        "qq5": ("QQ5Packet", QQ5 + b"x"),
        "qq5_short": ("QQ5Packet", QQ5[:3]),
        "empty": ("QQBasicPacket", b""),
    }
    return {k: (c, v.hex()) for k, (c, v) in found.items()}


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


def constructed(package):
    qq = package.qq
    tables = {}
    for name in sorted(dir(qq)):
        value = getattr(qq, name)
        if isinstance(value, dict) and not name.startswith("_"):
            tables[name] = sorted(value.items())
    return {
        "defaults": attempt(
            lambda: {
                n: snapshot(getattr(qq, n)()) for n in ("QQBasicPacket", "QQ3Packet", "QQ5Packet")
            }
        ),
        "keywords": attempt(
            lambda: [
                snapshot(qq.QQBasicPacket(command=qq.QQ_CMD_SEND_IM, qqNum=7, data=b"hi")),
                snapshot(qq.QQ5Packet(source=1, sequence=2, data=b"x")),
            ]
        ),
        "bytearray": attempt(lambda: snapshot(qq.QQBasicPacket(bytearray(BASIC + b"x")))),
        "tables": attempt(lambda: tables),
        "constants": attempt(
            lambda: sorted(
                (k, getattr(qq, k))
                for k in dir(qq)
                if k.isupper() and isinstance(getattr(qq, k), int)
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
            name: attempt(lambda c=c, h=h: snapshot(getattr(package.qq, c)(bytes.fromhex(h))))
            for name, (c, h) in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".qq").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/qq.py")).resolve(),
        "unverified QQ module origin",
    )
    package.qq = importlib.import_module(module + ".qq")
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
        C.require(not wrong, "QQ mismatch " + module + v + ": " + ", ".join(wrong))
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
