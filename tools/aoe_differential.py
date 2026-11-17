"""ATA over Ethernet messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same messages, including dpkt's own test vectors,
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

# dpkt's test vectors.
ATA = (
    "030a6b190000000045000028941f0000e30699b4232b2400de8e8442abd100500035e1"
    "2920d9000000229bf0e204656b"
)
MACS = bytes.fromhex("010203040506111213141516")


def aoe(cmd, body=b"", first=0x10):
    return bytes([first, 0, 0, 1, 2, cmd]) + b"\x00\x00\x00\x07" + body


def cases():
    """(target, hex) by name."""
    cfg = b"\x12\x34\x00\x01\x02\x01\x00\x04conf"
    found = {
        "aoe_ata": ("aoe", aoe(0, bytes.fromhex(ATA))),
        "aoe_ata_empty": ("aoe", aoe(0)),
        "aoe_ata_short": ("aoe", aoe(0, bytes.fromhex(ATA)[:11])),
        "aoe_cfg": ("aoe", aoe(1, cfg)),
        "aoe_cfg_response": ("aoe", aoe(1, cfg, first=0x18)),
        "aoe_unknown_cmd": ("aoe", aoe(7, b"opaque")),
        "aoe_short": ("aoe", aoe(0)[:9]),
        "ata": ("aoeata", bytes.fromhex(ATA)),
        "ata_short": ("aoeata", bytes.fromhex(ATA)[:11]),
        "cfg": ("aoecfg", cfg),
        "cfg_short": ("aoecfg", cfg[:7]),
        "ethernet_aoe": ("ethernet", MACS + b"\x88\xa2" + aoe(1, cfg)),
        "ethernet_aoe_ata": ("ethernet", MACS + b"\x88\xa2" + aoe(0, bytes.fromhex(ATA))),
        "ethernet_aoe_short": ("ethernet", MACS + b"\x88\xa2" + aoe(0)[:5]),
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
    found["attrs"] = {
        name: attempt(lambda name=name: repr(getattr(packet, name)))
        for name in ("data", "aoe", "aoeata", "aoecfg", "ver", "fl")
    }
    return found


def constructed(package):
    aoe_m = package.aoe

    def bits():
        packet = aoe_m.AOE()
        found = [packet.ver, packet.fl, bytes(packet).hex()]
        packet.ver = 2
        packet.fl = 12
        found += [packet._ver_fl, bytes(packet).hex()]
        return found

    def built():
        packet = aoe_m.AOE(cmd=aoe_m.AOE_CMD_ATA, data=package.aoeata.AOEATA(scnt=1))
        return [bytes(packet).hex(), len(packet), repr(packet)]

    def table():
        return sorted(
            (k, v.__module__.rsplit(".", 1)[-1] + "." + v.__name__)
            for k, v in aoe_m.AOE._cmdsw.items()
        )

    return {
        "default_aoe": attempt(lambda: snapshot(aoe_m.AOE())),
        "default_ata": attempt(lambda: snapshot(package.aoeata.AOEATA())),
        "default_cfg": attempt(lambda: snapshot(package.aoecfg.AOECFG())),
        "bits": attempt(bits),
        "bit_too_large": attempt(lambda: setattr(aoe_m.AOE(), "ver", 16)),
        "built": attempt(built),
        "table": attempt(table),
        "get_cmd_missing": attempt(lambda: aoe_m.AOE.get_cmd(9)),
        "ethernet_type": attempt(
            lambda: package.ethernet.Ethernet.get_type(package.ethernet.ETH_TYPE_AOE).__name__
        ),
        "constants": attempt(
            lambda: [
                aoe_m.AOE_CMD_ATA,
                aoe_m.AOE_CMD_CFG,
                aoe_m.AOE_FLAG_RSP,
                package.aoeata.ATA_DEVICE_IDENTIFY,
            ]
        ),
    }


def exercise(package):
    targets = {
        "aoe": package.aoe.AOE,
        "aoeata": package.aoeata.AOEATA,
        "aoecfg": package.aoecfg.AOECFG,
        "ethernet": package.ethernet.Ethernet,
    }
    return {
        "cases": {
            name: attempt(lambda t=t, h=h: snapshot(targets[t](bytes.fromhex(h))))
            for name, (t, h) in cases().items()
        },
        "constructed": constructed(package),
    }


def _raised(action):
    try:
        action()
    except Exception as error:  # noqa: BLE001 - the error is the observation.
        return error
    return None


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for member in ("aoe", "aoeata", "aoecfg", "ethernet"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified AoE or Ethernet module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# OctetRail matches 1.9.8 on every observation.
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
        C.require(not wrong, "AoE mismatch " + module + v + ": " + ", ".join(wrong))
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
