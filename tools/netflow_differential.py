"""NetFlow exports run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same version 1, 5, 6 and 7 exports, builds them from
records and packs them again. OctetRail must match dpkt
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


# dpkt's test vectors: the whole v1 sample, and the v5 header with 4 records.
DPKT_V1 = (
    "00010018677a613c4200fc1c24930870ac012057c0a863f70a0002010003000a0000000100000228677a372c"
    "677a372c5c1b0050ac01112c100000000004001bac011853ac18d9aac0a832020003001900000001000005dc"
    "677a377c677a377cd8e30050ac01062c100000000004001bac011418ac188dcdc0a832660003000700000001"
    "000005dc677a3790677a37908a81176fac0106361000000000040003ac0f2724ac01e51dc0a832060004001b"
    "0000000100000228677a3a38677a3a38a3511236ac2906fd180000000004001bac011645ac23178ec0a83206"
    "0003001b0000000100000228677a3a4c677a3a4cc9ff0050ac1f0686020000000003001bac0d09ffac019995"
    "c0a832060004001b00000001000005dc677a3a58677a3a58ee390017ac0106de1000000000040003ac0e4ad8"
    "ac01ae2fc0a832060004001b00000001000005dc677a3a68677a3a68b36e0015ac010681100000000004001b"
    "ac012338ac01d92ac0a832060003001b00000001000005dc677a3a74677a3a7400008350ac2101ab10000000"
    "0003001bac0a6037ac2a934ac0a832060004001b00000001000005dc677a3a74677a3a7400000000ac0132a9"
    "1000000000040007ac0a471fac01fd4ac0a832060004001b0000000100000028677a3a88677a3a8821996987"
    "ac1e067e020000000003001bac0128c9ac0142c4c0a83202000300190000000100000028677a3a88677a3a88"
    "7d360050ac0106fe100000000004001bac0b08e8ac0146e2c0a832020004001900000001000005dc677a3a9c"
    "677a3a9c60696987ac01063b100000000004001bac011d24ac3cf0c3c0a832060003001b00000001000005dc"
    "677a3a9c677a3a9c46320014ac0106731800000000040003ac0b1151ac01de06c0a832060004001b00000001"
    "000005dc677a3ab0677a3ab0ef231a2bac2906e9100000000004001bac0c52d9ac016fe8c0a8320200040019"
    "00000001000005dc677a3ac4677a3ac4136e006eac1906a81000000000030019ac013dddac017deec0a83266"
    "000300070000000100000028677a3ac4677a3ac40000dcbbac0101d3100000000004001bac0f28d1ac01cca5"
    "c0a832060004001b00000001000005dc677a3ad8677a3ad8c573176fac1906231800000000030007ac0a855b"
    "c0a8636e0a0002010004000a00000001000005dc677a3ae4677a3ae4bf6c0050ac0106cf1000000000040007"
    "ac01301fac182145c0a832660003000700000001000005dc677a3b00677a3b00119504bec0a806ea10000000"
    "0003000aac0130b6ac1ef4aac0a832060003001b00000001000005dc677a3b34677a3b3488640017ac01061f"
    "100000000004001bac01235fac1eb009c0a832060003001b00000001000005dc677a3b48677a3b4881530050"
    "ac20064e100000000003001bac0104d9ac019463c0a832060003001b0000000100000228677a3b5c677a3b5c"
    "55100050ac010650180000000004001bac013caeac2aac21c0a832060003001b00000001000000fa677a3b84"
    "677a3b840ce70050ac0111fd100000000004001bac011f1fac17ed69c0a832020003001900000001000005dc"
    "677a3b98677a3b98ba170016ac01067c1000000000030007"
)
DPKT_V5_HEADER = "0005001db5fac9d03a0b4142265677de9b73763100010000"
DPKT_V5_RECORDS = (
    "ac0a86a6ac01aaf7c0a83232027100690000000100000228b5fa8114b5fa8114353200500000060000000000"
    "00000000ac019144ac1443e4c0a83216006902710000000100000028b5fa9bbdb5fa9bbd005085d700000600"
    "0000000000000000ac17e2d7ac018c56c0a832320271006900000001000005dcb5fa6fb8b5fa6fb876e8176f"
    "000006000000000000000000ac0ef2e5ac0191b2c0a832320271006900000001000000fab5fa81eeb5fa81ee"
    "d0eb0015000006000000000000000000"
)


def header(version, count, extra):
    return version.to_bytes(2, "big") + count.to_bytes(2, "big") + bytes(range(1, 13)) + extra


def record(size, seed):
    return bytes((seed + i) % 256 for i in range(size))


V5 = bytes.fromhex(DPKT_V5_HEADER) + bytes.fromhex(DPKT_V5_RECORDS)
# (class, record size, bytes after the base header)
VERSIONS = {
    "Netflow1": (1, 48, b""),
    "Netflow5": (5, 48, bytes(8)),
    "Netflow6": (6, 52, bytes(8)),
    "Netflow7": (7, 52, bytes(8)),
}


def cases():
    """(class, hex) by name."""
    found = {
        "dpkt_v1": ("Netflow1", bytes.fromhex(DPKT_V1)),
        "dpkt_v5": ("Netflow5", V5),
        "dpkt_v5_cut": ("Netflow5", V5[:-7]),
        "dpkt_v5_as_v7": ("Netflow7", V5),
        "header_short": ("Netflow5", V5[:10]),
        "base": ("NetflowBase", header(1, 0, b"") + record(30, 1)),
        "base_empty": ("NetflowBase", header(1, 0, b"")),
    }
    for name, (version, size, extra) in VERSIONS.items():
        found[name + "_two"] = (name, header(version, 2, extra) + record(size, 3) + record(size, 9))
        found[name + "_empty"] = (name, header(version, 0, extra))
        found[name + "_cut"] = (name, header(version, 1, extra) + record(size - 1, 5))
        found[name + "_count_wrong"] = (name, header(version, 9, extra) + record(size, 7))
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


def decoded(packet):
    found = snapshot(packet)
    found["records"] = [snapshot(r) for r in packet.data] if isinstance(packet.data, list) else None
    return found


def constructed(package):
    nf = package.netflow

    def built():
        found = []
        for name in VERSIONS:
            cls = getattr(nf, name)
            records = [cls.NetflowRecord(src_addr=1, dst_addr=2), cls.NetflowRecord(dst_port=80)]
            message = cls(count=7, data=records)
            found.append([bytes(message).hex(), message.count, len(message), len(records[0])])
        return found

    def repack():
        message = nf.Netflow5(V5)
        return [bytes(message).hex(), len(message), [bytes(r).hex() for r in message.data]]

    return {
        "defaults": attempt(
            lambda: {
                n: [repr(getattr(nf, n)()), snapshot(getattr(nf, n).NetflowRecord())]
                for n in VERSIONS
            }
        ),
        "len_empty": attempt(lambda: len(nf.Netflow5(count=0, data=[]))),
        "built": attempt(built),
        "repack": attempt(repack),
        "bytearray": attempt(lambda: decoded(nf.Netflow5(bytearray(V5)))),
        "record_alone": attempt(lambda: snapshot(nf.Netflow5.NetflowRecord(V5[24:] + b"tail"))),
        "record_short": attempt(lambda: snapshot(nf.Netflow5.NetflowRecord(V5[24:40]))),
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
            name: attempt(lambda c=c, h=h: decoded(getattr(package.netflow, c)(bytes.fromhex(h))))
            for name, (c, h) in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".netflow").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/netflow.py")).resolve(),
        "unverified NetFlow module origin",
    )
    package.netflow = importlib.import_module(module + ".netflow")
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
        C.require(not wrong, "NetFlow mismatch " + module + v + ": " + ", ".join(wrong))
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
