"""Measure the installed offline UDP subset in an isolated provider environment."""

import argparse
import importlib
import importlib.metadata
import importlib.util
import json
import sys
from pathlib import Path

NAMES = ("sport", "dport", "ulen", "sum")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_provider(name, version):
    require(
        sys.flags.isolated and sys.prefix != sys.base_prefix,
        "isolated virtual environment required",
    )
    distribution = importlib.metadata.distribution(name)
    require(distribution.version == version, "installed UDP provider version mismatch")
    module = importlib.import_module(name)
    udp = importlib.import_module(name + ".udp")
    prefix = Path(sys.prefix).resolve()
    for obj, member in ((module, "__init__.py"), (udp, "udp.py")):
        origin = Path(obj.__file__).resolve()
        require(origin.is_relative_to(prefix), "UDP provider origin outside environment")
        require(
            origin == Path(distribution.locate_file(name + "/" + member)).resolve(),
            "UDP provider origin does not match distribution",
        )
    if name == "octetrail":
        require(importlib.util.find_spec("dpkt") is None, "unexpected dpkt in product environment")
        native = importlib.import_module(name + "._native")
        require(
            Path(native.__file__).resolve().is_relative_to(prefix),
            "UDP native origin outside environment",
        )
    return udp.UDP


def decode(values):
    return {
        name: bytes.fromhex(value) if name == "data" else value for name, value in values.items()
    }


def snapshot(packet):
    before = {name: getattr(packet, name) for name in NAMES}
    raw = bytes(packet)
    return {
        "before": before,
        "after": {name: getattr(packet, name) for name in NAMES},
        "data": packet.data.hex(),
        "field_kinds": [type(value).__name__ for value in before.values()],
        "data_kind": type(packet.data).__name__,
        "bytes_kind": type(raw).__name__,
        "hex": raw.hex(),
        "header_hex": packet.pack_hdr().hex(),
        "length": len(packet),
        "stable": bytes(packet) == raw and len(packet) == len(raw),
    }


def observe(factory, case):
    phase = "construct"
    try:
        if case["operation"] == "construct":
            packet = factory(**decode(case["fields"]))
        else:
            packet = factory(bytes.fromhex(case["hex"]), **decode(case.get("overrides", {})))
        phase = "serialize"
        observations = [snapshot(packet)]
        for update in case.get("updates", []):
            phase = "mutation"
            if "unpack" in update:
                packet.unpack(bytes.fromhex(update["unpack"]))
            else:
                for name, value in decode(update).items():
                    setattr(packet, name, value)
            phase = "serialize"
            observations.append(snapshot(packet))
        return {"outcome": "ok", "snapshots": observations}
    except Exception as error:  # noqa: BLE001 - error family and phase are measured observations.
        return {"outcome": "error", "phase": phase, "error": type(error).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", choices=("dpkt", "octetrail"), required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    factory = verify_provider(args.module, args.version)
    payload = json.load(sys.stdin)
    identifiers = [case["id"] for case in payload]
    require(len(identifiers) == len(set(identifiers)), "duplicate UDP case IDs")
    print(
        json.dumps(
            {
                "module": args.module,
                "version": args.version,
                "python": sys.version.split()[0],
                "python_optimization": sys.flags.optimize,
                "origin_verified": True,
                "cases_run": len(payload),
                "results": {case["id"]: observe(factory, case) for case in payload},
            }
        )
    )


if __name__ == "__main__":
    main()
