"""Observe the fixed-header TCP API in an isolated installed distribution."""

import argparse
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import sys
from pathlib import Path

NAMES = ("sport", "dport", "seq", "ack", "off", "flags", "win", "sum", "urp", "opts", "data")


class ProbeValidationError(RuntimeError):
    """The process or installed provider did not meet the probe's requirements."""


def require(condition, message):
    if not condition:
        raise ProbeValidationError(message)


def decoded(values):
    return {
        key: bytes.fromhex(value) if key in ("opts", "data") else value
        for key, value in values.items()
    }


def snapshot(packet):
    raw, length = bytes(packet), len(packet)
    values = {name: getattr(packet, name) for name in NAMES}
    return {
        **{
            name: value.hex() if isinstance(value, bytes) else value
            for name, value in values.items()
        },
        "field_kinds": [type(value).__name__ for value in values.values()],
        "hex": raw.hex(),
        "header_hex": packet.pack_hdr().hex(),
        "length": length,
        "bytes_kind": type(raw).__name__,
        "stable": bytes(packet) == raw and len(packet) == length,
    }


def observe(cls, case):
    phase = "construct"
    try:
        operation = case["operation"]
        if operation == "construct" or (operation == "mutate" and case["start"] == "construct"):
            packet = cls(**decoded(case["fields"]))
        else:
            packet = cls(bytes.fromhex(case["hex"]), **decoded(case.get("overrides", {})))
        phase = "serialize"
        snapshots = [snapshot(packet)]
        if operation == "mutate":
            for update in case["updates"]:
                phase = "mutation"
                for name, value in decoded(update).items():
                    setattr(packet, name, value)
                phase = "serialize"
                snapshots.append(snapshot(packet))
        return {"outcome": "ok", "snapshots": snapshots}
    except Exception as error:  # noqa: BLE001 - error family and phase are observed, not ignored.
        return {"outcome": "error", "phase": phase, "error": type(error).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", choices=("dpkt", "octetrail"), required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    require(sys.flags.isolated, "TCP probe requires isolated Python (-I)")
    require(sys.prefix != sys.base_prefix, "TCP probe requires a virtual environment")
    installed_version = importlib.metadata.version(args.module)
    require(
        installed_version == args.version,
        f"TCP probe version mismatch: requested {args.version}, found {installed_version}",
    )
    module = importlib.import_module(args.module)
    origin = Path(module.__file__).resolve()
    distribution = importlib.metadata.distribution(args.module)
    prefix = Path(sys.prefix).resolve()
    require(origin.is_relative_to(prefix), "TCP provider origin is outside the virtual environment")
    require(
        origin == Path(distribution.locate_file(args.module + "/__init__.py")).resolve(),
        "TCP provider origin does not match the installed distribution",
    )
    tcp = importlib.import_module(args.module + ".tcp")
    tcp_origin = Path(tcp.__file__).resolve()
    require(
        tcp_origin.is_relative_to(prefix), "TCP module origin is outside the virtual environment"
    )
    require(
        tcp_origin == Path(distribution.locate_file(args.module + "/tcp.py")).resolve(),
        "TCP module origin does not match the installed distribution",
    )
    if args.module == "octetrail":
        require(
            importlib.util.find_spec("dpkt") is None, "TCP wheel environment must not contain dpkt"
        )
        native = importlib.import_module("octetrail._native")
        require(
            Path(native.__file__).resolve().is_relative_to(prefix),
            "TCP native extension origin is outside the virtual environment",
        )
    payload = json.load(sys.stdin)
    print(
        json.dumps(
            {
                "module": args.module,
                "version": args.version,
                "python": sys.version,
                "python_optimization": sys.flags.optimize,
                "provider_file": str(origin),
                "tcp_file": str(Path(tcp.__file__).resolve()),
                "source_sha256": hashlib.sha256(Path(tcp.__file__).read_bytes()).hexdigest(),
                "origin_verified": True,
                "cases_run": len(payload),
                "results": {case["id"]: observe(tcp.TCP, case) for case in payload},
            }
        )
    )


if __name__ == "__main__":
    main()
