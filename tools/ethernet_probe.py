"""Observe Ethernet II behavior from an isolated, installed provider."""

import argparse
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import sys
from pathlib import Path


def decoded(values):
    return {
        key: bytes.fromhex(value) if key in ("dst", "src", "data") else value
        for key, value in values.items()
    }


def snapshot(packet):
    raw = bytes(packet)
    length = len(packet)
    return {
        "dst": bytes(packet.dst).hex(),
        "src": bytes(packet.src).hex(),
        "type": packet.type,
        "data": bytes(packet.data).hex(),
        "field_kinds": [
            type(value).__name__ for value in (packet.dst, packet.src, packet.type, packet.data)
        ],
        "hex": raw.hex(),
        "length": length,
        "bytes_kind": type(raw).__name__,
        "stable": bytes(packet) == raw and len(packet) == length,
    }


def observe(ethernet_class, case):
    phase = "construct"
    try:
        operation = case["operation"]
        if operation == "construct" or (operation == "mutate" and case["start"] == "construct"):
            packet = ethernet_class(**decoded(case["fields"]))
        else:
            raw = bytes.fromhex(case["hex"])
            raw = {"bytes": bytes, "bytearray": bytearray, "memoryview": memoryview}[
                case.get("buffer_kind", "bytes")
            ](raw)
            packet = ethernet_class(raw, **decoded(case.get("overrides", {})))
        phase = "serialize"
        observations = [snapshot(packet)]
        if operation == "mutate":
            for update in case["updates"]:
                phase = "mutation"
                for key, value in decoded(update).items():
                    setattr(packet, key, value)
                phase = "serialize"
                observations.append(snapshot(packet))
        return {"outcome": "ok", "snapshots": observations}
    except Exception as error:  # noqa: BLE001 - exceptions are observations, never swallowed.
        return {"outcome": "error", "phase": phase, "error": type(error).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", choices=("octetrail", "dpkt"), required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    assert sys.flags.isolated and sys.prefix != sys.base_prefix
    assert importlib.metadata.version(args.module) == args.version
    module = importlib.import_module(args.module)
    distribution = importlib.metadata.distribution(args.module)
    origin = Path(module.__file__).resolve()
    assert origin.is_relative_to(Path(sys.prefix).resolve())
    assert origin == Path(distribution.locate_file(args.module + "/__init__.py")).resolve()
    if args.module == "octetrail":
        assert importlib.util.find_spec("dpkt") is None
        native = importlib.import_module("octetrail._native")
        assert Path(native.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    ethernet = importlib.import_module(args.module + ".ethernet")
    assert Path(ethernet.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    payload = json.load(sys.stdin)
    results = {case["id"]: observe(ethernet.Ethernet, case) for case in payload}
    sources = [ethernet.__file__]
    if args.module == "dpkt":
        sources.append(importlib.import_module("dpkt.dpkt").__file__)
    print(
        json.dumps(
            {
                "module": args.module,
                "version": args.version,
                "python": sys.version,
                "provider_file": str(origin),
                "ethernet_file": str(Path(ethernet.__file__).resolve()),
                "origin_verified": True,
                "source_sha256": {
                    Path(path).name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                    for path in sources
                },
                "cases_run": len(results),
                "results": results,
            }
        )
    )


if __name__ == "__main__":
    main()
