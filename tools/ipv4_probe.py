"""Observe fixed IPv4 fields and ordinary bytes in an isolated installed provider."""

import argparse
import importlib
import importlib.metadata
import importlib.util
import json
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_provider(name, version):
    require(sys.flags.isolated and sys.prefix != sys.base_prefix, "isolated venv required")
    module = importlib.import_module(name)
    ip = importlib.import_module(name + ".ip")
    distribution = importlib.metadata.distribution(name)
    require(distribution.version == version, "installed distribution version mismatch")
    prefix = Path(sys.prefix).resolve()
    for obj in (module, ip):
        require(Path(obj.__file__).resolve().is_relative_to(prefix), "provider outside venv")
    require(
        Path(module.__file__).resolve()
        == Path(distribution.locate_file(name + "/__init__.py")).resolve(),
        "provider does not match installed distribution",
    )
    if name == "octetrail":
        require(importlib.util.find_spec("dpkt") is None, "unexpected dpkt in product venv")
        require(
            Path(ip._native.__file__).resolve().is_relative_to(prefix),
            "native provider outside venv",
        )
    return ip.IP


def fields(p):
    return {
        **{
            k: getattr(p, k)
            for k in ("v", "hl", "tos", "len", "id", "ttl", "p", "sum", "rf", "df", "mf", "offset")
        },
        **{k: bytes(getattr(p, k)).hex() for k in ("src", "dst", "opts", "data")},
        "flags": p._flags_offset if hasattr(p, "_flags_offset") else p.off,
    }


def decode(values):
    return {
        k: bytes.fromhex(v) if k in ("src", "dst", "opts", "data") else v for k, v in values.items()
    }


def observe(factory, case):
    phase = "construct"
    try:
        if case["operation"] == "construct":
            p = factory(**decode(case["values"]))
        else:
            raw = bytes.fromhex(case["hex"] + case.get("tail", ""))
            if "truncate" in case:
                raw = raw[: case["truncate"]]
            p = factory(raw)
        phase = "serialize"

        def snapshot():
            require(type(p.data) is bytes, "payload must be bytes")
            before = fields(p)
            raw = bytes(p)
            require(type(raw) is bytes, "serialization must return bytes")
            return {
                "before": before,
                "after": fields(p),
                "hex": raw.hex(),
                "length": len(p),
                "bytes_kind": type(raw).__name__,
            }

        snapshots = [snapshot()]
        for update in case.get("updates", []):
            phase = "mutation"
            for key, value in decode(update).items():
                setattr(p, key, value)
            phase = "serialize"
            snapshots.append(snapshot())
        return {"outcome": "ok", "snapshots": snapshots}
    except Exception as error:  # noqa: BLE001 - exceptions are measured results.
        return {"outcome": "error", "phase": phase, "error": type(error).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", choices=("dpkt", "octetrail"), required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    factory = verify_provider(args.module, args.version)
    cases = json.load(sys.stdin)
    print(
        json.dumps(
            {
                "module": args.module,
                "version": args.version,
                "python": sys.version.split()[0],
                "origin_verified": True,
                "cases_run": len(cases),
                "results": {c["id"]: observe(factory, c) for c in cases},
            }
        )
    )


if __name__ == "__main__":
    main()
