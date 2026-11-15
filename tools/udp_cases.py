"""Independent fixed benign UDP fixtures and observations, without packet libraries."""

import struct
from pathlib import Path

NAMES = ("sport", "dport", "ulen", "sum")
DEFAULTS = dict(zip(NAMES, (0xDEAD, 0, 8, 0), strict=True))
BASE = dict(zip(NAMES, (12345, 54321, 12, 0x1234), strict=True))
ROOT = Path(__file__).resolve().parents[1]


def literal():
    return bytes.fromhex((ROOT / "tests/fixtures/udp-base.hex").read_text())


def encode(fields, payload=b""):
    return struct.pack("!4H", *(fields[name] for name in NAMES)) + payload


def snapshot(fields, payload):
    raw = encode(fields, payload)
    return {
        "before": dict(fields),
        "after": dict(fields),
        "data": payload.hex(),
        "field_kinds": ["int"] * 4,
        "data_kind": "bytes",
        "bytes_kind": "bytes",
        "hex": raw.hex(),
        "header_hex": raw[:8].hex(),
        "length": len(raw),
        "stable": True,
    }


def success(fields, payload):
    return {"outcome": "ok", "snapshots": [snapshot(fields, payload)]}


def cases():
    result = []

    def add(name, operation, expected, **values):
        result.append(
            dict(id=name, operation=operation, status="matching", expected=expected, **values)
        )

    def pair(name, fields, data):
        for operation in ("construct", "parse"):
            add(
                name + "." + operation,
                operation,
                success(fields, data),
                fields={**fields, "data": data.hex()},
                hex=encode(fields, data).hex(),
            )

    pair("default", DEFAULTS, b"")
    pair("literal", BASE, b"rail")
    add(
        "positional_ignores_keywords",
        "parse",
        success(BASE, b"rail"),
        hex=literal().hex(),
        overrides={"sum": 0, "ulen": 8, "data": ""},
    )
    for name in NAMES:
        for value in (0, 1, 32767, 32768, 65535):
            pair(f"unsigned.{name}.{value}", {**BASE, name: value}, b"rail")
    for length in (0, 1, 3, 16, 64, 257):
        data = (b"ordinary offline bytes " * 12)[:length]
        pair(f"payload.{length}", {**BASE, "ulen": 8 + length}, data)
    for ulen in (0, 7, 8, 12, 65535):
        pair(f"retained_length.{ulen}", {**BASE, "ulen": ulen}, b"rail")
    for name in NAMES:
        fields = dict(BASE)
        observations = [snapshot(fields, b"rail")]
        updates = []
        for value in (0, 65535, 8):
            fields[name] = value
            updates.append({name: value})
            observations.append(snapshot(fields, b"rail"))
        add(
            "mutate." + name,
            "parse",
            {"outcome": "ok", "snapshots": observations},
            hex=literal().hex(),
            updates=updates,
        )
    for checksum in (0, 32768, 65535):
        fields = {**BASE, "ulen": 8, "sum": checksum}
        observations = [snapshot(fields, b"rail")]
        updates = []
        for data in (b"other payload", b"", b"rail"):
            updates.append({"data": data.hex()})
            observations.append(snapshot(fields, data))
        add(
            f"mutate_payload.{checksum}",
            "construct",
            {"outcome": "ok", "snapshots": observations},
            fields={**fields, "data": b"rail".hex()},
            updates=updates,
        )
    add(
        "unpack_replaces_fields",
        "parse",
        {"outcome": "ok", "snapshots": [snapshot(BASE, b"rail"), snapshot(DEFAULTS, b"")]},
        hex=literal().hex(),
        updates=[{"unpack": encode(DEFAULTS).hex()}],
    )
    for size in range(8):
        add(
            f"short.{size}",
            "parse",
            {"outcome": "error", "phase": "construct", "error": "NeedData"},
            hex=literal()[:size].hex(),
        )
    for name in NAMES:
        for value in (-1, 65536, 1.25, None, "integer"):
            for operation in ("construct", "mutate"):
                add(
                    f"bad_scalar.{name}.{value!r}.{operation}",
                    "construct",
                    {"outcome": "error", "phase": "serialize", "error": "PackError"},
                    fields={**BASE, name: value} if operation == "construct" else dict(BASE),
                    updates=[{name: value}] if operation == "mutate" else [],
                )
    pair("maximum_buffer", {**BASE, "ulen": 65535}, b"x" * 65527)
    pair("buffer_limit", {**BASE, "ulen": 65535}, b"x" * 65528)
    for case in result[-2:]:
        case["status"] = "resource_difference"
        case["expected_product"] = {
            "outcome": "error",
            "phase": "construct" if case["operation"] == "parse" else "serialize",
            "error": "PacketLimitError",
        }
    return result
