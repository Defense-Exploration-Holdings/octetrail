"""Independent offline Ethernet II inputs; no packet library generates these bytes."""

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DST = bytes.fromhex("02aabbccddee")
SRC = bytes.fromhex("021122334455")
OPAQUE_TYPE = 0x88B5
OPAQUE_TYPES = (0x0600, 0x1234, 0x7FFF, 0x8000, 0x88B5, 0x88B6, 0xFFFF)
PAYLOAD_LENGTHS = (0, 1, 3, 45, 46, 47, 255, 1500)


def frame(dst, src, eth_type, payload):
    """Encode only ordinary six-byte addresses and a two-byte unsigned wire type."""
    if len(dst) != 6 or len(src) != 6:
        raise ValueError("fixture addresses must contain six bytes")
    if not 0x0600 <= eth_type <= 0xFFFF:
        raise ValueError("fixture type must be in the Ethernet II range")
    return struct.pack("!6s6sH", dst, src, eth_type) + payload


def literal():
    return bytes.fromhex((ROOT / "tests/fixtures/ethernet-ii.hex").read_text())


def fields(dst=DST, src=SRC, eth_type=OPAQUE_TYPE, data=b""):
    return {"dst": dst.hex(), "src": src.hex(), "type": eth_type, "data": data.hex()}


def expected_snapshot(values, raw, *, data_kind="bytes"):
    return {
        **values,
        "field_kinds": ["bytes", "bytes", "int", data_kind],
        "hex": raw.hex(),
        "length": len(raw),
        "bytes_kind": "bytes",
        "stable": True,
    }


def cases():
    result = []

    def add(name, operation, expected, **options):
        result.append(
            {
                "id": name,
                "operation": operation,
                "status": "matching",
                "expected": expected,
                **options,
            }
        )

    def success(values, raw, **options):
        return {"outcome": "ok", "snapshots": [expected_snapshot(values, raw, **options)]}

    defaults = fields(b"", b"", 0x0800)
    default_raw = bytes.fromhex("0000000000000000000000000800")
    add("default_constructor", "construct", success(defaults, default_raw), fields={})
    add(
        "default_reparse",
        "parse",
        success(fields(bytes(6), bytes(6), 0x0800), default_raw),
        hex=default_raw.hex(),
    )
    for name, supplied, values, raw in (
        ("dst_only", {"dst": DST.hex()}, fields(DST, b"", 0x0800), DST + bytes(6) + b"\x08\x00"),
        ("src_only", {"src": SRC.hex()}, fields(b"", SRC, 0x0800), bytes(6) + SRC + b"\x08\x00"),
        ("type_only", {"type": OPAQUE_TYPE}, fields(b"", b""), bytes(12) + b"\x88\xb5"),
    ):
        add(name, "construct", success(values, raw), fields=supplied)

    for eth_type in OPAQUE_TYPES:
        for length in PAYLOAD_LENGTHS:
            payload = bytes((index * 29 + length) % 256 for index in range(length))
            values = fields(eth_type=eth_type, data=payload)
            raw = frame(DST, SRC, eth_type, payload)
            for operation in ("construct", "parse"):
                add(
                    f"{operation}.{eth_type:04x}.{length}",
                    operation,
                    success(values, raw),
                    fields=values,
                    hex=raw.hex(),
                )

    raw = literal()
    values = fields(data=b"octetrail")
    add("literal_parse", "parse", success(values, raw), hex=raw.hex())
    add("literal_construct", "construct", success(values, raw), fields=values)
    broadcast = fields(bytes.fromhex("ffffffffffff"), SRC, 0x88B6, b"offline")
    add(
        "broadcast_destination",
        "construct",
        success(broadcast, frame(bytes.fromhex(broadcast["dst"]), SRC, 0x88B6, b"offline")),
        fields=broadcast,
    )

    updates = [
        {"dst": SRC.hex()},
        {"src": DST.hex()},
        {"type": 0xFFFF},
        {"data": b"replacement\x00\xff".hex()},
        {"data": ""},
    ]
    snapshots = [expected_snapshot(values, raw)]
    current = dict(values)
    for update in updates:
        current.update(update)
        wire = frame(
            bytes.fromhex(current["dst"]),
            bytes.fromhex(current["src"]),
            current["type"],
            bytes.fromhex(current["data"]),
        )
        snapshots.append(expected_snapshot(dict(current), wire))
    for start in ("construct", "parse"):
        add(
            "mutation_from_" + start,
            "mutate",
            {"outcome": "ok", "snapshots": snapshots},
            start=start,
            fields=values,
            hex=raw.hex(),
            updates=updates,
        )

    for length in range(14):
        add(
            f"short_header.{length}",
            "parse",
            {"outcome": "error", "phase": "construct", "error": "NeedData"},
            hex=raw[:length].hex(),
        )

    # These observations describe upstream flexibility, without requiring a port
    # to adopt additional buffer types, ignored arguments or permissive widths.
    for kind in ("bytearray", "memoryview"):
        add(
            "reference_buffer_" + kind,
            "parse",
            success(values, raw, data_kind=kind),
            hex=raw.hex(),
            buffer_kind=kind,
            status="reference_only",
            reason="Non-bytes input retains the upstream payload buffer type; owned bytes are the tested API.",
        )
    add(
        "reference_buffer_with_keywords",
        "parse",
        success(values, raw),
        hex=raw.hex(),
        overrides={"type": 0x88B6, "data": b"ignored".hex()},
        status="reference_only",
        reason="Upstream ignores keyword fields when a positional buffer is present; not required here.",
    )
    short = fields(b"a", b"bc", data=b"opaque")
    add(
        "reference_short_addresses",
        "construct",
        success(short, b"a" + bytes(5) + b"bc" + bytes(4) + b"\x88\xb5opaque"),
        fields=short,
        status="reference_only",
        reason="Upstream pads short MAC values during packing; explicit addresses here have six bytes.",
    )
    for value in (-1, 0x10000, 1.0):
        for operation in ("construct", "mutate"):
            options = (
                {"fields": {"type": value}}
                if operation == "construct"
                else {"hex": raw.hex(), "start": "parse", "updates": [{"type": value}]}
            )
            add(
                f"reference_invalid_type.{operation}.{value}",
                operation,
                {"outcome": "error", "phase": "serialize", "error": "PackError"},
                **options,
                status="reference_only",
                reason="Upstream defers invalid field errors to bytes(); setter validation and PackError are not required here.",
            )
    return result
