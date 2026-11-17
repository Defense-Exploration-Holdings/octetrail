"""Independent benign TCP fixtures; no packet encoder is imported."""

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("sport", "dport", "seq", "ack", "off", "flags", "win", "sum", "urp")
WIDTHS = {"sport": 16, "dport": 16, "seq": 32, "ack": 32, "win": 16, "sum": 16, "urp": 16}
DEFAULTS = dict(zip(NAMES, (0xDEAD, 0, 0xDEADBEEF, 0, 5, 2, 65535, 0, 0), strict=True))
BASE = dict(
    zip(NAMES, (49152, 443, 0x89ABCDEF, 0x10203040, 5, 0x18, 0x8001, 0xA1B2, 0), strict=True)
)


def literal():
    return bytes.fromhex((ROOT / "tests/fixtures/tcp-base.hex").read_text())


def encode(values, data=b"", opts=b"", reserved=0):
    return (
        struct.pack(
            "!HHIIHHHH",
            values["sport"],
            values["dport"],
            values["seq"],
            values["ack"],
            values["off"] << 12 | reserved << 9 | values["flags"],
            values["win"],
            values["sum"],
            values["urp"],
        )
        + opts
        + data
    )


def state(values, raw, data=b"", opts=b""):
    return {
        **values,
        "opts": opts.hex(),
        "data": data.hex(),
        "field_kinds": ["int"] * 9 + ["bytes", "bytes"],
        "hex": raw.hex(),
        "header_hex": raw[:20].hex(),
        "length": len(raw),
        "bytes_kind": "bytes",
        "stable": True,
    }


def success(values, raw, data=b"", opts=b""):
    return {"outcome": "ok", "snapshots": [state(values, raw, data, opts)]}


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

    default_raw = bytes.fromhex("dead0000deadbeef000000005002ffff00000000")
    add("defaults", "construct", success(DEFAULTS, default_raw), fields={})
    add("default_parse", "parse", success(DEFAULTS, default_raw), hex=default_raw.hex())
    raw, data = literal(), b"tcp-base"
    add(
        "literal_construct",
        "construct",
        success(BASE, raw, data),
        fields={**BASE, "data": data.hex()},
    )
    add("literal_parse", "parse", success(BASE, raw, data), hex=raw.hex())
    add(
        "positional_ignores_keywords",
        "parse",
        success(BASE, raw, data),
        hex=raw.hex(),
        overrides={"sum": 0, "data": ""},
    )

    def pair(name, values, payload):
        wire = encode(values, payload)
        for operation in ("construct", "parse"):
            add(
                name + "." + operation,
                operation,
                success(values, wire, payload),
                fields={**values, "data": payload.hex()},
                hex=wire.hex(),
            )

    for field, bits in WIDTHS.items():
        for value in (0, 1, (1 << (bits - 1)) - 1, 1 << (bits - 1), (1 << bits) - 1):
            pair(f"unsigned.{field}.{value}", {**BASE, field: value}, data)
    for flags in (0, 1, 2, 4, 8, 16, 32, 64, 128, 0x18, 0x12, 0x11, 0x50, 0x90):
        pair(f"flags.{flags}", {**BASE, "flags": flags}, data)
    for length in (0, 1, 7, 45, 256, 1460):
        payload = bytes((index * 17 + length) % 256 for index in range(length))
        pair(f"payload.{length}", BASE, payload)

    updates = [
        {"sport": 65535},
        {"dport": 32768},
        {"seq": 0xFFFFFFFF},
        {"ack": 0x80000000},
        {"flags": 0x30},
        {"win": 0},
        {"sum": 0},
        {"urp": 1},
        {"off": 5},
        {"data": b"replacement\x00\xff".hex()},
        {"data": ""},
    ]
    snapshots = [state(BASE, raw, data)]
    current = {**BASE, "data": data.hex()}
    for update in updates:
        current.update(update)
        values = {name: current[name] for name in NAMES}
        payload = bytes.fromhex(current["data"])
        snapshots.append(state(values, encode(values, payload), payload))
    for start in ("construct", "parse"):
        add(
            "mutation." + start,
            "mutate",
            {"outcome": "ok", "snapshots": snapshots},
            start=start,
            fields={**BASE, "data": data.hex()},
            hex=raw.hex(),
            updates=updates,
        )

    for length in range(20):
        add(
            f"short_header.{length}",
            "parse",
            {"outcome": "error", "phase": "construct", "error": "NeedData"},
            hex=raw[:length].hex(),
        )
    for field, bits in WIDTHS.items():
        for value in (-1, 1 << bits, 1.5):
            for operation in ("construct", "mutate"):
                options = (
                    {"fields": {field: value}}
                    if operation == "construct"
                    else {
                        "start": "parse",
                        "hex": raw.hex(),
                        "updates": [{field: value}],
                    }
                )
                add(
                    f"field_error.{field}.{value}.{operation}",
                    operation,
                    {"outcome": "error", "phase": "serialize", "error": "PackError"},
                    **options,
                )

    for words in range(5):
        wire = raw[:12] + bytes((words << 4, raw[13])) + raw[14:]
        add(
            f"data_offset_below_five.{words}",
            "parse",
            {"outcome": "error", "phase": "construct", "error": "UnpackError"},
            hex=wire.hex(),
        )

    # Options are the bytes up to the offset that are present; nothing is checked.
    opts = b"\x01" * 4
    option_values = {**BASE, "off": 6}
    option_raw = encode(option_values, data, opts)
    add(
        "opaque_options",
        "parse",
        success(option_values, option_raw, data, opts),
        hex=option_raw.hex(),
    )
    long_opts = bytes(range(1, 41))
    long_values = {**BASE, "off": 15}
    long_raw = encode(long_values, data, long_opts)
    add(
        "largest_offset",
        "parse",
        success(long_values, long_raw, data, long_opts),
        hex=long_raw.hex(),
    )
    short_values = {**BASE, "off": 8}
    for present in range(13):
        wire = encode(short_values, b"", long_opts[:present])
        add(
            f"short_options.{present}",
            "parse",
            success(short_values, wire, b"", long_opts[:present]),
            hex=wire.hex(),
        )
    for name, values, given in (
        ("unmatched_options", BASE, opts),
        ("missing_options", option_values, b""),
        ("odd_options", BASE, b"\x01\x01\x01"),
    ):
        wire = encode(values, data, given)
        add(
            "pack." + name,
            "construct",
            success(values, wire, data, given),
            fields={**values, "opts": given.hex(), "data": data.hex()},
        )

    # The nonce bit is the ninth flag in dpkt 1.9.8 and part of the offset byte in 1.9.6.
    # OctetRail follows 1.9.8.
    def newer_only(name, expected_198, expected_196, **options):
        add(
            name,
            options.pop("operation", "parse"),
            None,
            status="difference",
            reason="dpkt 1.9.8 exposes nine flags and the reserved bits separately; "
            "1.9.6 keeps them in one offset byte. OctetRail follows 1.9.8.",
            expected_versions={
                "1.9.6": expected_196,
                "1.9.8": expected_198,
                "octetrail": expected_198,
            },
            **options,
        )

    for name, bits in (("nonce", 1), ("reserved.1", 2), ("reserved.4", 8), ("all", 0x0F)):
        wire = raw[:12] + bytes((0x50 | bits,)) + raw[13:]
        newer = {**BASE, "flags": BASE["flags"] | (0x100 if bits & 1 else 0)}
        newer_only(
            "header_bits." + name,
            success(newer, wire, data),
            success(BASE, wire, data),
            hex=wire.hex(),
        )
    nine = {**DEFAULTS, "flags": 0x1FF}
    newer_only(
        "nine_bit_flags.construct",
        success(nine, encode(nine)),
        {"outcome": "error", "phase": "serialize", "error": "PackError"},
        operation="construct",
        fields={"flags": 0x1FF},
    )
    return result
