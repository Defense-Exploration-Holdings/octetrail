"""Independent benign TCP base-header fixtures; no packet encoder is imported."""

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


def encode(values, data=b"", opts=b""):
    return (
        struct.pack(
            "!HHIIBBHHH",
            values["sport"],
            values["dport"],
            values["seq"],
            values["ack"],
            values["off"] << 4,
            values["flags"],
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
    invalid = raw[:12] + b"\x40" + raw[13:]
    add(
        "invalid_data_offset",
        "parse",
        {"outcome": "error", "phase": "construct", "error": "UnpackError"},
        hex=invalid.hex(),
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

    # Measured exclusions: ordinary option bytes and version-dependent flags.
    opts = b"\x01" * 4
    option_values = {**BASE, "off": 6}
    option_raw = encode(option_values, data, opts)
    unsupported = {"outcome": "error", "phase": "construct", "error": "NotImplementedError"}
    add(
        "excluded_options",
        "parse",
        None,
        hex=option_raw.hex(),
        status="difference",
        reason="Only a fixed 20-byte header is implemented; option headers are rejected.",
        expected_versions={
            "1.9.6": success(option_values, option_raw, data, opts),
            "1.9.8": success(option_values, option_raw, data, opts),
            "octetrail": unsupported,
        },
    )
    for name, bit in (("nonce", 1), ("reserved", 8)):
        wire = raw[:12] + bytes((0x50 | bit,)) + raw[13:]
        newer = {**BASE, "flags": BASE["flags"] | (0x100 if bit == 1 else 0)}
        add(
            "excluded_" + name,
            "parse",
            None,
            hex=wire.hex(),
            status="difference",
            reason="Nonce/reserved bits are outside the shared eight-flag API; nonce is exposed differently by the references.",
            expected_versions={
                "1.9.6": success(BASE, wire, data),
                "1.9.8": success(newer, wire, data),
                "octetrail": unsupported,
            },
        )
    return result
