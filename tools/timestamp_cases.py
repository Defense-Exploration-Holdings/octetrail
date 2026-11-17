"""Independent benign capture clocks and rational expectations; no packet libraries."""

import struct
from decimal import Decimal, localcontext
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def classic(order, nano, rows):
    scale = 10 ** (9 if nano else 6)
    raw = struct.pack(order + "IHHIIII", 0xA1B23C4D if nano else 0xA1B2C3D4, 2, 4, 0, 0, 64, 147)
    for ticks, data in rows:
        seconds, fraction = divmod(ticks, scale)
        raw += struct.pack(order + "IIII", seconds, fraction, len(data), len(data)) + data
    return raw


def block(order, kind, body):
    if len(body) % 4:
        raise ValueError("fixture block must be aligned")
    size = len(body) + 12
    return struct.pack(order + "II", kind, size) + body + struct.pack(order + "I", size)


def section(order):
    return block(order, 0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1))


def interface(order, encoded, offset):
    options = struct.pack(order + "HHB3x", 9, 1, encoded)
    options += struct.pack(order + "HHqHH", 14, 8, offset, 0, 0)
    return block(order, 1, struct.pack(order + "HHI", 147, 0, 64) + options)


def packet(order, ticks, data, interface_id=0):
    body = struct.pack(
        order + "IIIII", interface_id, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data)
    )
    return block(order, 6, body + data + b"\0" * (-len(data) % 4))


def row(ticks, data, base, exponent, offset=0, *, nano=False, classic_format=False):
    exact = Fraction(offset) + Fraction(ticks, base**exponent)
    if classic_format:
        seconds, fraction = divmod(ticks, base**exponent)
        with localcontext() as context:
            context.prec = 28
            default = seconds + fraction / (Decimal("1E9") if nano else 1e6)
    else:
        default = offset + ticks / float(base**exponent)
    return {
        "ticks": ticks,
        "base": base,
        "exponent": exponent,
        "offset": offset,
        "data": data.hex(),
        "ratio": [exact.numerator, exact.denominator],
        "default": {"value": str(default), "kind": type(default).__name__, "data": data.hex()},
    }


def cases():
    result = []
    for order, name in (("<", "little"), (">", "big")):
        for nano, exponent in ((False, 6), (True, 9)):
            scale = 10**exponent
            rows = [
                (0, b""),
                (1, b"one"),
                (1700000000 * scale + 123456, b"rail"),
                (0xFFFFFFFF * scale + scale - 1, b"last"),
            ]
            result.append(
                {
                    "id": f"classic.{name}.{exponent}",
                    "format": "pcap",
                    "status": "matching",
                    "hex": classic(order, nano, rows).hex(),
                    "rows": [
                        row(t, d, 10, exponent, nano=nano, classic_format=True) for t, d in rows
                    ],
                }
            )
        for encoded in (0, 6, 9, 0x8A, 0x90, 127, 255):
            base, exponent = (2 if encoded & 128 else 10), encoded & 127
            for offset in (-2, 0, 2):
                rows = [(0, b""), (1, b"one"), (1700000000123456, b"rail"), (2**64 - 1, b"last")]
                raw = section(order) + interface(order, encoded, offset)
                raw += b"".join(packet(order, t, d) for t, d in rows)
                result.append(
                    {
                        "id": f"pcapng.{name}.{encoded}.{offset}",
                        "format": "pcapng",
                        "status": "matching",
                        "hex": raw.hex(),
                        "rows": [row(t, d, base, exponent, offset) for t, d in rows],
                    }
                )
    literals = (
        (
            "little-micro.hex",
            "pcap",
            [
                row(1250000, b"abc", 10, 6, classic_format=True),
                row(2000000, b"", 10, 6, classic_format=True),
            ],
        ),
        (
            "big-nano.hex",
            "pcap",
            [row(1700000000123456789, b"rail", 10, 9, nano=True, classic_format=True)],
        ),
        ("pcapng-little.hex", "pcapng", [row(1250000, b"abc", 10, 6)]),
        ("pcapng-big-nano.hex", "pcapng", [row(1250000000, b"rail", 10, 9, -2)]),
    )
    for filename, format_name, rows in literals:
        result.append(
            {
                "id": "literal." + filename,
                "format": format_name,
                "status": "matching",
                "hex": bytes.fromhex((ROOT / "tests/fixtures" / filename).read_text()).hex(),
                "rows": rows,
            }
        )
    mixed = section("<") + interface("<", 6, 0) + interface("<", 0x8A, -2)
    mixed += packet("<", 1250000, b"one") + packet("<", 1024, b"two", 1)
    result.append(
        {
            "id": "pcapng.interfaces",
            "format": "pcapng",
            "status": "interface_difference",
            "hex": mixed.hex(),
            "rows": [row(1250000, b"one", 10, 6), row(1024, b"two", 2, 10, -2)],
            "reference_default": [
                row(1250000, b"one", 10, 6)["default"],
                row(1024, b"two", 10, 6)["default"],
            ],
        }
    )
    return result
