"""Independent synthetic pcapng field encoder for offline tests, not a product writer.

Only ordinary user-link byte strings are used. No capture/parser library writes
these inputs. Literal fixtures and direct expected values provide separate checks.
"""

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def block(order, kind, body):
    assert len(body) % 4 == 0
    length = len(body) + 12
    return struct.pack(order + "II", kind, length) + body + struct.pack(order + "I", length)


def options(order, values):
    if not values:
        return b""
    result = b""
    for code, value in values:
        result += struct.pack(order + "HH", code, len(value)) + value
        result += b"\0" * (-len(value) % 4)
    return result + struct.pack(order + "HH", 0, 0)


def section(order="<", length=-1):
    return block(order, 0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, length))


def interface(order="<", *, resolution=None, offset=None, snaplen=64, linktype=147, extra=()):
    values = list(extra)
    if resolution is not None:
        values.append((9, bytes([resolution])))
    if offset is not None:
        values.append((14, struct.pack(order + "q", offset)))
    return block(
        order, 1, struct.pack(order + "HHI", linktype, 0, snaplen) + options(order, values)
    )


def packet(order="<", *, interface_id=0, ticks=0, data=b"", original=None, extra=()):
    original = len(data) if original is None else original
    fields = struct.pack(
        order + "IIIII", interface_id, ticks >> 32, ticks & 0xFFFFFFFF, len(data), original
    )
    return block(order, 6, fields + data + b"\0" * (-len(data) % 4) + options(order, extra))


def single(
    order="<",
    rows=(),
    *,
    resolution=None,
    offset=None,
    snaplen=64,
    linktype=147,
    finite=False,
    unknown=False,
):
    body = block(order, 0x1234, b"test") if unknown else b""
    body += interface(
        order,
        resolution=resolution,
        offset=offset,
        snaplen=snaplen,
        linktype=linktype,
        extra=[(65000, b"ordinary")],
    )
    if unknown:
        body += block(order, 0x1234, b"")
    for ticks, data, original in rows:
        body += packet(order, ticks=ticks, data=data, original=original, extra=[(1, b"synthetic")])
    return section(order, len(body) if finite else -1) + body


def expected(rows, resolution=None, offset=None):
    encoded = 6 if resolution is None else resolution
    base, exponent = (2 if encoded & 0x80 else 10), encoded & 0x7F
    return [
        [str((offset or 0) + ticks / float(base**exponent)), "float", data.hex()]
        for ticks, data, _ in rows
    ]


def corpus():
    cases = []
    ordinary = [
        (0, b"a", 1),
        (1, b"abc", 5),
        (2**32 + 123, b"rail", 4),
        (2**64 - 1, bytes(range(64)), 64),
    ]
    ordinary += [(n * 1_000_000 + 123, b"row" + n.to_bytes(2, "big"), 8) for n in range(28)]
    for order in ("<", ">"):
        for index, resolution in enumerate((None, 3, 9, 0x8A, 0x7F, 0xFF)):
            for offset in (-2, 2):
                for shape, rows in enumerate(([], [(0, b"", 0)], ordinary)):
                    linktype = (1, 113, 147, 276)[(index + shape) % 4]
                    snaplen = 0 if shape == 2 else 64
                    raw = single(
                        order,
                        rows,
                        resolution=resolution,
                        offset=offset,
                        linktype=linktype,
                        snaplen=snaplen,
                        finite=index % 2 == 0,
                        unknown=True,
                    )
                    cases.append((raw, expected(rows, resolution, offset), snaplen, linktype))
    cases.extend(
        [
            (
                bytes.fromhex((ROOT / "tests/fixtures/pcapng-little.hex").read_text()),
                [["1.25", "float", b"abc".hex()]],
                64,
                147,
            ),
            (
                bytes.fromhex((ROOT / "tests/fixtures/pcapng-big-nano.hex").read_text()),
                [["-0.75", "float", b"rail".hex()]],
                64,
                147,
            ),
        ]
    )
    return cases
