"""Independent benign writer inputs and byte-level capture checks.

Expected wire timestamp components are explicit data, not a copy of the product's
rounding implementation. No capture writer or reader library produces expectations.
"""

import struct
import sys


def event(kind, value, seconds, fraction, data, conversion="bytes"):
    return {
        "timestamp": {"kind": kind, "value": value},
        "seconds": seconds,
        "fraction": fraction,
        "hex": data.hex(),
        "conversion": conversion,
    }


def cases():
    result = []
    for nano in (False, True):
        scale = 1_000_000_000 if nano else 1_000_000
        for linktype in (1, 147):
            for method in ("writepkt", "writepkt_time", "writepkts"):
                events = [
                    event("int", "0", 0, 0, b""),
                    event("float", "1.25", 1, scale // 4, b"abc", "bytearray"),
                    event(
                        "decimal",
                        "1700000000.123456789",
                        1_700_000_000,
                        123_456_789 if nano else 123_457,
                        bytes(range(64)),
                        "memoryview",
                    ),
                    event("float", "4294967295.5", 0xFFFFFFFF, scale // 2, b"last", "object"),
                    event("int", "2", 2, 0, b"r" * 65537),
                ]
                result.append(
                    {
                        "config": {"snaplen": 262144, "linktype": linktype, "nano": nano},
                        "method": method,
                        "events": events,
                    }
                )
        for method in ("writepkt", "writepkt_time", "writepkts"):
            ties = ("1.0000000005", "1.0000000015") if nano else ("1.0000005", "1.0000015")
            result.append(
                {
                    "config": {"nano": nano},
                    "method": method,
                    "events": [
                        event("decimal", ties[0], 1, 0, b"even"),
                        event("decimal", ties[1], 1, 2, b"up"),
                    ],
                }
            )
        result.append(
            {
                "config": {"nano": nano},
                "method": "writepkt",
                "events": [
                    event("clock", "1.25", 1, scale // 4, b"clock"),
                ],
            }
        )
    result.append({"config": {}, "method": "writepkts", "events": []})
    return result


def expected_bytes(case):
    config = case["config"]
    order = "<" if sys.byteorder == "little" else ">"
    magic = 0xA1B23C4D if config.get("nano", False) else 0xA1B2C3D4
    output = struct.pack(
        order + "IHHIIII", magic, 2, 4, 0, 0, config.get("snaplen", 1500), config.get("linktype", 1)
    )
    for row in case["events"]:
        data = bytes.fromhex(row["hex"])
        output += (
            struct.pack(order + "IIII", row["seconds"], row["fraction"], len(data), len(data))
            + data
        )
    return output


def decode_capture(data):
    """Independent bounded walk of generated classic-pcap bytes, using struct."""
    magics = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    assert len(data) >= 24
    order, scale = magics[data[:4]]
    major, minor, timezone, accuracy, snaplen, linktype = struct.unpack_from(
        order + "HHiiII", data, 4
    )
    assert (major, minor, timezone, accuracy) == (2, 4, 0, 0)
    assert snaplen > 0
    offset, records = 24, []
    while offset < len(data):
        assert len(data) - offset >= 16
        seconds, fraction, captured, original = struct.unpack_from(order + "IIII", data, offset)
        assert fraction < scale and captured <= snaplen and captured <= original
        offset += 16
        assert captured <= len(data) - offset
        records.append([seconds, fraction, original, data[offset : offset + captured].hex()])
        offset += captured
    return {"snaplen": snaplen, "linktype": linktype, "scale": scale, "records": records}
