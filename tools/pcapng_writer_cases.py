"""Benign output cases and an independent pcapng field encoder/decoder."""

import struct
import sys


def cases():
    ordinary = [
        (0, 0, b""),
        (1.25, 1_250_000, b"a"),
        (1.9999999, 2_000_000, b"ab"),
        (0.0000005, 0, b"abc"),
        (0.0000015, 2, b"rail"),
        (5000, 5_000_000_000, b"ordinary"),
        (2.5, 2_500_000, b"r" * 65537),
    ]
    raw = [
        (0, b""),
        (1, b"a"),
        (1024, b"ab"),
        (1_250_000_000, b"abc"),
        (2**32 + 3, b"rail"),
        (2**64 - 1, b"ordinary"),
        (65537, b"r" * 65537),
    ]
    configs = [
        {},
        {"section_comment": b"lab".hex()},
        {"interface_name": b"if0".hex()},
        {
            "section_comment": "",
            "interface_name": "if-μ".encode().hex(),
            "timestamp_resolution": 6,
            "timestamp_offset": 0,
        },
    ]
    result = []
    for index, config in enumerate(configs):
        config = {
            "snaplen": 0 if index == 2 else 262144,
            "linktype": 147 if index % 2 else 1,
            **config,
        }
        for method in ("writepkt", "writepkt_time", "writepkts", "writepkt_ticks"):
            events = [
                {"seconds": seconds, "ticks": ticks, "hex": data.hex()}
                for seconds, ticks, data in ordinary
            ]
            if method == "writepkt_ticks":
                events = [{"ticks": ticks, "hex": data.hex()} for ticks, data in raw]
            result.append({"config": config, "method": method, "events": events})
    for config in (
        {
            "timestamp_resolution": 9,
            "timestamp_offset": -2,
            "section_comment": b"lab".hex(),
            "interface_name": b"if0".hex(),
        },
        {"timestamp_resolution": 0x8A, "timestamp_offset": 2},
        {"timestamp_resolution": 0x7F},
        {"timestamp_resolution": 0xFF},
    ):
        result.append(
            {
                "config": {"snaplen": 0, "linktype": 147, **config},
                "method": "writepkt_ticks",
                "events": [{"ticks": ticks, "hex": data.hex()} for ticks, data in raw],
            }
        )
    result.append(
        {
            "config": {},
            "method": "writepkt",
            "clock": 1.25,
            "events": [{"ticks": 1_250_000, "hex": b"clock".hex()}],
        }
    )
    result.append({"config": {}, "method": "writepkts", "events": []})
    return result


def metadata_options(config, order):
    section, interface = [], []
    if config.get("section_comment") is not None:
        section.append((1, bytes.fromhex(config["section_comment"])))
    if config.get("interface_name") is not None:
        interface.append((2, bytes.fromhex(config["interface_name"])))
    if config.get("timestamp_resolution") is not None:
        interface.append((9, bytes([config["timestamp_resolution"]])))
    if config.get("timestamp_offset") is not None:
        interface.append((14, struct.pack(order + "q", config["timestamp_offset"])))
    return section, interface


def expected_bytes(case):
    order = "<" if sys.byteorder == "little" else ">"

    def options(values):
        raw = b"".join(
            struct.pack(order + "HH", code, len(value)) + value + b"\0" * (-len(value) % 4)
            for code, value in values
        )
        return raw + b"\0" * 4 if values else raw

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(order + "II", kind, length) + body + struct.pack(order + "I", length)

    config = case["config"]
    shb_options, idb_options = metadata_options(config, order)
    output = block(
        0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1) + options(shb_options)
    )
    output += block(
        1,
        struct.pack(order + "HHI", config.get("linktype", 1), 0, config.get("snaplen", 1500))
        + options(idb_options),
    )
    for row in case["events"]:
        ticks, data = row["ticks"], bytes.fromhex(row["hex"])
        output += block(
            6,
            struct.pack(order + "IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data))
            + data
            + b"\0" * (-len(data) % 4),
        )
    return output


def decode_capture(data):
    """Walk only the emitted subset, with independent length and option checks."""
    assert data[:4] == b"\x0a\x0d\x0d\x0a"
    order = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}[data[8:12]]

    def options(raw):
        values, position = [], 0
        while position < len(raw):
            assert len(raw) - position >= 4
            code, size = struct.unpack_from(order + "HH", raw, position)
            position += 4
            if code == 0:
                assert size == 0 and position == len(raw)
                return values
            padded = size + (-size % 4)
            assert padded <= len(raw) - position
            value = raw[position : position + size]
            assert raw[position + size : position + padded] == b"\0" * (padded - size)
            values.append([code, value.hex()])
            position += padded
        assert not raw, "nonempty options require an end marker"
        return values

    result, position, index = {"records": []}, 0, 0
    while position < len(data):
        assert len(data) - position >= 12
        kind, length = struct.unpack_from(order + "II", data, position)
        assert length >= 12 and length % 4 == 0 and length <= len(data) - position
        assert struct.unpack_from(order + "I", data, position + length - 4)[0] == length
        body = data[position + 8 : position + length - 4]
        if index == 0:
            assert kind == 0x0A0D0D0A and len(body) >= 16
            assert struct.unpack_from(order + "IHHq", body) == (0x1A2B3C4D, 1, 0, -1)
            result["section_options"] = options(body[16:])
        elif index == 1:
            assert kind == 1 and len(body) >= 8
            linktype, reserved, snaplen = struct.unpack_from(order + "HHI", body)
            assert reserved == 0
            result.update(linktype=linktype, snaplen=snaplen, interface_options=options(body[8:]))
        else:
            assert kind == 6 and len(body) >= 20
            interface, high, low, captured, original = struct.unpack_from(order + "IIIII", body)
            assert interface == 0 and captured <= original
            assert result["snaplen"] == 0 or captured <= result["snaplen"]
            assert len(body) == 20 + captured + (-captured % 4)
            assert body[20 + captured :] == b"\0" * (-captured % 4)
            result["records"].append([(high << 32) | low, original, body[20 : 20 + captured].hex()])
        index += 1
        position += length
    assert index >= 2
    return result
