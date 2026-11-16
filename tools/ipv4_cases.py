"""Independent ordinary IPv4 bytes and declared field/checksum expectations."""

import copy
import struct

LITERAL = bytes.fromhex("450000181234400040fd3b7ec0000201c63364027261696c")
BASE = {"src": "c0000201", "dst": "c6336402", "p": 253, "id": 0x1234, "df": 1}


def checksum(raw):
    words = struct.unpack("!%dH" % ((len(raw) + 1) // 2), raw + b"\0" * (len(raw) % 2))
    total = sum(words)
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total ^ 0xFFFF


def state(values=None):
    result = dict(
        v=4,
        hl=5,
        tos=0,
        len=20,
        id=0,
        flags=0,
        ttl=64,
        p=0,
        sum=0,
        src="00000000",
        dst="00000000",
        opts="",
        data="",
    )
    values = values or {}
    for name, value in values.items():
        if name in ("rf", "df", "mf"):
            result["flags"] |= value << {"rf": 15, "df": 14, "mf": 13}[name]
        else:
            result[name] = value
    if "len" not in values:
        result["len"] = 20 + len(bytes.fromhex(result["opts"] + result["data"]))
    return result


def header(s):
    return struct.pack(
        "!BBHHHBBH4s4s",
        s["v"] * 16 + s["hl"],
        s["tos"],
        s["len"],
        s["id"],
        s["flags"],
        s["ttl"],
        s["p"],
        s["sum"],
        bytes.fromhex(s["src"]),
        bytes.fromhex(s["dst"]),
    )


def fields(s, version):
    result = dict(s)
    result.update(
        rf=(s["flags"] >> 15) & 1,
        df=(s["flags"] >> 14) & 1,
        mf=(s["flags"] >> 13) & 1,
        offset=(s["flags"] & 8191) * (8 if version == "1.9.6" else 1),
    )
    return result


def snapshot(s, version):
    before = fields(s, version)
    if version == "1.9.6" or s["sum"] == 0:
        s["len"] = 20 + len(bytes.fromhex(s["opts"] + s["data"]))
    if s["sum"] == 0:
        s["sum"] = checksum(header(s) + bytes.fromhex(s["opts"]))
    wire = header(s) + bytes.fromhex(s["opts"] + s["data"])
    return {
        "before": before,
        "after": fields(s, version),
        "hex": wire.hex(),
        "length": 20 + len(bytes.fromhex(s["opts"] + s["data"])),
        "bytes_kind": "bytes",
    }


def expected(case, version):
    if case.get("error"):
        return {"outcome": "error", "phase": "construct", "error": case["error"]}
    s = copy.deepcopy(case["state"])
    observations = [snapshot(s, version)]
    for update in case.get("updates", []):
        for name, value in update.items():
            if name == "offset":
                wire_offset = value >> 3 if version == "1.9.6" else value
                s["flags"] = (s["flags"] & ~8191) | wire_offset
            else:
                s[name] = value
        observations.append(snapshot(s, version))
    return {"outcome": "ok", "snapshots": observations}


def cases():
    result = []

    def add(name, values, operation="construct", **extra):
        s = state(values)
        raw = header(s) + bytes.fromhex(s["opts"] + s["data"])
        result.append(
            dict(
                id=name,
                operation=operation,
                values=values,
                state=s,
                hex=raw.hex(),
                status="matching",
                **extra,
            )
        )

    add("default", {})
    for length in (0, 1, 3, 4, 15, 64):
        values = dict(BASE, data=(b"ordinary" * 8)[:length].hex())
        add(f"construct.{length}", values)
        s = state(values)
        s["sum"] = checksum(header(s))
        add(f"parse.{length}", s, operation="parse")
    for name, value in (
        ("tos", 255),
        ("ttl", 0),
        ("ttl", 255),
        ("id", 65535),
        ("rf", 1),
        ("mf", 1),
    ):
        add(f"field.{name}.{value}", dict(BASE, data=b"rail".hex(), **{name: value}))
    add("explicit_length_auto_sum", dict(BASE, len=20, data=b"rail".hex()))
    add("explicit_sum", dict(BASE, sum=1, data=b"rail".hex()))
    add("parse_zero_sum", dict(BASE, data=b"rail".hex()), operation="parse")
    literal_state = state(dict(BASE, data=b"rail".hex()))
    literal_state["sum"] = 0x3B7E
    add("trailing_bytes", literal_state, operation="parse", tail="706164")
    add("ttl_stale_sum", dict(BASE, data=b"rail".hex()), updates=[{"ttl": 63}])
    add("ttl_reset_sum", dict(BASE, data=b"rail".hex()), updates=[{"ttl": 63, "sum": 0}])
    add(
        "payload_reset_sum",
        dict(BASE, data=b"rail".hex()),
        updates=[{"data": "6f74686572", "sum": 0}],
    )
    add("zero_checksum_result", dict(id=0x7AEB))
    for size in range(20):
        add(f"short.{size}", {}, operation="parse", error="NeedData", truncate=size)
    add("small_ihl", dict(BASE, hl=4, data=b"rail".hex()), operation="parse", error="UnpackError")
    add(
        "retained_sum_length_change",
        dict(BASE, data=b"rail".hex()),
        updates=[{"data": "6f74686572"}],
    )
    result[-1]["status"] = "version_difference"
    offset_state = dict(literal_state, flags=0x4003, sum=0)
    offset_state["sum"] = checksum(header(offset_state))
    add("offset_units", offset_state, operation="parse")
    result[-1]["status"] = "version_difference"
    add(
        "offset_setter_units",
        offset_state,
        operation="parse",
        updates=[{"offset": 24, "sum": 0}, {"offset": 8, "sum": 0}],
    )
    result[-1]["status"] = "version_difference"
    add("opaque_options", dict(literal_state, hl=6, opts="01010101", len=28), operation="parse")
    limits = [
        ("version", dict(literal_state, v=6), "NotImplementedError"),
        ("zero_length", dict(literal_state, len=0), "NotImplementedError"),
        ("short_total_length", dict(literal_state, len=19), "ValueError"),
        ("short_payload", literal_state, "NeedData"),
    ]
    for name, values, error in limits:
        values = dict(values, sum=0)
        values["sum"] = checksum(header(values) + bytes.fromhex(values["opts"]))
        add(name, values, operation="parse", port_error=error)
        case = result[-1]
        case["status"] = "unsupported"
        if name == "short_total_length":
            case["state"]["data"] = ""
        if name == "short_payload":
            case["hex"] = case["hex"][:-2]
            case["state"]["data"] = "726169"
    return result
