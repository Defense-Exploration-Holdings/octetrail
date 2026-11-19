"""Independent benign fixture expectations for the format-selection checkpoint."""

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def cases():
    def literal(name):
        return bytes.fromhex((ROOT / "tests/fixtures" / name).read_text())

    micro = literal("little-micro.hex")
    nano = literal("big-nano.hex")
    ng = literal("pcapng-little.hex")
    ng_nano = literal("pcapng-big-nano.hex")
    ng_nano_header = 28 + struct.unpack_from(">I", ng_nano, 32)[0]
    fixtures = [
        ("classic_micro", micro, "pcap", 24, [["1.25", "float", "616263"], ["2.0", "float", ""]]),
        ("classic_nano", nano, "pcap", 24, [["1700000000.123456789", "Decimal", "7261696c"]]),
        ("ng_micro", ng, "pcapng", 48, [["1.25", "float", "616263"]]),
        ("ng_nano", ng_nano, "pcapng", ng_nano_header, [["-0.75", "float", "7261696c"]]),
    ]
    result = []

    def add(name, raw, format_name=None, header=0, rows=None, *, mode="read", **options):
        result.append(
            {
                "id": name,
                "hex": raw.hex(),
                "format": format_name,
                "header": header,
                "rows": rows or [],
                "mode": mode,
                "status": "matching",
                **options,
            }
        )

    for name, raw, format_name, header, rows in fixtures:
        for mode in ("read", "dispatch", "interleave"):
            add(name + "." + mode, raw, format_name, header, rows, mode=mode)
        if format_name == "pcap":
            add(name + ".offset", b"prefix" + raw, format_name, header + 6, rows, start=6)
        else:
            add(
                name + ".absolute_zero",
                ng + raw,
                "pcapng",
                48,
                [["1.25", "float", "616263"]],
                start=len(ng),
                first_only=True,
                status="fixed",
                fixed={"header": len(ng) + header, "rows": rows},
            )
        add(name + ".empty", raw[:header], format_name, header)
        add(
            name + ".nonseekable",
            raw,
            format_name,
            header,
            rows,
            nonseekable=True,
            error="AttributeError" if format_name == "pcapng" else None,
            **({"status": "fixed", "fixed": {"error": None}} if format_name == "pcapng" else {}),
        )
    for length in (0, 3, 23):
        add(f"initial_short_{length}", ng[:length], error="NeedData")
    add("ng_packet_trailer_short", ng[:-1], "pcapng", 48, error="NeedData", error_phase="iteration")
    ng_rows = [["1.25", "float", "616263"]]
    no_seek = {"error": None, "format": "pcapng", "header": 48, "rows": ng_rows}
    add(
        "seek_value_error",
        ng,
        mode="seek_value_error",
        error="ValueError",
        identity=True,
        status="fixed",
        fixed=no_seek,
    )
    add("read_os_error", b"", mode="read_os_error", error="OSError", identity=True)
    add(
        "read_value_recovery",
        ng,
        "pcapng",
        48,
        [["1.25", "float", "616263"]],
        mode="read_value_recovery",
        status="fixed",
        fixed={"error": "ValueError", "identity": False},
    )
    add(
        "two_read_value_errors",
        b"",
        mode="two_read_value_errors",
        error="ValueError",
        status="fixed",
        fixed={"message": "first read"},
    )
    add(
        "second_read_os_error",
        b"",
        mode="second_read_os_error",
        error="OSError",
        identity=True,
        status="fixed",
        fixed={"error": "ValueError", "identity": False},
    )
    add(
        "subclass_factory",
        micro,
        "pcap",
        24,
        [["1.25", "float", "616263"], ["2.0", "float", ""]],
        mode="subclass",
    )
    add(
        "unknown_format",
        bytes(64),
        status="difference",
        reason="Unknown magic bytes are rejected after reading only the magic.",
    )
    for length in (24, 27):
        add(
            f"initial_ng_header_{length}",
            ng[:length],
            status="difference",
            reason="PCAPNG magic selects the PCAPNG reader, whose truncation raises NeedData.",
        )
    add(
        "classic_short_payload",
        micro[:42],
        status="difference",
        reason="Native truncation is rejected; upstream yields the short payload.",
    )
    version = bytearray(micro)
    struct.pack_into("<H", version, 4, 9)
    add(
        "unsupported_classic_version",
        bytes(version),
        status="difference",
        reason="Classic magic selects the classic reader, which rejects the version.",
    )
    return result
