"""Probe the installed PCAPNG output subset, using upstream blocks only as controls."""

import argparse
import importlib
import importlib.metadata
import importlib.util
import io
import json
import struct
import sys
from pathlib import Path
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", choices=("octetrail", "dpkt"), required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    module = importlib.import_module(args.module)
    assert sys.flags.isolated and sys.prefix != sys.base_prefix
    assert importlib.metadata.version(args.module) == args.version
    origin = Path(module.__file__).resolve()
    assert origin.is_relative_to(Path(sys.prefix).resolve())
    assert (
        origin
        == Path(
            importlib.metadata.distribution(args.module).locate_file(args.module + "/__init__.py")
        ).resolve()
    )
    native = args.module == "octetrail"
    if native:
        assert importlib.util.find_spec("dpkt") is None
        assert (
            Path(module.pcapng._native.__file__)
            .resolve()
            .is_relative_to(Path(sys.prefix).resolve())
        )
    suffix = "LE" if sys.byteorder == "little" else ""
    order = "<" if sys.byteorder == "little" else ">"
    results = []
    for case in json.load(sys.stdin):
        config = case["config"]
        kwargs = {"snaplen": config.get("snaplen", 1500), "linktype": config.get("linktype", 1)}
        if native:
            for key in (
                "section_comment",
                "interface_name",
                "timestamp_resolution",
                "timestamp_offset",
            ):
                if key in config:
                    kwargs[key] = (
                        bytes.fromhex(config[key])
                        if key in ("section_comment", "interface_name")
                        else config[key]
                    )
        else:
            option_cls = getattr(module.pcapng, "PcapngOption" + suffix)

            def option(code, data, factory=option_cls):
                return factory(code=code, data=data)

            if config.get("section_comment") is not None:
                kwargs["shb"] = getattr(module.pcapng, "SectionHeaderBlock" + suffix)(
                    opts=[option(1, bytes.fromhex(config["section_comment"])), option(0, b"")]
                )
            opts = []
            if config.get("interface_name") is not None:
                opts.append(option(2, bytes.fromhex(config["interface_name"])))
            if config.get("timestamp_resolution") is not None:
                opts.append(option(9, bytes([config["timestamp_resolution"]])))
            if config.get("timestamp_offset") is not None:
                opts.append(option(14, struct.pack(order + "q", config["timestamp_offset"])))
            if opts:
                kwargs["idb"] = getattr(module.pcapng, "InterfaceDescriptionBlock" + suffix)(
                    snaplen=kwargs["snaplen"],
                    linktype=kwargs["linktype"],
                    opts=opts + [option(0, b"")],
                )
        stream = io.BytesIO()
        writer = module.pcapng.Writer(stream, **kwargs)
        returns = []
        method = case["method"]
        if method == "writepkts":
            returns.append(
                writer.writepkts(
                    (row["seconds"], bytes.fromhex(row["hex"])) for row in case["events"]
                )
            )
        else:
            for row in case["events"]:
                payload = bytes.fromhex(row["hex"])
                if method == "writepkt_ticks":
                    if native:
                        returns.append(writer.writepkt_ticks(payload, row["ticks"]))
                    else:
                        block = getattr(module.pcapng, "EnhancedPacketBlock" + suffix)(
                            ts_high=row["ticks"] >> 32,
                            ts_low=row["ticks"] & 0xFFFFFFFF,
                            pkt_data=payload,
                        )
                        # Upstream substitutes the clock for an all-zero EPB.
                        # A fixed zero preserves the explicit ticks for this control.
                        with patch.object(module.pcapng, "time", return_value=0):
                            returns.append(writer.writepkt(block))
                elif "clock" in case:
                    with patch.object(module.pcapng, "time", return_value=case["clock"]) as clock:
                        returns.append(writer.writepkt(payload))
                    clock.assert_called_once()
                else:
                    returns.append(getattr(writer, method)(payload, row["seconds"]))
        raw = stream.getvalue()
        readback = [
            [str(ts), type(ts).__name__, data.hex()]
            for ts, data in module.pcapng.Reader(io.BytesIO(raw))
        ]
        writer.close()
        assert stream.closed and all(value is None for value in returns)
        results.append(
            {"hex": raw.hex(), "readback": readback, "closed": True, "returns_none": True}
        )
    print(json.dumps({"origin_verified": True, "captures": results}))


if __name__ == "__main__":
    main()
