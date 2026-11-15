"""Exercise writer semantics in one isolated installed distribution."""

import argparse
import importlib
import importlib.metadata
import importlib.util
import io
import json
import sys
from decimal import ROUND_DOWN, ROUND_HALF_EVEN, Decimal, Inexact, localcontext
from pathlib import Path
from unittest.mock import patch


def timestamp(value):
    kind, text = value["kind"], value["value"]
    return {"int": int, "float": float, "decimal": Decimal, "clock": float}[kind](text)


class Packet:
    def __init__(self, data):
        self.data, self.calls = data, 0

    def __bytes__(self):
        self.calls += 1
        return self.data


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
    if args.module == "octetrail":
        assert importlib.util.find_spec("dpkt") is None
        assert (
            Path(module.pcap._native.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
        )
    results = []
    for case in json.load(sys.stdin):
        stream = io.BytesIO()
        writer = module.pcap.Writer(stream, **case["config"])
        returns = []
        if case["method"] == "writepkts":
            returns.append(
                writer.writepkts(
                    (timestamp(row["timestamp"]), bytes.fromhex(row["hex"]))
                    for row in case["events"]
                )
            )
        else:
            for row in case["events"]:
                data = bytes.fromhex(row["hex"])
                ts = timestamp(row["timestamp"])
                if case["method"] == "writepkt":
                    kind = row["conversion"]
                    data = {
                        "bytes": bytes,
                        "bytearray": bytearray,
                        "memoryview": memoryview,
                        "object": Packet,
                    }[kind](data)
                    if row["timestamp"]["kind"] == "clock":
                        with patch.object(module.pcap.time, "time", return_value=ts) as clock:
                            returns.append(writer.writepkt(data))
                        clock.assert_called_once()
                    else:
                        returns.append(writer.writepkt(data, ts))
                    if isinstance(data, Packet):
                        assert data.calls == 1
                else:
                    returns.append(writer.writepkt_time(data, ts))
        raw = stream.getvalue()
        decoded = [
            [str(ts), type(ts).__name__, data.hex()]
            for ts, data in module.pcap.Reader(io.BytesIO(raw))
        ]
        writer.close()
        assert stream.closed and all(value is None for value in returns)
        results.append(
            {"hex": raw.hex(), "readback": decoded, "returns_none": True, "closed": True}
        )

    contexts = []
    for nano in (False, True):
        for precision in (6, 12, 28):
            for rounding in (ROUND_DOWN, ROUND_HALF_EVEN):
                for trap in (False, True):
                    stream = io.BytesIO()
                    writer = module.pcap.Writer(stream, nano=nano)
                    with localcontext() as context:
                        context.prec, context.rounding, context.traps[Inexact] = (
                            precision,
                            rounding,
                            trap,
                        )
                        try:
                            writer.writepkt_time(b"context", Decimal("1.123456789"))
                            error = None
                        except Inexact:
                            error = "Inexact"
                    contexts.append({"hex": stream.getvalue().hex(), "error": error})
                    writer.close()

    carries = []
    for nano, value in ((False, "1.9999999"), (True, "1.9999999999")):
        stream = io.BytesIO()
        writer = module.pcap.Writer(stream, nano=nano)
        try:
            writer.writepkt_time(b"a", Decimal(value))
            error = None
        except ValueError:
            error = "ValueError"
        carries.append({"hex": stream.getvalue().hex(), "error": error})
        writer.close()
    print(
        json.dumps(
            {
                "origin_verified": True,
                "captures": results,
                "decimal_contexts": contexts,
                "rounding_carries": carries,
            }
        )
    )


if __name__ == "__main__":
    main()
