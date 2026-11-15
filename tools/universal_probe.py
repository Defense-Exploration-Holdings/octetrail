"""Observe selection behavior in one isolated installed provider environment."""

import argparse
import importlib
import importlib.metadata
import importlib.util
import io
import json
import platform
import sys
from pathlib import Path


def observe(provider, case):
    class Traced(io.BytesIO):
        name = "synthetic.capture"

        def __init__(self):
            super().__init__(bytes.fromhex(case["hex"]))
            self.seeks = []
            self.read_calls = 0
            self.failure = None
            if case["mode"] == "read_os_error":
                self.failure = OSError("synthetic read failure")
            elif case["mode"] == "seek_value_error":
                self.failure = ValueError("synthetic seek failure")
            elif case["mode"] == "second_read_os_error":
                self.failure = OSError("synthetic second read failure")

        def read(self, count):
            self.read_calls += 1
            mode = case["mode"]
            if mode == "read_os_error":
                raise self.failure
            if mode == "two_read_value_errors":
                raise ValueError("first read" if self.read_calls == 1 else "second read")
            if mode in ("read_value_recovery", "second_read_os_error") and self.read_calls == 1:
                raise ValueError("first read")
            if mode == "second_read_os_error":
                raise self.failure
            return super().read(count)

        def seek(self, offset, whence=0):
            self.seeks.append([offset, whence])
            if case["mode"] == "seek_value_error":
                raise self.failure
            return super().seek(offset, whence)

    source = Traced()
    io.BytesIO.seek(source, case.get("start", 0))

    class ReadOnly:
        name = source.name
        read = source.read

    argument = ReadOnly() if case.get("nonseekable") else source
    reader = None
    rows = []
    phase = "constructor"
    result = {}
    factory = provider.pcap.UniversalReader
    if case["mode"] == "subclass":

        class Selected(factory):
            pass

        factory = Selected
    try:
        reader = factory(argument)
        assert type(reader) in (provider.pcap.Reader, provider.pcapng.Reader)
        assert not isinstance(reader, factory)
        result.update(
            {
                "format": "pcap" if type(reader) is provider.pcap.Reader else "pcapng",
                "metadata": [
                    reader.name,
                    reader.snaplen,
                    reader.datalink(),
                    reader.dloff,
                    reader.filter,
                ],
                "constructor_position": source.tell(),
            }
        )
        phase = "iteration"

        def collect(timestamp, data, label="offline"):
            assert label == "offline" and type(data) is bytes
            rows.append([str(timestamp), type(timestamp).__name__, data.hex()])

        if case["mode"] == "dispatch":
            count = reader.dispatch(1, collect, "offline")
            assert type(count) is int and count == len(rows) <= 1
            result["dispatch_count"] = count
            assert reader.loop(collect, "offline") is None
        elif case["mode"] == "interleave":
            for iterator in (iter(reader), reader, iter(reader)):
                try:
                    collect(*next(iterator))
                except StopIteration:
                    break
            for packet in reader.readpkts():
                collect(*packet)
        elif case.get("first_only"):
            collect(*next(reader))
        else:
            for packet in reader:
                collect(*packet)
        if not case.get("first_only"):
            assert reader.readpkts() == []
        result["outcome"] = "ok"
    except (ValueError, OSError, AttributeError, provider.NeedData) as error:
        result.update(
            {
                "outcome": "error",
                "error": type(error).__name__,
                "phase": phase,
                "message": str(error),
                "same_exception": error is source.failure,
            }
        )
        if case["mode"] == "two_read_value_errors":
            result["context"] = str(error.__context__)
            result["cause"] = error.__cause__ is None
            result["context_suppressed"] = error.__suppress_context__
    result.update(
        {
            "rows": rows,
            "position": source.tell(),
            "seeks": source.seeks,
            "source_closed": source.closed,
        }
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", choices=("dpkt", "octetrail"), required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    assert sys.flags.isolated and sys.prefix != sys.base_prefix
    provider = importlib.import_module(args.module)
    distribution = importlib.metadata.distribution(args.module)
    assert distribution.version == args.version
    prefix = Path(sys.prefix).resolve()
    for module in (provider, provider.pcap, provider.pcapng):
        assert Path(module.__file__).resolve().is_relative_to(prefix)
    assert (
        Path(provider.__file__).resolve()
        == Path(distribution.locate_file(args.module + "/__init__.py")).resolve()
    )
    if args.module == "octetrail":
        assert importlib.util.find_spec("dpkt") is None
        assert Path(provider.pcap._native.__file__).resolve().is_relative_to(prefix)
    payload = json.load(sys.stdin)
    available = hasattr(provider.pcap, "UniversalReader")
    if not available:
        try:
            _ = provider.pcap.UniversalReader
        except AttributeError:
            pass
        else:
            raise AssertionError("absent factory unexpectedly resolved")
    results = {case["id"]: observe(provider, case) for case in payload} if available else {}
    print(
        json.dumps(
            {
                "module": args.module,
                "version": args.version,
                "python": platform.python_version(),
                "available": available,
                "origin_verified": True,
                "provider_file": str(Path(provider.pcap.__file__).relative_to(prefix)),
                "cases_run": len(results),
                "results": results,
            }
        )
    )


if __name__ == "__main__":
    main()
