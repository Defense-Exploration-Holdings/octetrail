"""Read only the covered pcapng subset from an isolated installed distribution."""

import argparse
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import sys
from pathlib import Path


def packed(records):
    return [[str(ts), type(ts).__name__, data.hex()] for ts, data in records]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", choices=("octetrail", "dpkt"), required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    module = importlib.import_module(args.module)
    assert sys.flags.isolated and sys.prefix != sys.base_prefix
    assert importlib.metadata.version(args.module) == args.version
    prefix = Path(sys.prefix).resolve()
    origin = Path(module.__file__).resolve()
    assert origin.is_relative_to(prefix)
    assert (
        origin
        == Path(
            importlib.metadata.distribution(args.module).locate_file(args.module + "/__init__.py")
        ).resolve()
    )
    if args.module == "octetrail":
        assert importlib.util.find_spec("dpkt") is None
        assert Path(module.pcapng._native.__file__).resolve().is_relative_to(prefix)
    result = []
    for path in json.load(sys.stdin):
        with open(path, "rb") as stream:
            reader = module.pcapng.Reader(stream)
            metadata = [
                reader.snaplen,
                reader.datalink(),
                reader.dloff,
                reader.filter,
                reader.name == stream.name,
                reader.fd == reader.fileno() == stream.fileno(),
            ]
            records = reader.readpkts()
            assert all(type(data) is bytes and type(ts) is float for ts, data in records)
            assert list(reader) == []
        with open(path, "rb") as stream:
            reader = module.pcapng.Reader(stream)
            shared = []
            for iterator in (iter(reader), reader, iter(reader)):
                try:
                    shared.append(next(iterator))
                except StopIteration:
                    break
            shared.extend(reader.readpkts())
            assert packed(shared) == packed(records)
        with open(path, "rb") as stream:
            reader = module.pcapng.Reader(stream)
            callbacks = []

            def collect(ts, data, label, *, sink=callbacks):
                assert label == "offline"
                sink.append((ts, data))

            assert reader.dispatch(2, collect, "offline") == min(2, len(records))
            assert reader.loop(collect, "offline") is None
            assert packed(callbacks) == packed(records)
            try:
                reader.setfilter("tcp")
            except NotImplementedError:
                pass
            else:
                raise AssertionError("unexpected filter implementation")
        digest, count, total = hashlib.sha256(), 0, 0
        with open(path, "rb") as stream:
            for _, data in module.pcapng.Reader(stream):
                digest.update(data)
                count += 1
                total += len(data)
        result.append(
            {
                "metadata": metadata,
                "records": packed(records),
                "consumer": [count, total, digest.hexdigest()],
            }
        )
    print(json.dumps({"origin_verified": True, "captures": result}))


if __name__ == "__main__":
    main()
