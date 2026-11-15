"""Probe the covered reader surface in an isolated installed environment.

Used by wheel_differential.py with ordinary independently built local captures.
The probe never starts services, opens sockets or writes capture data.
"""

import argparse
import hashlib
import importlib
import importlib.metadata
import importlib.util
import io
import json
import sys
from decimal import ROUND_DOWN, ROUND_HALF_EVEN, Inexact, localcontext
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
    distribution = importlib.metadata.distribution(args.module)
    origin = Path(module.__file__).resolve()
    assert origin.is_relative_to(prefix)
    assert origin == Path(distribution.locate_file(args.module + "/__init__.py")).resolve()
    if args.module == "octetrail":
        assert importlib.util.find_spec("dpkt") is None
        assert Path(module.pcap._native.__file__).resolve().is_relative_to(prefix)
    payload = json.load(sys.stdin)
    captures = []
    for path in payload["paths"]:
        with open(path, "rb") as stream:
            reader = module.pcap.Reader(stream)
            metadata = {
                "snaplen": reader.snaplen,
                "datalink": reader.datalink(),
                "dloff": reader.dloff,
                "filter": reader.filter,
                "name_matches": reader.name == stream.name,
                "fd_matches": reader.fd == reader.fileno() == stream.fileno(),
                "start_position": stream.tell(),
            }
            rows = reader.readpkts()
            assert all(type(data) is bytes for _, data in rows)
            after_eof = list(reader)
            assert not after_eof
        with open(path, "rb") as stream:
            reader = module.pcap.Reader(stream)
            interleaved = []
            for iterator in (iter(reader), reader, iter(reader)):
                try:
                    interleaved.append(next(iterator))
                except StopIteration:
                    break
            interleaved.extend(reader.readpkts())
            assert packed(interleaved) == packed(rows)
        with open(path, "rb") as stream:
            reader = module.pcap.Reader(stream)
            callbacks = []

            def callback(ts, data, label, *, sink=callbacks):
                assert label == "offline"
                sink.append((ts, data))

            processed = reader.dispatch(2, callback, "offline")
            assert processed == min(2, len(rows))
            assert reader.loop(callback, "offline") is None
            assert reader.dispatch(0, callback, "offline") == 0
            assert packed(callbacks) == packed(rows)
            try:
                reader.setfilter("tcp")
            except NotImplementedError:
                pass
            else:
                raise AssertionError("setfilter unexpectedly implemented")
        # A bounded streaming consumer retains only an incremental digest.
        with open(path, "rb") as stream:
            digest, count, total = hashlib.sha256(), 0, 0
            for _, data in module.pcap.Reader(stream):
                digest.update(data)
                count += 1
                total += len(data)
        captures.append(
            {
                "metadata": metadata,
                "records": packed(rows),
                "consumer": [count, total, digest.hexdigest()],
            }
        )

    contexts = []
    for precision in (6, 12, 28):
        for rounding in (ROUND_HALF_EVEN, ROUND_DOWN):
            for trap in (False, True):
                with localcontext() as context:
                    context.prec, context.rounding = precision, rounding
                    context.traps[Inexact] = trap
                    try:
                        reader = module.pcap.Reader(io.BytesIO(bytes.fromhex(payload["nano"])))
                        result = packed(list(reader))
                    except Inexact:
                        result = "Inexact"
                    contexts.append(result)

    errors = []
    for raw in payload["header_errors"]:
        try:
            list(module.pcap.Reader(io.BytesIO(bytes.fromhex(raw))))
        except (module.UnpackError, ValueError) as error:
            errors.append([type(error).__name__, isinstance(error, module.UnpackError)])
        else:
            raise AssertionError("expected a header error")
    try:
        rows = list(module.pcap.Reader(io.BytesIO(bytes.fromhex(payload["short_payload"]))))
        short = {"records": packed(rows)}
    except module.NeedData as error:
        short = {"error": type(error).__name__}
    print(
        json.dumps(
            {
                "captures": captures,
                "decimal_contexts": contexts,
                "header_errors": errors,
                "short_payload": short,
                "origin_verified": True,
            }
        )
    )


if __name__ == "__main__":
    main()
