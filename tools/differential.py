"""Offline classic-pcap comparison with a separately installed published dpkt.

No network calls, upstream writer, or third-party test dependencies are used.
Install the oracle from a hash-pinned requirement in a separate venv first.
"""

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORACLE = r"""
from decimal import Decimal
import dpkt
import importlib.metadata
import json
from pathlib import Path
import sys

assert sys.prefix != sys.base_prefix, "oracle requires its own virtual environment"
version = importlib.metadata.version("dpkt")
assert version == sys.argv[1], (version, sys.argv[1])
origin = Path(dpkt.__file__).resolve()
prefix = Path(sys.prefix).resolve()
assert origin.is_relative_to(prefix), "dpkt import is outside the oracle environment"
distribution = importlib.metadata.distribution("dpkt")
assert origin == Path(distribution.locate_file("dpkt/__init__.py")).resolve()
result = []
for path in json.load(sys.stdin):
    with open(path, "rb") as stream:
        reader = dpkt.pcap.Reader(stream)
        result.append({
            "snaplen": reader.snaplen,
            "linktype": reader.datalink(),
            "records": [{"time": str(ts), "type": type(ts).__name__, "hex": data.hex()}
                        for ts, data in reader],
        })
print(json.dumps({"version": version, "origin_verified": True, "captures": result}))
"""


def capture(order, nano, records):
    """Independent encoder using explicit format fields, never a capture writer."""
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    data = struct.pack(order + "IHHIIII", magic, 2, 4, 0, 0, 64, 147)
    for seconds, fraction, payload, original in records:
        data += struct.pack(order + "IIII", seconds, fraction, len(payload), original)
        data += payload
    return data


def run_native(binary, path, *options):
    return subprocess.run(
        [str(binary), *options, str(path)],
        text=True,
        capture_output=True,
        check=False,
    )


def compare(binary, python, version):
    cases = []
    for order in ("<", ">"):
        for nano in (False, True):
            ticks = 1_000_000_000 if nano else 1_000_000
            for records in (
                [],
                [(0, 0, b"", 0)],
                [(1, ticks // 4, b"abc", 5), (2, 0, b"", 0)],
                [(1_700_000_000, 123_456_789 if nano else 123_456, b"rail", 4)],
                [(0, 1, b"\x00\x01\x02", 3)],
                [(0xFFFFFFFF, ticks - 1, bytes(range(64)), 64)],
                [(n, n, b"sample", 6) for n in range(100)],
            ):
                cases.append((capture(order, nano, records), order, nano, records))

    # Independently reviewed literals also carry explicit expected values.
    cases.extend(
        [
            (
                bytes.fromhex((ROOT / "tests/fixtures/little-micro.hex").read_text()),
                "<",
                False,
                [(1, 250_000, b"abc", 5), (2, 0, b"", 0)],
            ),
            (
                bytes.fromhex((ROOT / "tests/fixtures/big-nano.hex").read_text()),
                ">",
                True,
                [(1_700_000_000, 123_456_789, b"rail", 4)],
            ),
        ]
    )

    with tempfile.TemporaryDirectory(prefix="octetrail-differential-") as directory:
        paths = []
        for index, (data, _, _, _) in enumerate(cases):
            path = Path(directory) / f"case-{index}.pcap"
            path.write_bytes(data)
            paths.append(path)

        reference = subprocess.run(
            [python, "-I", "-c", ORACLE, version],
            input=json.dumps([str(path) for path in paths]),
            text=True,
            capture_output=True,
            check=True,
        )
        evidence = json.loads(reference.stdout)
        assert evidence["version"] == version and evidence["origin_verified"]
        packet_count = 0
        for case, path, expected in zip(cases, paths, evidence["captures"], strict=True):
            _, order, nano, records = case
            result = run_native(binary, path)
            assert result.returncode == 0, result.stderr
            header, *actual = [json.loads(line) for line in result.stdout.splitlines()]
            assert header == {
                "snaplen": 64,
                "linktype": 147,
                "byte_order": "little" if order == "<" else "big",
                "resolution": "nanoseconds" if nano else "microseconds",
            }
            assert (expected["snaplen"], expected["linktype"]) == (64, 147)
            assert len(actual) == len(expected["records"]) == len(records)
            for native, oracle, (seconds, fraction, payload, original) in zip(
                actual, expected["records"], records, strict=True
            ):
                assert native == {
                    "seconds": seconds,
                    "fraction": fraction,
                    "original_len": original,
                    "hex": payload.hex(),
                }
                assert native["hex"] == oracle["hex"]
                if nano:
                    timestamp = seconds + fraction / Decimal("1E9")
                    assert oracle["type"] == "Decimal"
                    assert timestamp == Decimal(oracle["time"])
                else:
                    timestamp = seconds + fraction / 1e6
                    assert oracle["type"] == "float"
                    assert timestamp == float(oracle["time"])
                packet_count += 1

        # Published dpkt yields short payloads; the strict native reader rejects.
        short = Path(directory) / "short.pcap"
        short.write_bytes(capture("<", False, [(1, 0, b"abc", 3)])[:-1])
        result = run_native(binary, short)
        assert result.returncode != 0 and "truncated packet payload" in result.stderr
        reference = subprocess.run(
            [python, "-I", "-c", ORACLE, version],
            input=json.dumps([str(short)]),
            text=True,
            capture_output=True,
            check=True,
        )
        short_record = json.loads(reference.stdout)["captures"][0]["records"][0]
        assert short_record["hex"] == b"ab".hex()

        # CLI resource policy, error propagation and usage are also exercised.
        result = run_native(binary, paths[2], "--max-packet-bytes", "2")
        assert result.returncode != 0 and "packet limit 2" in result.stderr
        bad_args = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
        assert bad_args.returncode != 0 and "usage:" in bad_args.stderr

    corpus_hash = hashlib.sha256(b"".join(case[0] for case in cases)).hexdigest()
    print(
        json.dumps(
            {
                "reference": f"dpkt {version}",
                "origin_verified": True,
                "valid_captures": len(cases),
                "compared_packets": packet_count,
                "corpus_sha256": corpus_hash,
                "measured_differences": [
                    "truncated payload: native rejects, dpkt yields short bytes"
                ],
                "python_api_parity": "not tested; native CLI only",
            },
            indent=2,
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, help="oracle virtualenv Python executable")
    parser.add_argument("--version", choices=("1.9.8", "1.9.6"), default="1.9.8")
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/pcap-read")
    options = parser.parse_args()
    compare(options.binary.resolve(), options.python, options.version)


if __name__ == "__main__":
    main()
