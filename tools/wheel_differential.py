"""Compare an installed OctetRail wheel with both isolated pinned dpkt versions."""

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: only release tooling reads TOML.
    tomllib = None
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def encode(order, nano, records, linktype):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    result = struct.pack(order + "IHHIIII", magic, 2, 4, 0, 0, 64, linktype)
    for seconds, fraction, data in records:
        result += struct.pack(order + "IIII", seconds, fraction, len(data), len(data)) + data
    return result


def probe(python, module, version, payload):
    completed = subprocess.run(
        [
            python,
            "-I",
            str(ROOT / "tools/reader_probe.py"),
            "--module",
            module,
            "--version",
            version,
        ],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
        cwd=tempfile.gettempdir(),
    )
    return json.loads(completed.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python", required=True, help="fresh environment with the installed wheel"
    )
    parser.add_argument("--oracle-198", required=True)
    parser.add_argument("--oracle-196", required=True)
    args = parser.parse_args()
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    cases = []
    for order in ("<", ">"):
        for nano in (False, True):
            ticks = 1_000_000_000 if nano else 1_000_000
            for linktype in (1, 113, 147, 276):
                for rows in (
                    [],
                    [(0, 0, b"")],
                    [(1, ticks // 4, b"abc"), (2, 0, b"")],
                    [(0, 1, b"one"), (0xFFFFFFFF, ticks - 1, bytes(range(64)))],
                    [(n, n, b"row:" + n.to_bytes(2, "big")) for n in range(257)],
                ):
                    cases.append((encode(order, nano, rows, linktype), nano, rows))
    cases.extend(
        [
            (
                bytes.fromhex((ROOT / "tests/fixtures/little-micro.hex").read_text()),
                False,
                [(1, 250_000, b"abc"), (2, 0, b"")],
            ),
            (
                bytes.fromhex((ROOT / "tests/fixtures/big-nano.hex").read_text()),
                True,
                [(1_700_000_000, 123_456_789, b"rail")],
            ),
        ]
    )
    with tempfile.TemporaryDirectory(prefix="octetrail-wheel-compare-") as directory:
        paths = []
        for number, (raw, _, _) in enumerate(cases):
            path = Path(directory) / f"case-{number}.pcap"
            path.write_bytes(raw)
            paths.append(str(path))
        ordinary = encode("<", False, [(1, 0, b"abc")], 147)
        nano = encode(">", True, [(1_700_000_000, 123_456_789, b"rail")], 147)
        unknown_magic = b"none" + ordinary[4:24]
        payload = {
            "paths": paths,
            "nano": nano.hex(),
            "short_payload": ordinary[:-1].hex(),
            "header_errors": [ordinary[:10].hex(), ordinary[:30].hex(), unknown_magic.hex()],
        }
        actual = probe(args.python, "octetrail", version, payload)
        assert actual["origin_verified"]
        assert actual["short_payload"] == {"error": "NeedData"}
        packet_count = 0
        for (_, nano, rows), result in zip(cases, actual["captures"], strict=True):
            divisor = Decimal("1E9") if nano else 1e6
            assert result["records"] == [
                [str(seconds + fraction / divisor), "Decimal" if nano else "float", data.hex()]
                for seconds, fraction, data in rows
            ]
            assert result["consumer"] == [
                len(rows),
                sum(len(row[2]) for row in rows),
                hashlib.sha256(b"".join(row[2] for row in rows)).hexdigest(),
            ]
            packet_count += len(rows)
        covered = {key: value for key, value in actual.items() if key != "short_payload"}
        for version, python in (("1.9.8", args.oracle_198), ("1.9.6", args.oracle_196)):
            reference = probe(python, "dpkt", version, payload)
            assert reference["short_payload"] == {"records": [["1.0", "float", b"ab".hex()]]}
            reference.pop("short_payload")
            assert covered == reference, f"reader subset mismatch with dpkt {version}"
    print(
        json.dumps(
            {
                "valid_captures": len(cases),
                "compared_packets_per_reference": packet_count,
                "references": ["dpkt 1.9.8", "dpkt 1.9.6"],
                "decimal_context_combinations": 12,
                "covered_header_error_cases": 3,
                "origin_verified": True,
                "streaming_consumer": "packet count, total bytes and SHA-256 matched for each capture",
                "intentional_difference": "truncated payload: NeedData versus short bytes",
                "corpus_sha256": hashlib.sha256(b"".join(case[0] for case in cases)).hexdigest(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
