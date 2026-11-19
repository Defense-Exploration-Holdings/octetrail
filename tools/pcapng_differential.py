"""Measure installed-wheel pcapng behavior against both pinned dpkt references."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from pcapng_fixtures import ROOT, corpus, interface, packet, section


def probe(python, module, version, paths):
    output = subprocess.run(
        [
            python,
            "-I",
            str(ROOT / "tools/pcapng_probe.py"),
            "--module",
            module,
            "--version",
            version,
        ],
        input=json.dumps(paths),
        text=True,
        capture_output=True,
        check=True,
        cwd=tempfile.gettempdir(),
    )
    return json.loads(output.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True)
    parser.add_argument("--oracle-198", required=True)
    parser.add_argument("--oracle-196", required=True)
    args = parser.parse_args()
    cases = corpus()
    with tempfile.TemporaryDirectory(prefix="octetrail-pcapng-compare-") as directory:
        paths = []
        for number, (raw, _, _, _) in enumerate(cases):
            path = Path(directory) / f"case-{number}.pcapng"
            path.write_bytes(raw)
            paths.append(str(path))
        actual = probe(args.python, "octetrail", "1.0.0", paths)
        for result, (_, records, snaplen, linktype) in zip(actual["captures"], cases, strict=True):
            assert result["records"] == records
            offset = {1: 14, 113: 16}.get(linktype, 0)
            assert result["metadata"] == [snaplen, linktype, offset, "", True, True]
            payloads = [bytes.fromhex(row[2]) for row in records]
            assert result["consumer"] == [
                len(records),
                sum(map(len, payloads)),
                hashlib.sha256(b"".join(payloads)).hexdigest(),
            ]
        for version, python in (("1.9.8", args.oracle_198), ("1.9.6", args.oracle_196)):
            assert actual == probe(python, "dpkt", version, paths), (
                f"pcapng subset differs from dpkt {version}"
            )

        # A valid second interface has its own clock. Both baselines use only
        # the first interface's timing. This ordinary correctness boundary is
        # reported separately and is not counted as matching coverage.
        mixed = (
            section()
            + interface()
            + interface(resolution=0x8A, offset=-2)
            + packet(ticks=1_250_000, data=b"one")
            + packet(interface_id=1, ticks=1024, data=b"two")
        )
        path = Path(directory) / "two-interface-clocks.pcapng"
        path.write_bytes(mixed)
        expected = [["1.25", "float", b"one".hex()], ["-1.0", "float", b"two".hex()]]
        assert (
            probe(args.python, "octetrail", "1.0.0", [str(path)])["captures"][0]["records"]
            == expected
        )
        for version, python in (("1.9.8", args.oracle_198), ("1.9.6", args.oracle_196)):
            rows = probe(python, "dpkt", version, [str(path)])["captures"][0]["records"]
            assert rows == [["1.25", "float", b"one".hex()], ["0.001024", "float", b"two".hex()]]
    print(
        json.dumps(
            {
                "format": "pcapng Enhanced Packet Blocks",
                "valid_matching_captures": len(cases),
                "matching_packets_per_reference": sum(len(case[1]) for case in cases),
                "references": ["dpkt 1.9.8", "dpkt 1.9.6"],
                "origin_verified": True,
                "reader_methods_and_streaming_consumer": "matched",
                "explicit_difference": "second interface clock: -1.0 seconds versus dpkt 0.001024",
                "corpus_sha256": hashlib.sha256(b"".join(case[0] for case in cases)).hexdigest(),
                "multiple_sections": "independent expected values only; not differential parity",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
