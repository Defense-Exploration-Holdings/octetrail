"""Compare valid writer bytes and semantics with both baselines and independent fields."""

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

from pcap_writer_cases import cases, decode_capture, expected_bytes

ROOT = Path(__file__).resolve().parents[1]


def probe(python, module, version, payload):
    result = subprocess.run(
        [
            python,
            "-I",
            str(ROOT / "tools/pcap_writer_probe.py"),
            "--module",
            module,
            "--version",
            version,
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=True,
        cwd=tempfile.gettempdir(),
    )
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True)
    parser.add_argument("--oracle-198", required=True)
    parser.add_argument("--oracle-196", required=True)
    args = parser.parse_args()
    payload = cases()
    actual = probe(args.python, "octetrail", "0.6.1", payload)
    outputs = []
    for result, case in zip(actual["captures"], payload, strict=True):
        raw = bytes.fromhex(result["hex"])
        assert raw == expected_bytes(case)
        fields = decode_capture(raw)
        assert fields["snaplen"] == case["config"].get("snaplen", 1500)
        assert fields["linktype"] == case["config"].get("linktype", 1)
        assert fields["records"] == [
            [row["seconds"], row["fraction"], len(bytes.fromhex(row["hex"])), row["hex"]]
            for row in case["events"]
        ]
        outputs.append(raw)
    covered = {key: value for key, value in actual.items() if key != "rounding_carries"}
    for version, python in (("1.9.8", args.oracle_198), ("1.9.6", args.oracle_196)):
        reference = probe(python, "dpkt", version, payload)
        carries = reference.pop("rounding_carries")
        assert covered == reference, f"writer subset mismatch with dpkt {version}"
        for nano, difference, baseline in zip(
            (False, True), actual["rounding_carries"], carries, strict=True
        ):
            raw = bytes.fromhex(difference["hex"])
            assert difference["error"] == "ValueError" and len(raw) == 24
            assert decode_capture(raw)["records"] == []
            raw = bytes.fromhex(baseline["hex"])
            assert baseline["error"] is None
            order = "<" if raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
            assert struct.unpack_from(order + "IIII", raw, 24) == (
                1,
                1_000_000_000 if nano else 1_000_000,
                1,
                1,
            )
    print(
        json.dumps(
            {
                "format": "classic pcap writer",
                "matching_captures": len(payload),
                "matching_records_per_reference": sum(len(case["events"]) for case in payload),
                "references": ["dpkt 1.9.8", "dpkt 1.9.6"],
                "origin_verified": True,
                "independent_oracle": "explicit wire components, struct decoder and reviewed Rust byte fixtures",
                "decimal_context_combinations": len(actual["decimal_contexts"]),
                "explicit_difference": "fractional rounding carry rejected before record output; dpkt writes a full-scale fraction",
                "output_corpus_sha256": hashlib.sha256(b"".join(outputs)).hexdigest(),
                "python_byte_order": "host order only; Rust tests cover both orders",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
