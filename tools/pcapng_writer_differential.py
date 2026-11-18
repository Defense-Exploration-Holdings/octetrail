"""Check offline writer bytes, options and the covered API against two references."""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from pcapng_writer_cases import cases, decode_capture, expected_bytes, metadata_options

ROOT = Path(__file__).resolve().parents[1]


def probe(python, module, version, payload):
    result = subprocess.run(
        [
            python,
            "-I",
            str(ROOT / "tools/pcapng_writer_probe.py"),
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
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True)
    parser.add_argument("--oracle-198", required=True)
    parser.add_argument("--oracle-196", required=True)
    args = parser.parse_args()
    payload = cases()
    actual = probe(args.python, "octetrail", "0.6.2", payload)
    outputs = []
    for result, case in zip(actual["captures"], payload, strict=True):
        raw = bytes.fromhex(result["hex"])
        assert raw == expected_bytes(case)
        decoded = decode_capture(raw)
        config = case["config"]
        shb, idb = metadata_options(config, "<" if sys.byteorder == "little" else ">")
        assert decoded == {
            "snaplen": config.get("snaplen", 1500),
            "linktype": config.get("linktype", 1),
            "section_options": [[code, value.hex()] for code, value in shb],
            "interface_options": [[code, value.hex()] for code, value in idb],
            "records": [
                [row["ticks"], len(bytes.fromhex(row["hex"])), row["hex"]] for row in case["events"]
            ],
        }
        outputs.append(raw)
    for version, python in (("1.9.8", args.oracle_198), ("1.9.6", args.oracle_196)):
        assert actual == probe(python, "dpkt", version, payload), (
            f"PCAPNG output differs from dpkt {version}"
        )
    seconds = [case for case in payload if case["method"] != "writepkt_ticks"]
    ticks = [case for case in payload if case["method"] == "writepkt_ticks"]
    print(
        json.dumps(
            {
                "format": "pcapng single-section single-interface EPBs",
                "byte_matching_captures": len(payload),
                "byte_matching_records_per_reference": sum(len(case["events"]) for case in payload),
                "seconds_api_captures": len(seconds),
                "seconds_api_records": sum(len(case["events"]) for case in seconds),
                "raw_tick_option_captures": len(ticks),
                "raw_tick_option_records": sum(len(case["events"]) for case in ticks),
                "references": ["dpkt 1.9.8", "dpkt 1.9.6"],
                "origin_verified": True,
                "independent_oracle": "explicit ticks, struct encoder/decoder and reviewed hex fixtures",
                "custom_clock_api": "explicit ticks; reference EPB objects are comparison controls, not an implemented block API",
                "output_corpus_sha256": hashlib.sha256(b"".join(outputs)).hexdigest(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
