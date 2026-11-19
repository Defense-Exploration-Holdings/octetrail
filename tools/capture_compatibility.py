"""Run only the manifest's eligible offline consumer scenarios against providers.

Two isolated dpkt reference processes and explicitly selected OctetRail test-map
processes load exactly the same project-authored consumer source. Ineligible
scenarios are reported, never converted into passing or silently skipped tests.
"""

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from pcap_writer_cases import decode_capture as decode_pcap
from pcapng_writer_cases import decode_capture as decode_pcapng

ROOT = Path(__file__).resolve().parents[1]


def fixtures():
    def literal(name):
        return bytes.fromhex((ROOT / "tests/fixtures" / name).read_text())

    micro, nano = literal("little-micro.hex"), literal("big-nano.hex")
    ng, custom = literal("pcapng-little.hex"), literal("pcapng-big-nano.hex")
    return {
        "pcap_micro": (micro, [["1.25", "float", b"abc"], ["2.0", "float", b""]]),
        "pcap_nano": (nano, [["1700000000.123456789", "Decimal", b"rail"]]),
        "pcapng_micro": (ng, [["1.25", "float", b"abc"]]),
        "pcapng_custom": (custom, [["-0.75", "float", b"rail"]]),
        "pcap_empty": (micro[:24], []),
        "pcapng_empty": (ng[:48], []),
        "pcap_record_short": (micro[:30], []),
        "pcapng_trailer_short": (ng[:-1], []),
    }


def copy_expectation(case, rows):
    """Explicit field expectations, not output from either capture library."""
    order = "<" if sys.byteorder == "little" else ">"
    if case["format"] == "pcap":
        magic = 0xA1B23C4D if case["nano"] else 0xA1B2C3D4
        raw = struct.pack(order + "IHHIIII", magic, 2, 4, 0, 0, 64, 147)
        components = {
            "1.25": (1, 250_000),
            "2.0": (2, 0),
            "1700000000.123456789": (1_700_000_000, 123_456_789),
        }
        for timestamp, _, data in rows:
            seconds, fraction = components[timestamp]
            raw += struct.pack(order + "IIII", seconds, fraction, len(data), len(data)) + data
        assert len(decode_pcap(raw)["records"]) == len(rows)
        return raw
    raw = struct.pack(order + "IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28) + struct.pack(
        order + "IIHHII", 1, 20, 147, 0, 64, 20
    )
    for timestamp, _, data in rows:
        assert timestamp == "1.25"
        padded = data + b"\0" * (-len(data) % 4)
        length = 32 + len(padded)
        raw += struct.pack(order + "IIIIIII", 6, length, 0, 0, 1_250_000, len(data), len(data))
        raw += padded + struct.pack(order + "I", length)
    assert len(decode_pcapng(raw)["records"]) == len(rows)
    return raw


def run(python, backend, version, payload):
    completed = subprocess.run(
        [
            python,
            "-I",
            str(ROOT / "tools/capture_consumer_probe.py"),
            "--backend",
            backend,
            "--version",
            version,
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=True,
        cwd=tempfile.gettempdir(),
    )
    return json.loads(completed.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python", required=True, action="append", help="fresh installed-wheel environment"
    )
    parser.add_argument("--oracle-198", required=True)
    parser.add_argument("--oracle-196", required=True)
    args = parser.parse_args()
    manifest = json.loads((ROOT / "tests/consumers/eligibility.json").read_text())
    scenarios = manifest["scenarios"]
    assert manifest["schema_version"] == 1 and len({case["id"] for case in scenarios}) == len(
        scenarios
    )
    eligible = [case for case in scenarios if case["status"] == "eligible"]
    ineligible = [case for case in scenarios if case["status"] == "ineligible"]
    assert len(eligible) == 19 and len(ineligible) == 11
    assert all(case.get("reason") for case in ineligible)
    corpus = fixtures()
    providers = [("dpkt", "1.9.8", args.oracle_198), ("dpkt", "1.9.6", args.oracle_196)]
    providers += [("octetrail-test-map", "1.0.0", python) for python in args.python]
    reports, reference = [], None
    with tempfile.TemporaryDirectory(prefix="octetrail-capture-consumer-") as directory:
        paths = {}
        for name, (raw, _) in corpus.items():
            path = Path(directory) / (name + ".capture")
            path.write_bytes(raw)
            paths[name] = str(path)
        for index, (backend, version, python) in enumerate(providers):
            output = Path(directory) / f"run-{index}"
            output.mkdir()
            payload = [
                dict(
                    case,
                    input=paths[case["fixture"]],
                    output=str(output / (case["id"] + ".capture")),
                )
                for case in eligible
            ]
            report = run(python, backend, version, payload)
            assert report["origin_verified"] and report["byte_order"] == sys.byteorder
            assert (
                report["consumer_sha256"]
                == hashlib.sha256(
                    (ROOT / "tests/consumers/capture_consumer.py").read_bytes()
                ).hexdigest()
            )
            assert set(report["results"]) == {case["id"] for case in eligible}
            assert report["constants"] == {
                "pcap": [0, 1, 113, 147, 2, 4, 0xA1B2C3D4, 0xA1B23C4D],
                "pcapng": [0, 1, 113, 1, 0, 0x0A0D0D0A, 1, 6],
            }
            for case in eligible:
                actual = report["results"][case["id"]]
                if case["operation"] == "error":
                    assert actual == {
                        "error": "NeedData",
                        "unpack_family": True,
                        "root_family": True,
                    }
                    continue
                rows = corpus[case["fixture"]][1]
                expected = {
                    "metadata": [64, 147, 0, "", True, True],
                    "rows": [[timestamp, kind, len(data)] for timestamp, kind, data in rows],
                    "payload_sha256": hashlib.sha256(b"".join(row[2] for row in rows)).hexdigest(),
                }
                if case["operation"] == "dispatch":
                    expected["dispatch_count"] = min(1, len(rows))
                if case["operation"] == "copy":
                    raw = bytes.fromhex(actual["output_hex"])
                    assert raw == copy_expectation(case, rows)
                    (decode_pcap if case["format"] == "pcap" else decode_pcapng)(raw)
                    expected["output_hex"] = raw.hex()
                assert actual == expected, case["id"]
            semantic = {"results": report["results"], "constants": report["constants"]}
            if reference is None:
                reference = semantic
            else:
                assert semantic == reference, f"consumer mismatch for {backend} {version}"
            reports.append(
                {
                    key: report[key]
                    for key in (
                        "backend",
                        "distribution_version",
                        "python",
                        "provider_file",
                        "mapping_restored",
                    )
                }
            )
    print(
        json.dumps(
            {
                "scope": "curated project consumer, not upstream tests",
                "declared_scenarios": len(scenarios),
                "eligible_checks_per_run": len(eligible),
                "ineligible_not_executed": len(ineligible),
                "checks_by_operation": dict(Counter(case["operation"] for case in eligible)),
                "selected_constants": 16,
                "consumer_sha256": hashlib.sha256(
                    (ROOT / "tests/consumers/capture_consumer.py").read_bytes()
                ).hexdigest(),
                "fixture_corpus_sha256": hashlib.sha256(
                    b"".join(corpus[name][0] for name in sorted(corpus))
                ).hexdigest(),
                "eligibility_manifest_sha256": hashlib.sha256(
                    (ROOT / "tests/consumers/eligibility.json").read_bytes()
                ).hexdigest(),
                "runs": reports,
                "ineligible_ids": [case["id"] for case in ineligible],
                "distribution_resolution": "unchanged; no dpkt metadata provided by the test map",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
