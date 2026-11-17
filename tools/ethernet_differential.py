"""Validate Ethernet II oracles, with optional installed OctetRail comparisons."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from ethernet_cases import cases

ROOT = Path(__file__).resolve().parents[1]


def probe(python, module, version, payload):
    process = subprocess.run(
        [
            python,
            "-I",
            str(ROOT / "tools/ethernet_probe.py"),
            "--module",
            module,
            "--version",
            version,
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=tempfile.gettempdir(),
        check=True,
        timeout=60,
    )
    return json.loads(process.stdout)


def validate(report, payload):
    assert report["origin_verified"]
    assert report["cases_run"] == len(payload)
    assert set(report["results"]) == {case["id"] for case in payload}
    for case in payload:
        actual = report["results"][case["id"]]
        assert actual == case["expected"], (
            report["module"],
            report["version"],
            case["id"],
            actual,
            case["expected"],
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-196", required=True)
    parser.add_argument("--oracle-198", required=True)
    parser.add_argument("--python", action="append", default=[])
    args = parser.parse_args()
    payload = cases()
    matching = [case for case in payload if case["status"] == "matching"]
    reference_only = [case for case in payload if case["status"] == "reference_only"]
    assert len({case["id"] for case in payload}) == len(payload)
    baselines = [
        probe(args.oracle_196, "dpkt", "1.9.6", payload),
        probe(args.oracle_198, "dpkt", "1.9.8", payload),
    ]
    for report in baselines:
        validate(report, payload)
    assert baselines[0]["results"] == baselines[1]["results"]
    actuals = []
    for python in args.python:
        actual = probe(python, "octetrail", "0.4.1", matching)
        validate(actual, matching)
        for case in matching:
            assert actual["results"][case["id"]] == baselines[0]["results"][case["id"]]
        actuals.append(actual)
    print(
        json.dumps(
            {
                "scope": "Offline Ethernet II, bytes payloads and unsigned wire fields; no nested protocol parsing",
                "declared_cases": len(payload),
                "required_cases_per_provider": len(matching),
                "reference_only_cases_per_oracle": len(reference_only),
                "oracles": "both validated against independent expectations and equal to each other",
                "octetrail": "validated"
                if actuals
                else "pending: no OctetRail interpreter supplied",
                "exception_messages": "not compared; error family and failure phase are compared",
                "case_definition_sha256": hashlib.sha256(
                    (ROOT / "tools/ethernet_cases.py").read_bytes()
                ).hexdigest(),
                "case_payload_sha256": hashlib.sha256(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
                "required_ids": [case["id"] for case in matching],
                "reference_only": [
                    {
                        "id": case["id"],
                        "reason": case["reason"],
                        "observation": baselines[0]["results"][case["id"]],
                    }
                    for case in reference_only
                ],
                "providers": [
                    {key: value for key, value in report.items() if key != "results"}
                    for report in [*baselines, *actuals]
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
