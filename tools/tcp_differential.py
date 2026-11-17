"""Compare TCP headers, options and payloads with both pinned dpkt versions."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from tcp_cases import cases

ROOT = Path(__file__).resolve().parents[1]


class ComparisonError(ValueError):
    """A comparison or its provenance failed validation."""


def require(condition, message):
    if not condition:
        raise ComparisonError(message)


def probe(python, module, version, payload):
    process = subprocess.run(
        [python, "-I", str(ROOT / "tools/tcp_probe.py"), "--module", module, "--version", version],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=tempfile.gettempdir(),
        check=True,
        timeout=60,
    )
    return json.loads(process.stdout)


def validate(report, payload):
    require(report["origin_verified"] is True, "TCP comparison has an unverified provider origin")
    require(report["cases_run"] == len(payload), "TCP comparison case count does not match input")
    identifiers = {case["id"] for case in payload}
    require(len(identifiers) == len(payload), "TCP comparison input has duplicate case identifiers")
    require(
        set(report["results"]) == identifiers,
        "TCP comparison result identifiers do not match input",
    )
    for case in payload:
        expected = (
            case["expected"]
            if case["status"] == "matching"
            else case["expected_versions"][
                "octetrail" if report["module"] == "octetrail" else report["version"]
            ]
        )
        actual = report["results"][case["id"]]
        require(
            actual == expected,
            f"TCP observation mismatch for {report['module']} {report['version']} {case['id']}: "
            f"got {actual!r}, expected {expected!r}",
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-196", required=True)
    parser.add_argument("--oracle-198", required=True)
    parser.add_argument("--python", action="append", default=[])
    args = parser.parse_args()
    payload = cases()
    matching = [case for case in payload if case["status"] == "matching"]
    differences = [case for case in payload if case["status"] == "difference"]
    require(len(matching) > 100 and len(differences) == 5, "Unexpected TCP corpus partition")
    require(
        len({case["id"] for case in payload}) == len(payload),
        "TCP corpus has duplicate case identifiers",
    )
    baselines = [
        probe(args.oracle_196, "dpkt", "1.9.6", payload),
        probe(args.oracle_198, "dpkt", "1.9.8", payload),
    ]
    for report in baselines:
        validate(report, payload)
    for case in matching:
        require(
            baselines[0]["results"][case["id"]] == baselines[1]["results"][case["id"]],
            f"TCP oracle observations disagree for {case['id']}",
        )
    actuals = [probe(python, "octetrail", "0.2.0", payload) for python in args.python]
    for report in actuals:
        validate(report, payload)
        for case in matching:
            require(
                report["results"][case["id"]] == baselines[0]["results"][case["id"]],
                f"TCP wheel observation differs from the oracle for {case['id']}",
            )
    print(
        json.dumps(
            {
                "scope": "TCP header, nine flags, reserved bits, opaque options, bytes payload and caller-supplied checksum",
                "declared_cases": len(payload),
                "matching_cases_per_provider": len(matching),
                "declared_differences_per_provider": len(differences),
                "oracle_validation": "both agree with independent expectations; shared cases equal",
                "octetrail": "validated"
                if actuals
                else "pending: no OctetRail interpreter supplied",
                "exception_messages": "not compared; error class and failure phase compared",
                "case_definition_sha256": hashlib.sha256(
                    (ROOT / "tools/tcp_cases.py").read_bytes()
                ).hexdigest(),
                "case_payload_sha256": hashlib.sha256(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
                "matching_ids": [case["id"] for case in matching],
                "differences": [
                    {
                        "id": case["id"],
                        "reason": case["reason"],
                        "observations": [
                            {
                                "module": report["module"],
                                "version": report["version"],
                                "result": report["results"][case["id"]],
                            }
                            for report in [*baselines, *actuals]
                        ],
                    }
                    for case in differences
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
