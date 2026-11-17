"""Compare independent UDP expectations with both pinned oracles and installed wheels."""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from udp_cases import cases

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def probe(python, module, version, payload):
    flags = ["-B", "-I"]
    if sys.flags.optimize:
        flags.append("-" + "O" * sys.flags.optimize)
    result = subprocess.run(
        [
            python,
            *flags,
            str(ROOT / "tools/udp_probe.py"),
            "--module",
            module,
            "--version",
            version,
        ],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=tempfile.gettempdir(),
        timeout=60,
        check=True,
    )
    return json.loads(result.stdout)


def validate(report, payload, module="dpkt", version="1.9.8", optimization=None):
    require(
        report["module"] == module and report["version"] == version,
        "UDP provider identity mismatch",
    )
    require(report["origin_verified"] is True, "UDP provider origin unverified")
    require(report["cases_run"] == len(payload), "UDP case count mismatch")
    identifiers = {case["id"] for case in payload}
    require(len(identifiers) == len(payload), "duplicate UDP case IDs")
    require(set(report["results"]) == identifiers, "UDP result IDs mismatch")
    if optimization is not None:
        require(report["python_optimization"] == optimization, "UDP optimization level mismatch")
    for case in payload:
        expected = (
            case.get("expected_product", case["expected"])
            if module == "octetrail"
            else case["expected"]
        )
        actual = report["results"][case["id"]]
        require(actual == expected, f"UDP mismatch: {module} {version} {case['id']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-196", required=True)
    parser.add_argument("--oracle-198", required=True)
    parser.add_argument("--python", action="append", required=True)
    args = parser.parse_args()
    payload = cases()
    matching = [case for case in payload if case["status"] == "matching"]
    differences = [case for case in payload if case["status"] == "resource_difference"]
    require(
        len(matching) + len(differences) == len(payload) and len(differences) == 2,
        "unexpected UDP case partition",
    )
    providers = []
    for python, module, version in [
        (args.oracle_196, "dpkt", "1.9.6"),
        (args.oracle_198, "dpkt", "1.9.8"),
        *((python, "octetrail", "0.3.0") for python in args.python),
    ]:
        report = probe(python, module, version, payload)
        validate(report, payload, module, version, sys.flags.optimize)
        providers.append(report)
    for case in matching:
        key = case["id"]
        require(
            all(report["results"][key] == providers[0]["results"][key] for report in providers),
            f"UDP providers disagree on shared case {key}",
        )
    print(
        json.dumps(
            {
                "scope": "fixed UDP header, opaque bytes and retained caller length/checksum",
                "declared_cases": len(payload),
                "matching_cases_per_provider": len(matching),
                "resource_difference_cases_per_provider": len(differences),
                "exception_comparison": "family and phase; messages and failed-object state excluded",
                "case_definition_sha256": hashlib.sha256(
                    (ROOT / "tools/udp_cases.py").read_bytes()
                ).hexdigest(),
                "case_payload_sha256": hashlib.sha256(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
                "matching_ids": [case["id"] for case in matching],
                "resource_difference_ids": [case["id"] for case in differences],
                "resource_difference": "product caps complete buffer at 65535 bytes; both dpkt versions retain larger opaque buffers",
                "providers": [
                    {key: value for key, value in report.items() if key != "results"}
                    for report in providers
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
