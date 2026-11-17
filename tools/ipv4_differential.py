"""Check declared IPv4 equality, version differences and strict exclusions."""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from ipv4_cases import LITERAL, cases, expected, header, state

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def probe(python, module, version, payload):
    flags = ["-I"]
    if sys.flags.optimize:
        flags.append("-" + "O" * sys.flags.optimize)
    result = subprocess.run(
        [
            python,
            *flags,
            str(ROOT / "tools/ipv4_probe.py"),
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
        timeout=60,
    )
    return json.loads(result.stdout)


def validate(report, payload, version, product=False):
    require(report["origin_verified"] is True, "provider origin not verified")
    require(report["cases_run"] == len(payload), "case count mismatch")
    require(set(report["results"]) == {c["id"] for c in payload}, "case IDs mismatch")
    for case in payload:
        if product and case["status"] == "unsupported":
            wanted = {"outcome": "error", "phase": "construct", "error": case["port_error"]}
        else:
            wanted = expected(case, version)
        require(
            report["results"][case["id"]] == wanted,
            f"{report['module']} {version} {case['id']}: "
            f"{report['results'][case['id']]!r} != {wanted!r}",
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", action="append", required=True)
    parser.add_argument("--oracle-196", required=True)
    parser.add_argument("--oracle-198", required=True)
    args = parser.parse_args()
    payload = cases()
    s = state(
        dict(src="c0000201", dst="c6336402", p=253, id=0x1234, df=1, sum=0x3B7E, data="7261696c")
    )
    require(header(s) + bytes.fromhex(s["data"]) == LITERAL, "independent literal mismatch")
    references = [
        probe(args.oracle_196, "dpkt", "1.9.6", payload),
        probe(args.oracle_198, "dpkt", "1.9.8", payload),
    ]
    for report in references:
        validate(report, payload, report["version"])
    products = []
    for python in args.python:
        report = probe(python, "octetrail", "0.3.1", payload)
        validate(report, payload, "1.9.8", True)
        products.append(report)
    common = [c for c in payload if c["status"] == "matching"]
    differences = [c for c in payload if c["status"] == "version_difference"]
    for case in common:
        key = case["id"]
        require(
            references[0]["results"][key] == references[1]["results"][key],
            f"shared oracle result mismatch: {key}",
        )
        for p in products:
            require(
                p["results"][key] == references[0]["results"][key],
                f"product shared result mismatch: {key}",
            )
    for case in differences:
        key = case["id"]
        require(
            references[0]["results"][key] != references[1]["results"][key],
            f"expected oracle difference missing: {key}",
        )
        for p in products:
            require(
                p["results"][key] == references[1]["results"][key],
                f"product version-target mismatch: {key}",
            )
    print(
        json.dumps(
            {
                "scope": "IPv4 base header, opaque options/bytes and ordinary header checksums",
                "declared_cases": len(payload),
                "common_equal_cases": len(common),
                "version_difference_cases": len(differences),
                "strict_or_unsupported_cases": len(payload) - len(common) - len(differences),
                "version_differences": [c["id"] for c in differences],
                "excluded": [
                    {"id": c["id"], "port_error": c["port_error"]}
                    for c in payload
                    if c["status"] == "unsupported"
                ],
                "case_sha256": hashlib.sha256(
                    (ROOT / "tools/ipv4_cases.py").read_bytes()
                ).hexdigest(),
                "providers": [
                    {k: v for k, v in r.items() if k != "results"} for r in references + products
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
