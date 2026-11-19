"""Measure the supported UniversalReader slice and explicit strict differences."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from universal_cases import cases

ROOT = Path(__file__).resolve().parents[1]


def probe(python, module, version, payload):
    result = subprocess.run(
        [
            python,
            "-I",
            str(ROOT / "tools/universal_probe.py"),
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
    )
    return json.loads(result.stdout)


def comparable(observation):
    result = dict(observation)
    if result.get("error") == "NeedData":
        result.pop("message")  # Existing reader truncation text is outside parity.
    # dpkt seeks to offset 0 before trying PCAPNG. OctetRail picks the reader by
    # the magic bytes and never seeks; validate() checks that separately.
    result.pop("seeks")
    return result


def validate(report, payload, octetrail=False):
    assert report["available"] and report["origin_verified"]
    assert report["cases_run"] == len(payload)
    assert set(report["results"]) == {case["id"] for case in payload}
    for case in payload:
        actual = report["results"][case["id"]]
        assert not actual["source_closed"]
        if octetrail:
            assert actual["seeks"] == [], case["id"]
            if case["status"] == "fixed":
                case = {**case, **case["fixed"]}
                if "message" in case:
                    assert actual["message"] == case["message"], case["id"]
        if case["status"] == "difference":
            continue
        if case.get("error"):
            assert actual["outcome"] == "error" and actual["error"] == case["error"], case["id"]
            assert actual["phase"] == case.get("error_phase", "constructor")
            if case.get("identity"):
                assert actual["same_exception"]
            if case.get("identity") is False:
                assert not actual["same_exception"]
            if case["error"] == "NeedData" and actual["phase"] == "constructor":
                assert actual["position"] == len(bytes.fromhex(case["hex"]))
                assert actual["seeks"] == []
            continue
        assert actual["outcome"] == "ok", case["id"]
        assert actual["format"] == case["format"] and actual["rows"] == case["rows"]
        assert actual["metadata"] == ["synthetic.capture", 64, 147, 0, ""]
        assert actual["constructor_position"] == case["header"]
        if not octetrail:
            assert actual["seeks"] == ([] if case["format"] == "pcap" else [[0, 0]])
        if case["mode"] == "dispatch":
            assert actual["dispatch_count"] == min(1, len(case["rows"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", action="append", required=True)
    parser.add_argument("--oracle-198", required=True)
    parser.add_argument("--oracle-196", required=True)
    args = parser.parse_args()
    payload = cases()
    matching = [case for case in payload if case["status"] == "matching"]
    differences = [case for case in payload if case["status"] == "difference"]
    fixed = [case for case in payload if case["status"] == "fixed"]
    assert (len(payload), len(matching), len(differences), len(fixed)) == (39, 26, 5, 8)
    baseline = probe(args.oracle_198, "dpkt", "1.9.8", payload)
    validate(baseline, payload)
    absent = probe(args.oracle_196, "dpkt", "1.9.6", payload)
    assert absent["origin_verified"] and not absent["available"] and absent["cases_run"] == 0
    assert absent["results"] == {}
    reports = []
    for python in args.python:
        actual = probe(python, "octetrail", "1.0.0", payload)
        validate(actual, payload, octetrail=True)
        for case in matching:
            assert comparable(actual["results"][case["id"]]) == comparable(
                baseline["results"][case["id"]]
            ), case["id"]
        for case in differences:
            key = case["id"]
            assert actual["results"][key] != baseline["results"][key]
            if key == "unknown_format":
                assert (
                    actual["results"][key]["error"]
                    == baseline["results"][key]["error"]
                    == "ValueError"
                )
                assert actual["results"][key]["message"] == (
                    "unknown capture format: magic 00000000"
                )
            elif key.startswith("initial_ng_header_"):
                assert actual["results"][key]["error"] == "NeedData"
                assert baseline["results"][key]["error"] == "ValueError"
            else:
                assert actual["results"][key]["outcome"] == "error"
                assert baseline["results"][key]["outcome"] == "ok"
                error, phase = {
                    "classic_short_payload": ("NeedData", "iteration"),
                    "unsupported_classic_version": ("ValueError", "constructor"),
                }[key]
                assert actual["results"][key]["error"] == error
                assert actual["results"][key]["phase"] == phase
        reports.append(actual)
    print(
        json.dumps(
            {
                "scope": "dpkt 1.9.8 native-backed offline UniversalReader subset",
                "declared_cases": len(payload),
                "matching_cases_per_available_provider": len(matching),
                "known_differences_per_available_provider": len(differences),
                "fixed_dpkt_selection_rules": [case["id"] for case in fixed],
                "need_data_message_parity": "not claimed; exception family and other observations compared",
                "case_definition_sha256": hashlib.sha256(
                    (ROOT / "tools/universal_cases.py").read_bytes()
                ).hexdigest(),
                "fixture_corpus_sha256": hashlib.sha256(
                    b"".join(bytes.fromhex(case["hex"]) for case in payload)
                ).hexdigest(),
                "matching_ids": [case["id"] for case in matching],
                "differences": [
                    {
                        "id": case["id"],
                        "reason": case["reason"],
                        "dpkt_198": baseline["results"][case["id"]],
                        "octetrail": reports[0]["results"][case["id"]],
                    }
                    for case in differences
                ],
                "providers": [
                    {
                        key: report[key]
                        for key in (
                            "module",
                            "version",
                            "python",
                            "available",
                            "origin_verified",
                            "provider_file",
                            "cases_run",
                        )
                    }
                    for report in [baseline, absent, *reports]
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
