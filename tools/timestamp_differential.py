"""Compare default capture timestamps and separately verify the exact Decimal option."""

import argparse
import hashlib
import importlib
import importlib.metadata
import importlib.util
import io
import json
import subprocess
import sys
import tempfile

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: only release tooling reads TOML.
    tomllib = None
from decimal import Decimal
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_provider(name, version):
    require(sys.flags.isolated and sys.prefix != sys.base_prefix, "isolated venv required")
    distribution = importlib.metadata.distribution(name)
    require(distribution.version == version, "timestamp provider version mismatch")
    prefix = Path(sys.prefix).resolve()
    modules, origins = {}, {}
    for suffix in ("", "pcap", "pcapng"):
        full_name = name + ("." + suffix if suffix else "")
        module = importlib.import_module(full_name)
        origin = Path(module.__file__).resolve()
        member = name + "/" + (suffix + ".py" if suffix else "__init__.py")
        require(origin.is_relative_to(prefix), "timestamp provider outside venv")
        require(
            origin == Path(distribution.locate_file(member)).resolve(),
            "timestamp distribution origin mismatch",
        )
        modules[suffix] = module
        origins[full_name] = {
            "path": str(origin),
            "sha256": hashlib.sha256(origin.read_bytes()).hexdigest(),
        }
    if name == "octetrail":
        require(importlib.util.find_spec("dpkt") is None, "unexpected dpkt in product venv")
        native = importlib.import_module("octetrail._native")
        require(
            Path(native.__file__).resolve().is_relative_to(prefix), "timestamp native outside venv"
        )
    return modules, origins


def observe(factory, raw, kwargs):
    source = io.BytesIO(raw)
    reader = factory(source, **kwargs)
    rows = []
    for timestamp, data in reader:
        numerator, denominator = timestamp.as_integer_ratio()
        rows.append(
            {
                "value": str(timestamp),
                "kind": type(timestamp).__name__,
                "data": data.hex(),
                "ratio": [numerator, denominator],
            }
        )
    require(
        not source.closed and source.tell() == len(raw) and list(reader) == [],
        "timestamp cursor/ownership mismatch",
    )
    return rows


def validate(report, payload, name, version, optimization):
    require(
        report["module"] == name and report["version"] == version,
        "timestamp provider identity mismatch",
    )
    require(report["origin_verified"] is True, "timestamp origin unverified")
    require(report["python_optimization"] == optimization, "timestamp optimization mismatch")
    ids = {case["id"] for case in payload}
    require(
        len(ids) == len(payload)
        and report["cases_run"] == len(payload)
        and set(report["results"]) == ids,
        "timestamp case coverage mismatch",
    )
    for case in payload:
        result = report["results"][case["id"]]
        expected_default = (
            case.get("reference_default")
            if name == "dpkt" and case["status"] == "interface_difference"
            else [row["default"] for row in case["rows"]]
        )
        normalized = [
            {key: row[key] for key in ("value", "kind", "data")} for row in result["default"]
        ]
        require(normalized == expected_default, "default timestamp mismatch: " + case["id"])
        if name == "dpkt":
            require(
                result["decimal_keyword"] == "unsupported",
                "reference Decimal keyword unexpectedly supported",
            )
        else:
            require(
                result["explicit_false"] == result["default"],
                "explicit false changed timestamp behavior",
            )
            require(len(result["decimal"]) == len(case["rows"]), "Decimal record count mismatch")
            for actual, wanted in zip(result["decimal"], case["rows"], strict=True):
                value = Decimal(actual["value"])
                require(
                    actual["kind"] == "Decimal"
                    and actual["ratio"] == wanted["ratio"]
                    and list(value.as_integer_ratio()) == wanted["ratio"]
                    and value.as_tuple().exponent == -wanted["exponent"]
                    and actual["data"] == wanted["data"],
                    "exact Decimal mismatch: " + case["id"],
                )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", choices=("dpkt", "octetrail"))
    parser.add_argument("--version")
    parser.add_argument("--oracle-196")
    parser.add_argument("--oracle-198")
    parser.add_argument("--python", action="append", default=[])
    args = parser.parse_args()
    if args.probe:
        modules, origins = verify_provider(args.probe, args.version)
        payload = json.load(sys.stdin)
        require(
            len({case["id"] for case in payload}) == len(payload), "duplicate timestamp case IDs"
        )
        results = {}
        for case in payload:
            factory, raw = modules[case["format"]].Reader, bytes.fromhex(case["hex"])
            result = {"default": observe(factory, raw, {})}
            if args.probe == "octetrail":
                result["explicit_false"] = observe(factory, raw, {"decimal_timestamps": False})
                result["decimal"] = observe(factory, raw, {"decimal_timestamps": True})
            else:
                try:
                    factory(io.BytesIO(raw), decimal_timestamps=True)
                except TypeError:
                    result["decimal_keyword"] = "unsupported"
                else:
                    result["decimal_keyword"] = "supported"
            results[case["id"]] = result
        print(
            json.dumps(
                {
                    "module": args.probe,
                    "version": args.version,
                    "python": sys.version.split()[0],
                    "python_optimization": sys.flags.optimize,
                    "origin_verified": True,
                    "origins": origins,
                    "cases_run": len(payload),
                    "results": results,
                }
            )
        )
        return
    require(
        args.oracle_196 and args.oracle_198 and args.python,
        "both oracle interpreters and a product interpreter are required",
    )
    from timestamp_cases import cases

    product_version = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    )["project"]["version"]
    payload, reports = cases(), []
    for python, name, version in [
        (args.oracle_196, "dpkt", "1.9.6"),
        (args.oracle_198, "dpkt", "1.9.8"),
        *((python, "octetrail", product_version) for python in args.python),
    ]:
        flags = ["-B", "-I"] + (["-" + "O" * sys.flags.optimize] if sys.flags.optimize else [])
        process = subprocess.run(
            [python, *flags, str(Path(__file__).resolve()), "--probe", name, "--version", version],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=True,
            timeout=60,
            cwd=tempfile.gettempdir(),
        )
        report = json.loads(process.stdout)
        validate(report, payload, name, version, sys.flags.optimize)
        reports.append(report)
    matching = [case for case in payload if case["status"] == "matching"]
    for case in matching:
        require(
            all(
                report["results"][case["id"]]["default"]
                == reports[0]["results"][case["id"]]["default"]
                for report in reports
            ),
            "default providers disagree: " + case["id"],
        )
    print(
        json.dumps(
            {
                "scope": "offline exact Decimal reader option; default parity separately measured",
                "default_matching_captures_per_provider": len(matching),
                "default_matching_records_per_provider": sum(len(c["rows"]) for c in matching),
                "separate_interface_clock_difference_captures": 1,
                "exact_decimal_captures_per_product": len(payload),
                "exact_decimal_records_per_product": sum(len(c["rows"]) for c in payload),
                "reference_extension": "both pinned versions reject decimal_timestamps; no extension parity claimed",
                "corpus_sha256": hashlib.sha256(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
                "providers": [{k: v for k, v in r.items() if k != "results"} for r in reports],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
