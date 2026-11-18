"""Run the unchanged curated consumer with one explicitly selected provider."""

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import platform
import runpy
import sys
from contextlib import nullcontext
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSUMER = ROOT / "tests/consumers/capture_consumer.py"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("octetrail-test-map", "dpkt"), required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    assert sys.flags.isolated and sys.prefix != sys.base_prefix
    payload = json.load(sys.stdin)
    mapping = args.backend == "octetrail-test-map"
    if mapping:
        assert args.version == importlib.metadata.version("octetrail") == "0.6.1"
        support = runpy.run_path(str(ROOT / "tools/capture_test_namespace.py"))
        context = support["mapped_capture_namespace"]()
    else:
        import dpkt

        assert importlib.metadata.version("dpkt") == args.version
        origin = Path(dpkt.__file__).resolve()
        assert origin.is_relative_to(Path(sys.prefix).resolve())
        assert (
            origin
            == Path(
                importlib.metadata.distribution("dpkt").locate_file("dpkt/__init__.py")
            ).resolve()
        )
        context = nullcontext(dpkt)
    with context as provider:
        module = runpy.run_path(str(CONSUMER))
        result = {case["id"]: module["run"](case) for case in payload}
        constants = module["constants"]()
        if mapping:
            try:
                importlib.metadata.version("dpkt")
            except importlib.metadata.PackageNotFoundError:
                pass
            else:
                raise AssertionError("test mapping must not create upstream distribution metadata")
        provider_file = str(Path(provider.__file__).relative_to(sys.prefix))
    if mapping:
        assert support["dpkt_cache_keys"]() == []
        assert importlib.util.find_spec("dpkt") is None
    print(
        json.dumps(
            {
                "results": result,
                "constants": constants,
                "consumer_sha256": hashlib.sha256(CONSUMER.read_bytes()).hexdigest(),
                "backend": args.backend,
                "distribution_version": args.version,
                "python": platform.python_version(),
                "byte_order": sys.byteorder,
                "provider_file": provider_file,
                "mapping_restored": mapping,
                "origin_verified": True,
            }
        )
    )


if __name__ == "__main__":
    main()
