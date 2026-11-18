"""Check normal imports when both distributions coexist in a fresh test venv."""

import importlib.metadata
import importlib.util
import json
import platform
import runpy
import sys
from pathlib import Path

assert sys.flags.isolated and sys.prefix != sys.base_prefix
ROOT = Path(__file__).resolve().parents[1]
support = runpy.run_path(str(ROOT / "tools/capture_test_namespace.py"))
assert support["dpkt_cache_keys"]() == []
capture = importlib.import_module("octetrail.capture")

assert support["dpkt_cache_keys"]() == []
assert importlib.util.find_spec("dpkt") is not None
assert importlib.metadata.version("octetrail") == "0.7.2"
assert importlib.metadata.version("dpkt") == "1.9.8"
try:
    with support["mapped_capture_namespace"]():
        raise AssertionError("installed upstream must prevent mapping")
except RuntimeError as error:
    assert "installed dpkt" in str(error)
assert support["dpkt_cache_keys"]() == []
dpkt = importlib.import_module("dpkt")

assert capture.pcap.Reader.__module__ == "octetrail.pcap"
assert dpkt.pcap.Reader.__module__ == "dpkt.pcap"
prefix = Path(sys.prefix).resolve()
for module in (capture, capture.pcap, capture.pcapng, capture.pcap._native, dpkt, dpkt.pcap):
    assert Path(module.__file__).resolve().is_relative_to(prefix)
packages = importlib.metadata.packages_distributions()
assert packages["dpkt"] == ["dpkt"] and packages["octetrail"] == ["octetrail"]
print(
    json.dumps(
        {
            "python": platform.python_version(),
            "separate_distributions": True,
            "explicit_capture_provider": "octetrail",
            "normal_dpkt_import": "dpkt 1.9.8",
            "mapping_refused_installed_upstream": True,
            "origin_verified": True,
        }
    )
)
