"""Disposable-process test support, never part of the installed wheel.

This closed, three-module alias is evidence for a curated offline consumer only.
It refuses a real/importable upstream package and makes no resolver claim.
"""

import importlib.metadata
import importlib.util
import sys
from contextlib import contextmanager
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType


def dpkt_cache_keys():
    return [name for name in sys.modules if name == "dpkt" or name.startswith("dpkt.")]


@contextmanager
def mapped_capture_namespace():
    if not sys.flags.isolated or sys.prefix == sys.base_prefix:
        raise RuntimeError(
            "capture namespace tests require -I and a disposable virtual environment"
        )
    if dpkt_cache_keys():
        raise RuntimeError("refusing to mask cached dpkt modules")
    try:
        importlib.metadata.distribution("dpkt")
    except importlib.metadata.PackageNotFoundError:
        pass
    else:
        raise RuntimeError("refusing to mask an installed dpkt distribution")
    if importlib.util.find_spec("dpkt") is not None:
        raise RuntimeError("refusing to mask an importable dpkt package")
    import octetrail
    from octetrail import capture

    prefix = Path(sys.prefix).resolve()
    distribution = importlib.metadata.distribution("octetrail")
    assert importlib.metadata.version("octetrail") == "0.1.0"
    assert (
        Path(octetrail.__file__).resolve()
        == Path(distribution.locate_file("octetrail/__init__.py")).resolve()
    )
    for module in (octetrail, capture, capture.pcap, capture.pcapng, capture.pcap._native):
        assert Path(module.__file__).resolve().is_relative_to(prefix)
    facade = ModuleType("dpkt", "Test-only closed capture namespace backed by octetrail.capture")
    facade.__file__ = capture.__file__
    facade.__package__ = "dpkt"
    facade.__path__ = []
    facade.__all__ = tuple(capture.__all__)
    facade.__spec__ = ModuleSpec("dpkt", loader=None, origin=capture.__file__, is_package=True)
    for name in capture.__all__:
        setattr(facade, name, getattr(capture, name))
    modules = {"dpkt": facade, "dpkt.pcap": capture.pcap, "dpkt.pcapng": capture.pcapng}
    before_hooks = tuple(sys.meta_path)
    sys.modules.update(modules)
    try:
        yield facade
    finally:
        for name in dpkt_cache_keys():
            del sys.modules[name]
        assert tuple(sys.meta_path) == before_hooks
