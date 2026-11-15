"""Explicit provider for the measured dpkt-style offline capture subset.

Use ``from octetrail import capture as packets`` to select this provider in
application code. Importing it never installs a dpkt alias or changes imports.
See docs/capture-compatibility.md for the exact covered surface.
"""

from . import pcap, pcapng
from .errors import Error, NeedData, UnpackError

__all__ = ["Error", "NeedData", "UnpackError", "pcap", "pcapng"]
