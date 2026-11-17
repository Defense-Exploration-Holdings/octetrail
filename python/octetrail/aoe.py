"""ATA over Ethernet, as dpkt 1.9.8 reads it.

Ethernet decodes type 0x88A2 as :class:`AOE`, which decodes its command with
the classes in ``AOE._cmdsw``.
"""

import importlib
import struct

from .errors import UnpackError
from .packet import Packet


class AOE(Packet):
    """ATA over Ethernet header.

    Attributes:
        ver, fl: The version and flags, the halves of the first byte.
        err: Error.
        maj, min: Shelf and slot address.
        cmd: Command, which selects the class of ``data``.
        tag: Tag.
    """

    __hdr__ = (
        ("_ver_fl", "B", 0x10),
        ("err", "B", 0),
        ("maj", "H", 0),
        ("min", "B", 0),
        ("cmd", "B", 0),
        ("tag", "I", 0),
    )
    __bit_fields__ = {
        "_ver_fl": (
            ("ver", 4),
            ("fl", 4),
        )
    }
    _cmdsw = {}

    @classmethod
    def set_cmd(cls, cmd, pktclass):
        cls._cmdsw[cmd] = pktclass

    @classmethod
    def get_cmd(cls, cmd):
        return cls._cmdsw[cmd]

    def unpack(self, buf):
        Packet.unpack(self, buf)
        try:
            self.data = self._cmdsw[self.cmd](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, struct.error, UnpackError):
            pass


AOE_CMD_ATA = 0
AOE_CMD_CFG = 1
AOE_FLAG_RSP = 1 << 3


def _load_cmds():
    # Each AOE_CMD_<NAME> maps to class AOE<NAME> of module aoe<name> when one exists.
    prefix = "AOE_CMD_"
    for k, v in list(globals().items()):
        if k.startswith(prefix):
            name = "aoe" + k[len(prefix) :].lower()
            try:
                mod = importlib.import_module(__package__ + "." + name)
                AOE.set_cmd(v, getattr(mod, name.upper()))
            except (ImportError, AttributeError):
                continue


def _mod_init():
    """Fill the command table once every module is loaded, as in dpkt."""
    if not AOE._cmdsw:
        _load_cmds()
