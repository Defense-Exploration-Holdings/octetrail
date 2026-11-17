"""Portmap and rpcbind, as dpkt 1.9.8 reads them."""

from .packet import Packet

PMAP_PROG = 100000
PMAP_PROCDUMP = 4
PMAP_VERS = 2


class Pmap(Packet):
    """Portmap mapping: program, version, protocol and port."""

    __hdr__ = (("prog", "I", 0), ("vers", "I", 0), ("prot", "I", 0), ("port", "I", 0))
