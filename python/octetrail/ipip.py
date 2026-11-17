"""IP in IP (protocol 4): the inner datagram is IPv4, as in dpkt."""

from .ip import IP as IPIP

__all__ = ["IPIP"]
