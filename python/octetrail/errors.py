"""The covered subset of dpkt's packing and unpacking exception hierarchy."""


class Error(Exception):
    """Base error for the compatibility subset."""


class PackError(Error):
    """A header could not be packed from its assigned fields."""


class UnpackError(Error):
    """An unpacking operation could not be completed."""


class NeedData(UnpackError):
    """A header or packet payload is incomplete."""


class NestingError(UnpackError, RecursionError):
    """Headers nest deeper than the Python recursion limit allows to decode.

    dpkt raises RecursionError here. This class is also an UnpackError, so code
    that catches either one handles it. A payload decoder never keeps the bytes
    of a payload that fails this way: the error reaches the caller, as in dpkt.
    """
