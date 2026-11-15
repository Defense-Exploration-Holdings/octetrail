"""The covered subset of dpkt's packing and unpacking exception hierarchy."""


class Error(Exception):
    """Base error for the compatibility subset."""


class PackError(Error):
    """A header could not be packed from its assigned fields."""


class UnpackError(Error):
    """An unpacking operation could not be completed."""


class NeedData(UnpackError):
    """A header or packet payload is incomplete."""
