"""SSL and TLS records and handshakes, parsed the way dpkt 1.9.8 does.

The variable-length parts are read in Rust. The classes follow dpkt's
``dpkt.ssl`` and are built on :class:`octetrail.Packet`. No cryptography.
"""

import struct
import warnings

from . import _native, ssl_ciphersuites
from .errors import NeedData, UnpackError
from .packet import Packet


class SSL3Exception(UnpackError):
    """An unknown handshake type, or a record version tls_multi_factory rejects.

    dpkt's SSL3Exception derives from Exception. This one is also an
    UnpackError, so parse errors stay UnpackError.
    """


class SSL2IndexError(UnpackError, IndexError):
    """An SSLv2 record with a two-byte length has no padding byte.

    dpkt raises a plain IndexError here.
    """


def _deprecation_warning(*args):
    warnings.warn(*args, stacklevel=2)


def _bytes(buf):
    return buf if type(buf) is bytes else bytes(buf)


class SSL2(Packet):
    __hdr__ = (("len", "H", 0),)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        data = _bytes(self.data)
        try:
            n, msg, pad, rest = _native._ssl2(self.len, data)
        except IndexError as error:
            self.len &= 0x3FFF
            raise SSL2IndexError(str(error)) from None
        self.len = n
        self.msg = data[msg[0] : msg[1]]
        if pad is not None:
            self.pad = data[pad[0] : pad[1]]
        self.data = data[rest[0] : rest[1]]


class TLS(Packet):
    """A run of TLS records in ``records``."""

    __hdr__ = (
        ("type", "B", ""),
        ("version", "H", ""),
        ("len", "H", ""),
    )

    def __init__(self, *args, **kwargs):
        self.records = []
        Packet.__init__(self, *args, **kwargs)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        raw = _bytes(buf)
        # As in dpkt, the first record starts at offset 0, so it also covers
        # the five header bytes unpacked above.
        spans, error = _native._tls_records(raw)
        for start, end in spans:
            self.records.append(TLSRecord(raw[start:end]))
        if error == "short_record":
            raise NeedData("TLSRecord data was too short.")
        pointer = spans[-1][1] if spans else 0
        self.data = self.data[pointer:]


SSL3_V = 0x0300
TLS1_V = 0x0301
TLS11_V = 0x0302
TLS12_V = 0x0303

ssl3_versions_str = {SSL3_V: "SSL3", TLS1_V: "TLS 1.0", TLS11_V: "TLS 1.1", TLS12_V: "TLS 1.2"}

SSL3_VERSION_BYTES = set((b"\x03\x00", b"\x03\x01", b"\x03\x02", b"\x03\x03"))


# Alert levels
SSL3_AD_WARNING = 1
SSL3_AD_FATAL = 2
alert_level_str = {SSL3_AD_WARNING: "SSL3_AD_WARNING", SSL3_AD_FATAL: "SSL3_AD_FATAL"}

# SSL3 alert descriptions
SSL3_AD_CLOSE_NOTIFY = 0
SSL3_AD_UNEXPECTED_MESSAGE = 10  # fatal
SSL3_AD_BAD_RECORD_MAC = 20  # fatal
SSL3_AD_DECOMPRESSION_FAILURE = 30  # fatal
SSL3_AD_HANDSHAKE_FAILURE = 40  # fatal
SSL3_AD_NO_CERTIFICATE = 41
SSL3_AD_BAD_CERTIFICATE = 42
SSL3_AD_UNSUPPORTED_CERTIFICATE = 43
SSL3_AD_CERTIFICATE_REVOKED = 44
SSL3_AD_CERTIFICATE_EXPIRED = 45
SSL3_AD_CERTIFICATE_UNKNOWN = 46
SSL3_AD_ILLEGAL_PARAMETER = 47  # fatal

# TLS1 alert descriptions
TLS1_AD_DECRYPTION_FAILED = 21
TLS1_AD_RECORD_OVERFLOW = 22
TLS1_AD_UNKNOWN_CA = 48  # fatal
TLS1_AD_ACCESS_DENIED = 49  # fatal
TLS1_AD_DECODE_ERROR = 50  # fatal
TLS1_AD_DECRYPT_ERROR = 51
TLS1_AD_EXPORT_RESTRICTION = 60  # fatal
TLS1_AD_PROTOCOL_VERSION = 70  # fatal
TLS1_AD_INSUFFICIENT_SECURITY = 71  # fatal
TLS1_AD_INTERNAL_ERROR = 80  # fatal
TLS1_AD_USER_CANCELLED = 90
TLS1_AD_NO_RENEGOTIATION = 100
# /* codes 110-114 are from RFC3546 */
TLS1_AD_UNSUPPORTED_EXTENSION = 110
TLS1_AD_CERTIFICATE_UNOBTAINABLE = 111
TLS1_AD_UNRECOGNIZED_NAME = 112
TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE = 113
TLS1_AD_BAD_CERTIFICATE_HASH_VALUE = 114
TLS1_AD_UNKNOWN_PSK_IDENTITY = 115  # fatal


# Mapping alert types to strings
alert_description_str = {
    SSL3_AD_CLOSE_NOTIFY: "SSL3_AD_CLOSE_NOTIFY",
    SSL3_AD_UNEXPECTED_MESSAGE: "SSL3_AD_UNEXPECTED_MESSAGE",
    SSL3_AD_BAD_RECORD_MAC: "SSL3_AD_BAD_RECORD_MAC",
    SSL3_AD_DECOMPRESSION_FAILURE: "SSL3_AD_DECOMPRESSION_FAILURE",
    SSL3_AD_HANDSHAKE_FAILURE: "SSL3_AD_HANDSHAKE_FAILURE",
    SSL3_AD_NO_CERTIFICATE: "SSL3_AD_NO_CERTIFICATE",
    SSL3_AD_BAD_CERTIFICATE: "SSL3_AD_BAD_CERTIFICATE",
    SSL3_AD_UNSUPPORTED_CERTIFICATE: "SSL3_AD_UNSUPPORTED_CERTIFICATE",
    SSL3_AD_CERTIFICATE_REVOKED: "SSL3_AD_CERTIFICATE_REVOKED",
    SSL3_AD_CERTIFICATE_EXPIRED: "SSL3_AD_CERTIFICATE_EXPIRED",
    SSL3_AD_CERTIFICATE_UNKNOWN: "SSL3_AD_CERTIFICATE_UNKNOWN",
    SSL3_AD_ILLEGAL_PARAMETER: "SSL3_AD_ILLEGAL_PARAMETER",
    TLS1_AD_DECRYPTION_FAILED: "TLS1_AD_DECRYPTION_FAILED",
    TLS1_AD_RECORD_OVERFLOW: "TLS1_AD_RECORD_OVERFLOW",
    TLS1_AD_UNKNOWN_CA: "TLS1_AD_UNKNOWN_CA",
    TLS1_AD_ACCESS_DENIED: "TLS1_AD_ACCESS_DENIED",
    TLS1_AD_DECODE_ERROR: "TLS1_AD_DECODE_ERROR",
    TLS1_AD_DECRYPT_ERROR: "TLS1_AD_DECRYPT_ERROR",
    TLS1_AD_EXPORT_RESTRICTION: "TLS1_AD_EXPORT_RESTRICTION",
    TLS1_AD_PROTOCOL_VERSION: "TLS1_AD_PROTOCOL_VERSION",
    TLS1_AD_INSUFFICIENT_SECURITY: "TLS1_AD_INSUFFICIENT_SECURITY",
    TLS1_AD_INTERNAL_ERROR: "TLS1_AD_INTERNAL_ERROR",
    TLS1_AD_USER_CANCELLED: "TLS1_AD_USER_CANCELLED",
    TLS1_AD_NO_RENEGOTIATION: "TLS1_AD_NO_RENEGOTIATION",
    TLS1_AD_UNSUPPORTED_EXTENSION: "TLS1_AD_UNSUPPORTED_EXTENSION",
    TLS1_AD_CERTIFICATE_UNOBTAINABLE: "TLS1_AD_CERTIFICATE_UNOBTAINABLE",
    TLS1_AD_UNRECOGNIZED_NAME: "TLS1_AD_UNRECOGNIZED_NAME",
    TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE: "TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE",
    TLS1_AD_BAD_CERTIFICATE_HASH_VALUE: "TLS1_AD_BAD_CERTIFICATE_HASH_VALUE",
    TLS1_AD_UNKNOWN_PSK_IDENTITY: "TLS1_AD_UNKNOWN_PSK_IDENTITY",
}


# struct format strings for parsing buffer lengths
# don"t forget, you have to pad a 3-byte value with \x00


_SIZE_FORMATS = ["!B", "!H", "!I", "!I"]


def _struct_error(lenbytes):
    return struct.error("unpack requires a buffer of %d bytes" % lenbytes)


def parse_variable_array(buf, lenbytes):
    """Return the length-prefixed data at the start of buf and the bytes used.

    The size used is the declared one, even when buf is shorter.
    """
    assert lenbytes <= 4
    if not 1 <= lenbytes <= 4:
        size_format = _SIZE_FORMATS[lenbytes - 1]
        size = struct.unpack(size_format, buf[:lenbytes])[0]
        return buf[lenbytes : lenbytes + size], size + lenbytes
    raw = _bytes(buf[:lenbytes])
    if len(raw) != lenbytes:
        raise _struct_error(4 if lenbytes == 3 else lenbytes)
    size = int.from_bytes(raw, "big")
    return buf[lenbytes : lenbytes + size], size + lenbytes


def parse_extensions(buf):
    """Return the (type, data) pairs of a hello's extension block."""
    raw = _bytes(buf)
    found, error = _native._tls_extensions(raw)
    if error is not None:
        raise _struct_error(2)
    return [(kind, raw[start:end]) for kind, start, end in found]


class TLSRecord(Packet):
    """One record. ``data`` is the record body, which is not decoded."""

    __hdr__ = (
        ("type", "B", 0),
        ("version", "H", 0),
        ("length", "H", 0),
    )

    def __init__(self, *args, **kwargs):
        self.compressed = kwargs.pop("compressed", False)
        self.encrypted = kwargs.pop("encrypted", False)
        Packet.__init__(self, *args, **kwargs)
        self.length = len(self.data)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        header_length = self.__hdr_len__
        self.data = buf[header_length : header_length + self.length]
        if len(self.data) != self.length:
            raise NeedData("TLSRecord data was too short.")
        self.compressed = True
        self.encrypted = True


class TLSChangeCipherSpec(Packet):
    __hdr__ = (("type", "B", 1),)


class TLSAppData(str):
    pass


class TLSAlert(Packet):
    __hdr__ = (
        ("level", "B", 1),
        ("description", "B", 0),
    )


class TLSHelloRequest(Packet):
    __hdr__ = ()


def _suite(code):
    return ssl_ciphersuites.BY_CODE.get(code, ssl_ciphersuites.get_unknown_ciphersuite(code))


class TLSClientHello(Packet):
    __hdr__ = (
        ("version", "H", 0x0301),
        ("random", "32s", "\x00" * 32),
    )

    def unpack(self, buf):
        Packet.unpack(self, buf)
        raw = _bytes(buf)
        session, suites, methods, extensions, error = _native._tls_hello(raw, True)
        if session is not None:
            self.session_id = raw[session[0] : session[1]]
        if suites is not None:
            self.ciphersuites = [_suite(code) for code in suites]
        if methods is not None:
            self.compression_methods = tuple(raw[methods[0] : methods[1]])
        if extensions is not None:
            self.extensions = [(kind, raw[start:end]) for kind, start, end in extensions]
        if error is not None:
            # Packet.__init__ turns this into UnpackError, as in dpkt.
            raise _struct_error(2)


class TLSServerHello(Packet):
    __hdr__ = (
        ("version", "H", "0x0301"),
        ("random", "32s", "\x00" * 32),
    )

    def unpack(self, buf):
        try:
            Packet.unpack(self, buf)
        except struct.error:
            raise NeedData() from None
        raw = _bytes(buf)
        session, suites, method, extensions, error = _native._tls_hello(raw, False)
        if session is not None:
            self.session_id = raw[session[0] : session[1]]
        if suites is not None:
            self.ciphersuite = _suite(suites[0])
        if method is not None:
            self.compression_method = raw[method[0]]
        if extensions is not None:
            self.extensions = [(kind, raw[start:end]) for kind, start, end in extensions]
        if error is not None:
            raise NeedData()

    @property
    def cipher_suite(self):
        _deprecation_warning(
            "TLSServerHello.cipher_suite is deprecated and renamed to .ciphersuite"
        )
        return self.ciphersuite

    @property
    def compression(self):
        _deprecation_warning(
            "TLSServerHello.compression is deprecated and renamed to .compression_method"
        )
        return self.compression_method


class TLSCertificate(Packet):
    __hdr__ = ()

    def unpack(self, buf):
        Packet.unpack(self, buf)
        raw = _bytes(buf)
        found, error = _native._tls_certificates(raw)
        if found is not None:
            self.certificates = [raw[start:end] for start, end in found]
        if error is not None:
            raise NeedData()


class TLSUnknownHandshake(Packet):
    __hdr__ = ()


TLSNewSessionTicket = TLSUnknownHandshake
TLSServerKeyExchange = TLSUnknownHandshake
TLSCertificateRequest = TLSUnknownHandshake
TLSServerHelloDone = TLSUnknownHandshake
TLSCertificateVerify = TLSUnknownHandshake
TLSClientKeyExchange = TLSUnknownHandshake
TLSFinished = TLSUnknownHandshake

HANDSHAKE_TYPES = {
    0: ("HelloRequest", TLSHelloRequest),
    1: ("ClientHello", TLSClientHello),
    2: ("ServerHello", TLSServerHello),
    4: ("NewSessionTicket", TLSNewSessionTicket),
    11: ("Certificate", TLSCertificate),
    12: ("ServerKeyExchange", TLSServerKeyExchange),
    13: ("CertificateRequest", TLSCertificateRequest),
    14: ("ServerHelloDone", TLSServerHelloDone),
    15: ("CertificateVerify", TLSCertificateVerify),
    16: ("ClientKeyExchange", TLSClientKeyExchange),
    20: ("Finished", TLSFinished),
}


class TLSHandshake(Packet):
    """One handshake message. ``data`` is decoded by its type."""

    __hdr__ = (
        ("type", "B", 0),
        ("length_bytes", "3s", 0),
    )
    __pprint_funcs__ = {"length_bytes": lambda x: struct.unpack("!I", b"\x00" + x)[0]}

    def unpack(self, buf):
        Packet.unpack(self, buf)
        embedded_type = HANDSHAKE_TYPES.get(self.type)
        if embedded_type is None:
            raise SSL3Exception("Unknown or invalid handshake type %d" % self.type)
        self.data = self.data[: self.length]
        if len(self.data) != self.length:
            raise NeedData()
        self.data = embedded_type[1](self.data)

    @property
    def length(self):
        return struct.unpack("!I", b"\x00" + self.length_bytes)[0]


RECORD_TYPES = {
    20: TLSChangeCipherSpec,
    21: TLSAlert,
    22: TLSHandshake,
    23: TLSAppData,
}


class SSLFactory:
    """``SSLFactory(buf)`` returns a TLSRecord for SSL 3 and TLS versions, else SSL2."""

    def __new__(cls, buf):
        v = buf[1:3]
        if v in SSL3_VERSION_BYTES:
            return TLSRecord(buf)
        return SSL2(buf)


def tls_multi_factory(buf):
    """Return the complete records at the start of buf and the bytes they use.

    Raises SSL3Exception for a record whose version is not SSL 3 or TLS.
    """
    try:
        spans, consumed = _native._tls_multi_factory(_bytes(buf))
    except _native.TlsVersionError as error:
        at = error.args[0]
        raise SSL3Exception("Bad TLS version in buf: %r" % buf[at : at + 5]) from None
    raw = _bytes(buf)
    return [TLSRecord(raw[start:end]) for start, end in spans], consumed
