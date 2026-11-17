# Portions Copyright 2012 Google Inc. All rights reserved.
"""TLS cipher suite definitions, as in dpkt 1.9.8's ``dpkt.ssl_ciphersuites``.

``CIPHERSUITES`` lists ``CipherSuite`` objects, ``BY_CODE`` maps codes to them and
``BY_NAME(name)`` finds one by name. Treat them as immutable.
"""


class CipherSuite:
    """One cipher suite.

    ``code`` is the two-byte code. ``kx``, ``auth``, ``cipher``, ``mode`` and ``mac``
    name its algorithms, and ``name`` and ``encoding`` default to names built
    from them. ``kx_auth`` joins the key exchange and authentication names.
    """

    def __init__(self, code, kx, auth, cipher, mode, mac, name=None, encoding=None):
        self.code = code
        self._kx = kx.rstrip()
        self._auth = auth.rstrip()
        self.cipher = cipher.rstrip()
        self.mode = mode.rstrip()
        self.mac = mac.rstrip()
        self._name = name
        self._encoding = encoding

    @property
    def kx(self):
        if self._kx == "":  # PSK
            return self._auth
        return self._kx

    @property
    def auth(self):
        if self._auth == "":  # RSA
            return self._kx
        return self._auth

    @property
    def kx_auth(self):
        if self._auth == "":
            return self._kx
        if self._kx == "":
            return self._auth
        return self._kx + "_" + self._auth

    @property
    def encoding(self):
        if self._encoding is None:
            if self.mode == "":
                return self.cipher
            return self.cipher + "_" + self.mode
        return self._encoding

    @property
    def name(self):
        if self._name is None:
            if self.mac == "":  # CCM and CCM_8
                return "TLS_" + self.kx_auth + "_WITH_" + self.encoding
            return "TLS_" + self.kx_auth + "_WITH_" + self.encoding + "_" + self.mac
        return self._name

    def __repr__(self):
        return "CipherSuite(0x%04x, %s)" % (self.code, self.name)

    MAC_SIZES = {
        "MD5": 16,
        "SHA": 20,
        "SHA256": 32,
        "SHA384": 48,
    }

    BLOCK_SIZES = {
        "3DES_EDE": 8,
        "AES_128": 16,
        "AES_256": 16,
        "ARIA": 16,
        "CAMELLIA_128": 16,
        "CAMELLIA_256": 16,
        "CHACHA20": 64,
        "DES": 8,
        "DES40": 8,
        "IDEA": 8,
        "RC2_40": 8,
        "RC4_40": None,
        "RC4_128": None,
        "SEED": 16,
    }

    @property
    def mac_size(self):
        """In bytes, 0 when unknown."""
        return self.MAC_SIZES.get(self.mac, 0)

    @property
    def block_size(self):
        """In bytes, 1 when unknown."""
        return self.BLOCK_SIZES.get(self.cipher, 1)

    @property
    def pfs(self):
        return self.kx in ("DHE", "ECDHE")

    @property
    def aead(self):
        return self.mode in ("CCM", "CCM_8", "GCM")

    @property
    def anonymous(self):
        return self.auth.startswith("anon")


def get_unknown_ciphersuite(code):
    return CipherSuite(code, "", "", "", "", "", name="Unknown")


# The IANA registry, as dpkt lists it:
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
CIPHERSUITES = [
    # not a real cipher suite, can be ignored, see RFC5746
    CipherSuite(
        0x00FF, "NULL", "        ", "NULL    ", "    ", "NULL", "TLS_EMPTY_RENEGOTIATION_INFO"
    ),
    # RFC7507
    CipherSuite(0x5600, "", "            ", "", "", "", "TLS_FALLBACK"),
    CipherSuite(0xFFFF, "", "            ", "", "", "", "UNKNOWN_CIPHER"),
    # RFC2246 : TLS 1.0
    CipherSuite(0x0000, "NULL", "        ", "NULL    ", "    ", "NULL"),
    CipherSuite(0x0001, "RSA", "         ", "NULL    ", "    ", "MD5"),
    CipherSuite(0x0002, "RSA", "         ", "NULL    ", "    ", "SHA"),
    CipherSuite(0x0003, "RSA_EXPORT", "  ", "RC4_40  ", "    ", "MD5"),
    CipherSuite(0x0004, "RSA", "         ", "RC4_128 ", "    ", "MD5"),
    CipherSuite(0x0005, "RSA", "         ", "RC4_128 ", "    ", "SHA"),
    CipherSuite(0x0006, "RSA_EXPORT", "  ", "RC2_40  ", "CBC ", "MD5", encoding="RC2_CBC_40"),
    CipherSuite(0x0007, "RSA", "         ", "IDEA    ", "CBC ", "SHA"),
    CipherSuite(0x0008, "RSA_EXPORT", "  ", "DES40   ", "CBC ", "SHA"),
    CipherSuite(0x0009, "RSA", "         ", "DES     ", "CBC ", "SHA"),
    CipherSuite(0x000A, "RSA", "         ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0x000B, "DH", "DSS_EXPORT", "DES40   ", "CBC ", "SHA"),
    CipherSuite(0x000C, "DH", "DSS       ", "DES     ", "CBC ", "SHA"),
    CipherSuite(0x000D, "DH", "DSS       ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0x000E, "DH", "RSA_EXPORT", "DES40   ", "CBC ", "SHA"),
    CipherSuite(0x000F, "DH", "RSA       ", "DES     ", "CBC ", "SHA"),
    CipherSuite(0x0010, "DH", "RSA       ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0x0011, "DHE", "DSS_EXPORT", "DES40  ", "CBC ", "SHA"),
    CipherSuite(0x0012, "DHE", "DSS      ", "DES     ", "CBC ", "SHA"),
    CipherSuite(0x0013, "DHE", "DSS      ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0x0014, "DHE", "RSA_EXPORT", "DES40  ", "CBC ", "SHA"),
    CipherSuite(0x0015, "DHE", "RSA      ", "DES     ", "CBC ", "SHA"),
    CipherSuite(0x0016, "DHE", "RSA      ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0x0017, "DH", "anon_EXPORT", "RC4_40 ", "    ", "MD5"),
    CipherSuite(0x0018, "DH", "anon      ", "RC4_128 ", "    ", "MD5"),
    CipherSuite(0x0019, "DH", "anon_EXPORT", "DES40  ", "CBC ", "SHA"),
    CipherSuite(0x001A, "DH", "anon      ", "DES     ", "CBC ", "SHA"),
    CipherSuite(0x001B, "DH", "anon      ", "3DES_EDE", "CBC ", "SHA"),
    # Reserved: 0x1c-0x1d
    # RFC4346 : TLS 1.1
    # RFC2712
    CipherSuite(0x001E, "KRB5", "        ", "DES     ", "CBC ", "SHA"),
    CipherSuite(0x001F, "KRB5", "        ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0x0020, "KRB5", "        ", "RC4_128 ", "    ", "SHA"),
    CipherSuite(0x0021, "KRB5", "        ", "IDEA    ", "CBC ", "SHA"),
    CipherSuite(0x0022, "KRB5", "        ", "DES     ", "CBC ", "MD5"),
    CipherSuite(0x0023, "KRB5", "        ", "3DES_EDE", "CBC ", "MD5"),
    CipherSuite(0x0024, "KRB5", "        ", "RC4_128 ", "    ", "MD5"),
    CipherSuite(0x0025, "KRB5", "        ", "IDEA    ", "CBC ", "MD5"),
    CipherSuite(0x0026, "KRB5_EXPORT", " ", "DES40   ", "CBC ", "SHA", encoding="DES_CBC_40"),
    CipherSuite(0x0027, "KRB5_EXPORT", " ", "RC2_40  ", "CBC ", "SHA", encoding="RC2_CBC_40"),
    CipherSuite(0x0028, "KRB5_EXPORT", " ", "RC4_40  ", "    ", "SHA"),
    CipherSuite(0x0029, "KRB5_EXPORT", " ", "DES40   ", "CBC ", "MD5", encoding="DES_CBC_40"),
    CipherSuite(0x002A, "KRB5_EXPORT", " ", "RC2_40  ", "CBC ", "MD5", encoding="RC2_CBC_40"),
    CipherSuite(0x002B, "KRB5_EXPORT", " ", "RC4_40  ", "    ", "MD5"),
    # RFC4785
    CipherSuite(0x002C, "    ", "PSK     ", "NULL    ", "    ", "SHA"),
    CipherSuite(0x002D, "DHE ", "PSK     ", "NULL    ", "    ", "SHA"),
    CipherSuite(0x002E, "RSA ", "PSK     ", "NULL    ", "    ", "SHA"),
    # RFC3268
    CipherSuite(0x002F, "RSA ", "        ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0x0030, "DH  ", "DSS     ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0x0031, "DH  ", "RSA     ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0x0032, "DHE ", "DSS     ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0x0033, "DHE ", "RSA     ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0x0034, "DH  ", "anon    ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0x0035, "RSA ", "        ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0x0036, "DH  ", "DSS     ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0x0037, "DH  ", "RSA     ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0x0038, "DHE ", "DSS     ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0x0039, "DHE ", "RSA     ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0x003A, "DH  ", "anon    ", "AES_256 ", "CBC ", "SHA"),
    # RFC5246 : TLS 1.2
    CipherSuite(0x003B, "RSA ", "        ", "NULL    ", "    ", "SHA256"),
    CipherSuite(0x003C, "RSA ", "        ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0x003D, "RSA ", "        ", "AES_256 ", "CBC ", "SHA256"),
    CipherSuite(0x003E, "DH  ", "DSS     ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0x003F, "DH  ", "RSA     ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0x0040, "DHE ", "DSS     ", "AES_128 ", "CBC ", "SHA256"),
    # RFC5932
    CipherSuite(0x0041, "RSA ", "        ", "CAMELLIA_128", "CBC", "SHA"),
    CipherSuite(0x0042, "DH  ", "DSS     ", "CAMELLIA_128", "CBC", "SHA"),
    CipherSuite(0x0043, "DH  ", "RSA     ", "CAMELLIA_128", "CBC", "SHA"),
    CipherSuite(0x0044, "DHE ", "DSS     ", "CAMELLIA_128", "CBC", "SHA"),
    CipherSuite(0x0045, "DHE ", "RSA     ", "CAMELLIA_128", "CBC", "SHA"),
    CipherSuite(0x0046, "DH  ", "anon    ", "CAMELLIA_128", "CBC", "SHA"),
    # Reserved: 0x47-5c
    # Unassigned: 0x5d-5f
    # Reserved: 0x60-66
    # RFC5246 : TLS 1.2
    CipherSuite(0x0067, "DHE ", "RSA     ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0x0068, "DH  ", "DSS     ", "AES_256 ", "CBC ", "SHA256"),
    CipherSuite(0x0069, "DH  ", "RSA     ", "AES_256 ", "CBC ", "SHA256"),
    CipherSuite(0x006A, "DHE ", "DSS     ", "AES_256 ", "CBC ", "SHA256"),
    CipherSuite(0x006B, "DHE ", "RSA     ", "AES_256 ", "CBC ", "SHA256"),
    CipherSuite(0x006C, "DH  ", "anon    ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0x006D, "DH  ", "anon    ", "AES_256 ", "CBC ", "SHA256"),
    # Unassigned: 0x6e-83
    # RFC5932
    CipherSuite(0x0084, "RSA ", "        ", "CAMELLIA_256", "CBC", "SHA"),
    CipherSuite(0x0085, "DH  ", "DSS     ", "CAMELLIA_256", "CBC", "SHA"),
    CipherSuite(0x0086, "DH  ", "RSA     ", "CAMELLIA_256", "CBC", "SHA"),
    CipherSuite(0x0087, "DHE ", "DSS     ", "CAMELLIA_256", "CBC", "SHA"),
    CipherSuite(0x0088, "DHE ", "RSA     ", "CAMELLIA_256", "CBC", "SHA"),
    CipherSuite(0x0089, "DH  ", "anon    ", "CAMELLIA_256", "CBC", "SHA"),
    # RFC4279
    CipherSuite(0x008A, "    ", "PSK     ", "RC4_128 ", "    ", "SHA"),
    CipherSuite(0x008B, "    ", "PSK     ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0x008C, "    ", "PSK     ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0x008D, "    ", "PSK     ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0x008E, "DHE ", "PSK     ", "RC4_128 ", "    ", "SHA"),
    CipherSuite(0x008F, "DHE ", "PSK     ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0x0090, "DHE ", "PSK     ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0x0091, "DHE ", "PSK     ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0x0092, "RSA ", "PSK     ", "RC4_128 ", "    ", "SHA"),
    CipherSuite(0x0093, "RSA ", "PSK     ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0x0094, "RSA ", "PSK     ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0x0095, "RSA ", "PSK     ", "AES_256 ", "CBC ", "SHA"),
    # RFC4162
    CipherSuite(0x0096, "RSA ", "        ", "SEED    ", "CBC ", "SHA"),
    CipherSuite(0x0097, "DH  ", "DSS     ", "SEED    ", "CBC ", "SHA"),
    CipherSuite(0x0098, "DH  ", "RSA     ", "SEED    ", "CBC ", "SHA"),
    CipherSuite(0x0099, "DHE ", "DSS     ", "SEED    ", "CBC ", "SHA"),
    CipherSuite(0x009A, "DHE ", "RSA     ", "SEED    ", "CBC ", "SHA"),
    CipherSuite(0x009B, "DH  ", "anon    ", "SEED    ", "CBC ", "SHA"),
    # RFC5288
    CipherSuite(0x009C, "RSA ", "        ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0x009D, "RSA ", "        ", "AES_256 ", "GCM ", "SHA384"),
    CipherSuite(0x009E, "DHE ", "RSA     ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0x009F, "DHE ", "RSA     ", "AES_256 ", "GCM ", "SHA384"),
    CipherSuite(0x00A0, "DH  ", "RSA     ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0x00A1, "DH  ", "RSA     ", "AES_256 ", "GCM ", "SHA384"),
    CipherSuite(0x00A2, "DHE ", "DSS     ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0x00A3, "DHE ", "DSS     ", "AES_256 ", "GCM ", "SHA384"),
    CipherSuite(0x00A4, "DH  ", "DSS     ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0x00A5, "DH  ", "DSS     ", "AES_256 ", "GCM ", "SHA384"),
    CipherSuite(0x00A6, "DH  ", "anon    ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0x00A7, "DH  ", "anon    ", "AES_256 ", "GCM ", "SHA384"),
    # RFC5487
    CipherSuite(0x00A8, "    ", "PSK     ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0x00A9, "    ", "PSK     ", "AES_256 ", "GCM ", "SHA384"),
    CipherSuite(0x00AA, "DHE ", "PSK     ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0x00AB, "DHE ", "PSK     ", "AES_256 ", "GCM ", "SHA384"),
    CipherSuite(0x00AC, "RSA ", "PSK     ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0x00AD, "RSA ", "PSK     ", "AES_256 ", "GCM ", "SHA384"),
    CipherSuite(0x00AE, "    ", "PSK     ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0x00AF, "    ", "PSK     ", "AES_256 ", "CBC ", "SHA384"),
    CipherSuite(0x00B0, "    ", "PSK     ", "NULL    ", "    ", "SHA256"),
    CipherSuite(0x00B1, "    ", "PSK     ", "NULL    ", "    ", "SHA384"),
    CipherSuite(0x00B2, "DHE ", "PSK     ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0x00B3, "DHE ", "PSK     ", "AES_256 ", "CBC ", "SHA384"),
    CipherSuite(0x00B4, "DHE ", "PSK     ", "NULL    ", "    ", "SHA256"),
    CipherSuite(0x00B5, "DHE ", "PSK     ", "NULL    ", "    ", "SHA384"),
    CipherSuite(0x00B6, "RSA ", "PSK     ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0x00B7, "RSA ", "PSK     ", "AES_256 ", "CBC ", "SHA384"),
    CipherSuite(0x00B8, "RSA ", "PSK     ", "NULL    ", "    ", "SHA256"),
    CipherSuite(0x00B9, "RSA ", "PSK     ", "NULL    ", "    ", "SHA384"),
    # RFC5932
    CipherSuite(0x00BA, "RSA ", "        ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0x00BB, "DH  ", "DSS     ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0x00BC, "DH  ", "RSA     ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0x00BD, "DHE ", "DSS     ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0x00BE, "DHE ", "RSA     ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0x00BF, "DH  ", "anon    ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0x00C0, "RSA ", "        ", "CAMELLIA_256", "CBC", "SHA256"),
    CipherSuite(0x00C1, "DH  ", "DSS     ", "CAMELLIA_256", "CBC", "SHA256"),
    CipherSuite(0x00C2, "DH  ", "RSA     ", "CAMELLIA_256", "CBC", "SHA256"),
    CipherSuite(0x00C3, "DHE ", "DSS     ", "CAMELLIA_256", "CBC", "SHA256"),
    CipherSuite(0x00C4, "DHE ", "RSA     ", "CAMELLIA_256", "CBC", "SHA256"),
    CipherSuite(0x00C5, "DH  ", "anon    ", "CAMELLIA_256", "CBC", "SHA256"),
    # RFC8446 TLS 1.3
    CipherSuite(
        0x1301, "    ", "        ", "AES_128 ", "GCM     ", "SHA256", name="TLS_AES_128_GCM_SHA256"
    ),
    CipherSuite(
        0x1302, "    ", "        ", "AES_256 ", "GCM     ", "SHA384", name="TLS_AES_256_GCM_SHA384"
    ),
    CipherSuite(
        0x1303,
        "    ",
        "        ",
        "CHACHA20",
        "POLY1305",
        "SHA256",
        name="TLS_CHACHA20_POLY1305_SHA256",
    ),
    CipherSuite(
        0x1304, "    ", "        ", "AES_128 ", "CCM     ", "SHA256", name="TLS_AES_128_CCM_SHA256"
    ),
    CipherSuite(
        0x1305,
        "    ",
        "        ",
        "AES_128 ",
        "CCM_8   ",
        "SHA256",
        name="TLS_AES_128_CCM_8_SHA256",
    ),
    # RFC4492
    CipherSuite(0xC001, "ECDH ", "ECDSA  ", "NULL    ", "    ", "SHA"),
    CipherSuite(0xC002, "ECDH ", "ECDSA  ", "RC4_128 ", "    ", "SHA"),
    CipherSuite(0xC003, "ECDH ", "ECDSA  ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0xC004, "ECDH ", "ECDSA  ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0xC005, "ECDH ", "ECDSA  ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0xC006, "ECDHE", "ECDSA  ", "NULL    ", "    ", "SHA"),
    CipherSuite(0xC007, "ECDHE", "ECDSA  ", "RC4_128 ", "    ", "SHA"),
    CipherSuite(0xC008, "ECDHE", "ECDSA  ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0xC009, "ECDHE", "ECDSA  ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0xC00A, "ECDHE", "ECDSA  ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0xC00B, "ECDH ", "RSA    ", "NULL    ", "    ", "SHA"),
    CipherSuite(0xC00C, "ECDH ", "RSA    ", "RC4_128 ", "    ", "SHA"),
    CipherSuite(0xC00D, "ECDH ", "RSA    ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0xC00E, "ECDH ", "RSA    ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0xC00F, "ECDH ", "RSA    ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0xC010, "ECDHE", "RSA    ", "NULL    ", "    ", "SHA"),
    CipherSuite(0xC011, "ECDHE", "RSA    ", "RC4_128 ", "    ", "SHA"),
    CipherSuite(0xC012, "ECDHE", "RSA    ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0xC013, "ECDHE", "RSA    ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0xC014, "ECDHE", "RSA    ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0xC015, "ECDH ", "anon   ", "NULL    ", "    ", "SHA"),
    CipherSuite(0xC016, "ECDH ", "anon   ", "RC4_128 ", "    ", "SHA"),
    CipherSuite(0xC017, "ECDH ", "anon   ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0xC018, "ECDH ", "anon   ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0xC019, "ECDH ", "anon   ", "AES_256 ", "CBC ", "SHA"),
    # RFC5054
    CipherSuite(0xC01A, "SRP_SHA", "     ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0xC01B, "SRP_SHA", "RSA  ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0xC01C, "SRP_SHA", "DSS  ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0xC01D, "SRP_SHA", "     ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0xC01E, "SRP_SHA", "RSA  ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0xC01F, "SRP_SHA", "DSS  ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0xC020, "SRP_SHA", "     ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0xC021, "SRP_SHA", "RSA  ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0xC022, "SRP_SHA", "DSS  ", "AES_256 ", "CBC ", "SHA"),
    # RFC5289
    CipherSuite(0xC023, "ECDHE", "ECDSA  ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0xC024, "ECDHE", "ECDSA  ", "AES_256 ", "CBC ", "SHA384"),
    CipherSuite(0xC025, "ECDH ", "ECDSA  ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0xC026, "ECDH ", "ECDSA  ", "AES_256 ", "CBC ", "SHA384"),
    CipherSuite(0xC027, "ECDHE", "RSA    ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0xC028, "ECDHE", "RSA    ", "AES_256 ", "CBC ", "SHA384"),
    CipherSuite(0xC029, "ECDH ", "RSA    ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0xC02A, "ECDH ", "RSA    ", "AES_256 ", "CBC ", "SHA384"),
    CipherSuite(0xC02B, "ECDHE", "ECDSA  ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0xC02C, "ECDHE", "ECDSA  ", "AES_256 ", "GCM ", "SHA384"),
    CipherSuite(0xC02D, "ECDH ", "ECDSA  ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0xC02E, "ECDH ", "ECDSA  ", "AES_256 ", "GCM ", "SHA384"),
    CipherSuite(0xC02F, "ECDHE", "RSA    ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0xC030, "ECDHE", "RSA    ", "AES_256 ", "GCM ", "SHA384"),
    CipherSuite(0xC031, "ECDH ", "RSA    ", "AES_128 ", "GCM ", "SHA256"),
    CipherSuite(0xC032, "ECDH ", "RSA    ", "AES_256 ", "GCM ", "SHA384"),
    # RFC5489
    CipherSuite(0xC033, "ECDHE", "PSK    ", "RC4_128 ", "    ", "SHA"),
    CipherSuite(0xC034, "ECDHE", "PSK    ", "3DES_EDE", "CBC ", "SHA"),
    CipherSuite(0xC035, "ECDHE", "PSK    ", "AES_128 ", "CBC ", "SHA"),
    CipherSuite(0xC036, "ECDHE", "PSK    ", "AES_256 ", "CBC ", "SHA"),
    CipherSuite(0xC037, "ECDHE", "PSK    ", "AES_128 ", "CBC ", "SHA256"),
    CipherSuite(0xC038, "ECDHE", "PSK    ", "AES_256 ", "CBC ", "SHA384"),
    CipherSuite(0xC039, "ECDHE", "PSK    ", "NULL    ", "    ", "SHA"),
    CipherSuite(0xC03A, "ECDHE", "PSK    ", "NULL    ", "    ", "SHA256"),
    CipherSuite(0xC03B, "ECDHE", "PSK    ", "NULL    ", "    ", "SHA384"),
    # RFC6209
    CipherSuite(0xC03C, "RSA ", "        ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC03D, "RSA ", "        ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC03E, "DH  ", "DSS     ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC03F, "DH  ", "DSS     ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC040, "DH  ", "RSA     ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC041, "DH  ", "RSA     ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC042, "DHE ", "DSS     ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC043, "DHE ", "DSS     ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC044, "DHE ", "RSA     ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC045, "DHE ", "RSA     ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC046, "DH  ", "anon    ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC047, "DH  ", "anon    ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC048, "ECDHE", "ECDSA  ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC049, "ECDHE", "ECDSA  ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC04A, "ECDH ", "ECDSA  ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC04B, "ECDH ", "ECDSA  ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC04C, "ECDHE", "RSA    ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC04D, "ECDHE", "RSA    ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC04E, "ECDH ", "RSA    ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC04F, "ECDH ", "RSA    ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC050, "RSA ", "        ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC051, "RSA ", "        ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC052, "DHE ", "RSA     ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC053, "DHE ", "RSA     ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC054, "DH  ", "RSA     ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC055, "DH  ", "RSA     ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC056, "DHE ", "DSS     ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC057, "DHE ", "DSS     ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC058, "DH  ", "DSS     ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC059, "DH  ", "DSS     ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC05A, "DH  ", "anon    ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC05B, "DH  ", "anon    ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC05C, "ECDHE", "ECDSA  ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC05D, "ECDHE", "ECDSA  ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC05E, "ECDH ", "ECDSA  ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC05F, "ECDH ", "ECDSA  ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC060, "ECDHE", "RSA    ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC061, "ECDHE", "RSA    ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC062, "ECDH ", "RSA    ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC063, "ECDH ", "RSA    ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC064, "    ", "PSK     ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC065, "    ", "PSK     ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC066, "DHE ", "PSK     ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC067, "DHE ", "PSK     ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC068, "RSA ", "PSK     ", "ARIA_128", "CBC ", "SHA256"),
    CipherSuite(0xC069, "RSA ", "PSK     ", "ARIA_256", "CBC ", "SHA384"),
    CipherSuite(0xC06A, "    ", "PSK     ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC06B, "    ", "PSK     ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC06C, "DHE ", "PSK     ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC06D, "DHE ", "PSK     ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC06E, "RSA ", "PSK     ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC06F, "RSA ", "PSK     ", "ARIA_256", "GCM ", "SHA384"),
    CipherSuite(0xC070, "ECDHE", "PSK    ", "ARIA_128", "GCM ", "SHA256"),
    CipherSuite(0xC071, "ECDHE", "PSK    ", "ARIA_256", "GCM ", "SHA384"),
    # RFC6367
    CipherSuite(0xC072, "ECDHE", "ECDSA  ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0xC073, "ECDHE", "ECDSA  ", "CAMELLIA_256", "CBC", "SHA384"),
    CipherSuite(0xC074, "ECDH ", "ECDSA  ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0xC075, "ECDH ", "ECDSA  ", "CAMELLIA_256", "CBC", "SHA384"),
    CipherSuite(0xC076, "ECDHE", "RSA    ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0xC077, "ECDHE", "RSA    ", "CAMELLIA_256", "CBC", "SHA384"),
    CipherSuite(0xC078, "ECDH ", "RSA    ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0xC079, "ECDH ", "RSA    ", "CAMELLIA_256", "CBC", "SHA384"),
    CipherSuite(0xC07A, "RSA ", "        ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC07B, "RSA ", "        ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC07C, "DHE ", "RSA     ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC07D, "DHE ", "RSA     ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC07E, "DH  ", "RSA     ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC07F, "DH  ", "RSA     ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC080, "DHE ", "DSS     ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC081, "DHE ", "DSS     ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC082, "DH  ", "DSS     ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC083, "DH  ", "DSS     ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC084, "DH  ", "anon    ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC085, "DH  ", "anon    ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC086, "ECDHE", "ECDSA  ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC087, "ECDHE", "ECDSA  ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC088, "ECDH ", "ECDSA  ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC089, "ECDH ", "ECDSA  ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC08A, "ECDHE", "RSA    ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC08B, "ECDHE", "RSA    ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC08C, "ECDH ", "RSA    ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC08D, "ECDH ", "RSA    ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC08E, "    ", "PSK     ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC08F, "    ", "PSK     ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC090, "DHE ", "PSK     ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC091, "DHE ", "PSK     ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC092, "RSA ", "PSK     ", "CAMELLIA_128", "GCM", "SHA256"),
    CipherSuite(0xC093, "RSA ", "PSK     ", "CAMELLIA_256", "GCM", "SHA384"),
    CipherSuite(0xC094, "    ", "PSK     ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0xC095, "    ", "PSK     ", "CAMELLIA_256", "CBC", "SHA384"),
    CipherSuite(0xC096, "DHE ", "PSK     ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0xC097, "DHE ", "PSK     ", "CAMELLIA_256", "CBC", "SHA384"),
    CipherSuite(0xC098, "RSA ", "PSK     ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0xC099, "RSA ", "PSK     ", "CAMELLIA_256", "CBC", "SHA384"),
    CipherSuite(0xC09A, "ECDHE", "PSK    ", "CAMELLIA_128", "CBC", "SHA256"),
    CipherSuite(0xC09B, "ECDHE", "PSK    ", "CAMELLIA_256", "CBC", "SHA384"),
    # RFC6655
    CipherSuite(0xC09C, "RSA ", "        ", "AES_128 ", "CCM ", ""),
    CipherSuite(0xC09D, "RSA ", "        ", "AES_256 ", "CCM ", ""),
    CipherSuite(0xC09E, "DHE ", "RSA     ", "AES_128 ", "CCM ", ""),
    CipherSuite(0xC09F, "DHE ", "RSA     ", "AES_256 ", "CCM ", ""),
    CipherSuite(0xC0A0, "RSA ", "        ", "AES_128 ", "CCM_8", ""),
    CipherSuite(0xC0A1, "RSA ", "        ", "AES_256 ", "CCM_8", ""),
    CipherSuite(0xC0A2, "DHE ", "RSA     ", "AES_128 ", "CCM_8", ""),
    CipherSuite(0xC0A3, "DHE ", "RSA     ", "AES_256 ", "CCM_8", ""),
    CipherSuite(0xC0A4, "    ", "PSK     ", "AES_128 ", "CCM ", ""),
    CipherSuite(0xC0A5, "    ", "PSK     ", "AES_256 ", "CCM ", ""),
    CipherSuite(0xC0A6, "DHE ", "PSK     ", "AES_128 ", "CCM ", ""),
    CipherSuite(0xC0A7, "DHE ", "PSK     ", "AES_256 ", "CCM ", ""),
    CipherSuite(0xC0A8, "    ", "PSK     ", "AES_128 ", "CCM_8", ""),
    CipherSuite(0xC0A9, "    ", "PSK     ", "AES_256 ", "CCM_8", ""),
    CipherSuite(0xC0AA, "DHE ", "PSK     ", "AES_128 ", "CCM_8", ""),
    CipherSuite(0xC0AB, "DHE ", "PSK     ", "AES_256 ", "CCM_8", ""),
    # RFC7251
    CipherSuite(0xC0AC, "ECDHE", "ECDSA  ", "AES_128 ", "CCM ", ""),
    CipherSuite(0xC0AD, "ECDHE", "ECDSA  ", "AES_256 ", "CCM ", ""),
    CipherSuite(0xC0AE, "ECDHE", "ECDSA  ", "AES_128 ", "CCM_8", ""),
    CipherSuite(0xC0AF, "ECDHE", "ECDSA  ", "AES_256 ", "CCM_8", ""),
    # Unassigned: 0xc0b0-0xcca7
    CipherSuite(
        0xCC13,
        "ECDHE",
        "RSA    ",
        "CHACHA20",
        "POLY1305",
        "SHA256",
        "OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    ),
    CipherSuite(
        0xCC14,
        "ECDHE",
        "ECDSA  ",
        "CHACHA20",
        "POLY1305",
        "SHA256",
        "OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    ),
    CipherSuite(
        0xCC15,
        "DHE  ",
        "RSA    ",
        "CHACHA20",
        "POLY1305",
        "SHA256",
        "OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    ),
    # RFC7905
    CipherSuite(0xCCA8, "ECDHE", "RSA    ", "CHACHA20", "POLY1305", "SHA256"),
    CipherSuite(0xCCA9, "ECDHE", "ECDSA  ", "CHACHA20", "POLY1305", "SHA256"),
    CipherSuite(0xCCAA, "DHE  ", "RSA    ", "CHACHA20", "POLY1305", "SHA256"),
    CipherSuite(0xCCAB, "     ", "PSK    ", "CHACHA20", "POLY1305", "SHA256"),
    CipherSuite(0xCCAC, "ECDHE", "PSK    ", "CHACHA20", "POLY1305", "SHA256"),
    CipherSuite(0xCCAD, "DHE  ", "PSK    ", "CHACHA20", "POLY1305", "SHA256"),
    CipherSuite(0xCCAE, "RSA  ", "PSK    ", "CHACHA20", "POLY1305", "SHA256"),
    # RFC8701  // GREASE (Generate Random Extensions And Sustain Extensibility)
    CipherSuite(0x0A0A, "", "", "", "", "", "GREASE"),
    CipherSuite(0x1A1A, "", "", "", "", "", "GREASE"),
    CipherSuite(0x2A2A, "", "", "", "", "", "GREASE"),
    CipherSuite(0x3A3A, "", "", "", "", "", "GREASE"),
    CipherSuite(0x4A4A, "", "", "", "", "", "GREASE"),
    CipherSuite(0x5A5A, "", "", "", "", "", "GREASE"),
    CipherSuite(0x6A6A, "", "", "", "", "", "GREASE"),
    CipherSuite(0x7A7A, "", "", "", "", "", "GREASE"),
    CipherSuite(0x8A8A, "", "", "", "", "", "GREASE"),
    CipherSuite(0x9A9A, "", "", "", "", "", "GREASE"),
    CipherSuite(0xAAAA, "", "", "", "", "", "GREASE"),
    CipherSuite(0xBABA, "", "", "", "", "", "GREASE"),
    CipherSuite(0xCACA, "", "", "", "", "", "GREASE"),
    CipherSuite(0xDADA, "", "", "", "", "", "GREASE"),
    CipherSuite(0xEAEA, "", "", "", "", "", "GREASE"),
    CipherSuite(0xFAFA, "", "", "", "", "", "GREASE"),
    # Unassigned: 0xccaf-0xfefd
    # Reserved: 0xfefe-0xffff
]

BY_CODE = {cipher.code: cipher for cipher in CIPHERSUITES}

BY_NAME_DICT = None


def BY_NAME(name):  # noqa: N802 - dpkt's name.
    """Return the cipher suite called name. Raises KeyError."""
    global BY_NAME_DICT
    if BY_NAME_DICT is None:
        BY_NAME_DICT = {suite.name: suite for suite in CIPHERSUITES}
    return BY_NAME_DICT[name]


NULL_SUITE = BY_CODE[0x0000]
