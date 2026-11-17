# SSL and TLS

`octetrail.ssl` parses and packs SSL and TLS records and handshake messages the
way dpkt 1.9.8 does. The variable-length parts (hellos, extensions, certificate
lists and record runs) are read in Rust. The classes are
[`Packet`](packet.md) subclasses, as in dpkt. There is no cryptography,
decryption or stream reassembly.

```python
from octetrail import ssl

records, consumed = ssl.tls_multi_factory(b"\x17\x03\x03\x00\x04note")
assert records[0].data == b"note"
assert consumed == 9
hello = ssl.TLSHandshake(records[0].data) if records[0].type == 22 else None
```

## Records

- `TLSRecord` has `type`, `version`, `length`, `data`, `compressed` and
  `encrypted`. Parsing reads `length` bytes of data, raises `NeedData` when fewer
  are present, and sets both flags. `length` is always `len(data)` after
  construction. The data is not decoded. `RECORD_TYPES` maps record types to the
  classes dpkt lists for them, but nothing applies it.
- `tls_multi_factory(buf)` returns the complete records at the start of `buf`
  and the bytes they use. It stops at an incomplete record, and raises
  `SSL3Exception` for a version that is not SSL 3.0 or TLS 1.0 to 1.2.
- `TLS(buf)` reads a run of records into `records`. As in dpkt, the first
  record starts at offset 0, so `TLS` itself also unpacks that record's header.
- `SSLFactory(buf)` returns a `TLSRecord` for SSL 3 and TLS versions and an
  `SSL2` otherwise.
- `SSL2` splits an SSLv2 record into `len`, `msg`, `pad` (two-byte form only)
  and `data`, the bytes after it.
- `TLSChangeCipherSpec`, `TLSAlert` (`level`, `description`) and
  `TLSAppData` (a `str` subclass) are as in dpkt.

## Handshakes

`TLSHandshake` has `type`, `length_bytes` and `length`. Its data is the next
`length` bytes, decoded by type through `HANDSHAKE_TYPES`:

| Type | Class | Attributes |
| --- | --- | --- |
| 0 | `TLSHelloRequest` | |
| 1 | `TLSClientHello` | `version`, `random`, `session_id`, `ciphersuites`, `compression_methods`, `extensions` |
| 2 | `TLSServerHello` | `version`, `random`, `session_id`, `ciphersuite`, `compression_method`, `extensions` |
| 11 | `TLSCertificate` | `certificates` |
| 4, 12 to 16, 20 | `TLSUnknownHandshake` | |

- `extensions` is a list of `(type, data)` pairs, set only when at least six
  bytes follow the fixed fields. The extension loop ends when its pointer
  reaches the declared block length, as in dpkt.
- Cipher suites are `ssl_ciphersuites.CipherSuite` objects from `BY_CODE`, or
  new "Unknown" ones for other codes. `ssl_ciphersuites` has dpkt's table, with
  `BY_NAME(name)`, `NULL_SUITE` and the `kx`, `auth`, `mac_size`,
  `block_size`, `pfs`, `aead` and `anonymous` properties.
- `TLSServerHello.cipher_suite` and `.compression` warn and return the renamed
  attributes, as in dpkt.
- `parse_variable_array(buf, lenbytes)` and `parse_extensions(buf)` are dpkt's
  helpers. The size returned is the declared one, even when `buf` is shorter.

## Errors

- `NeedData`: a record or handshake is shorter than its length, a ServerHello
  or certificate list is cut short, or a header is short.
- `UnpackError`: a ClientHello field is cut short past its fixed 34 bytes, or
  its cipher suite list has an odd length.
- `SSL3Exception`: an unknown handshake type, or a record version that
  `tls_multi_factory` rejects. dpkt's class derives from `Exception`. Here it is
  also an `UnpackError`.
- `SSL2IndexError`: an SSLv2 record with a two-byte length and no padding byte.
  dpkt raises `IndexError`. This class is both an `UnpackError` and an
  `IndexError`.

There are no size or count limits, and parsing takes time linear in the input.

## Packing

`bytes()` packs the header fields and then `data`, as for any `Packet`. The
variable-length hello fields are not packed from their attributes. A hello
packs its fixed fields and its unparsed `data`. Defaults that are not valid
for their formats, such as `TLSClientHello`'s text `random` or `TLS`'s empty
strings, raise `PackError`, as in dpkt.

## Measured compatibility

The [fixture driver](../tools/tls_differential.py) parses records, record runs,
handshakes of each type, hellos, certificate lists and SSLv2 records, including
dpkt's own test vectors, and compares every observation against dpkt 1.9.6 and
1.9.8:

```sh
python3 tools/tls_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```

OctetRail matches 1.9.8 on all of them apart from the declared differences
above, `SSL3Exception` being an `UnpackError` and `SSL2IndexError`.
