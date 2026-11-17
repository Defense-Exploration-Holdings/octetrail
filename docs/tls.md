# Passive offline TLS envelopes

`octetrail.ssl` explicitly parses supplied record/handshake bytes and selected
ServerHello metadata. It does not perform networking, cryptography, decryption,
transport reassembly or automatic dispatch.

```python
from octetrail import ssl

records, consumed = ssl.tls_multi_factory(b"\x17\x03\x03\x00\x04note")
assert records[0].data == b"note"
assert consumed == 9
```

TLSRecord exposes mutable type, version, length, data, compressed and encrypted.
Direct parsing accepts unsigned header fields and consumes only the declared
record body. Extra backing bytes are ignored without copying. Data remains
opaque bytes, bounded by its 16-bit wire length (65535 bytes).

Default fields are zero, data is empty and flags are false. Construction derives
length from data, ignoring a length keyword as dpkt does. Buffer construction
and every unpack set both flags true, overriding false constructor flags. This
reference convention does not indicate that cryptography was performed. Later
data changes leave the stored length unchanged. bytes, len and pack_hdr follow
those retained-field rules.

`tls_multi_factory(bytes)` recognizes record versions 0x0300 through 0x0303.
It returns a prefix of complete records and the consumed byte count. A call stops
before an incomplete record, after 1024 records or before exceeding 1 MiB of
framed bytes including headers. Continue from the returned offset using the
caller's buffering strategy. The unconsumed tail is not copied by the factory.
Even a large backing buffer only causes bounded framing work and bounded record
body copies. Both dpkt references instead frame all complete records per call.
A complete header with another version raises SSL3Exception.

TLSHandshake parses one complete four-byte envelope. Its framed length, including
the header, is capped at 1 MiB; trailing backing bytes are not charged or copied.
A missing declared body raises NeedData before the framed-size limit is considered.
Type 2 contains TLSServerHello; other types contain exact bytes. No cross-record
assembly or within-record handshake iteration occurs. The read-only length
property interprets mutable three-byte length_bytes. It remains stale after a
child/data edit, just like record length; no implicit wire-length repair occurs.

TLSServerHello parses a complete body and exposes version, 32-byte random,
session_id, integer cipher_suite_code, compression_method and optional ordered
extensions containing opaque bytes. The compression alias reads the same value.
Session IDs longer than 32 bytes are format errors. Extension items and their
vector must be complete and consume the remaining body. Limits are 128 extensions
and 1 MiB per complete supplied hello body. The native parser validates the fixed
prefix before borrowing random bytes.

The variable tail is retained as data. Serialization uses version, random and
that raw tail; editing session_id, cipher/compression metadata or extensions alone
does not rewrite it. Replace data explicitly to rebuild variable fields. General
keyword/default constructors for handshakes/hellos and CipherSuite objects are
absent. dpkt 1.9.6 uses cipher_suite/compression, while 1.9.8 uses ciphersuite/
compression_method with deprecated aliases. This API exposes only the numeric code.

RECORD_TYPES intentionally maps only type 22 to TLSHandshake. Other record
bodies stay opaque. ClientHello, certificates, other typed handshake classes,
SSL2/SSLFactory/TLS aggregate objects and variable-array helpers are deferred.
Unknown handshake numbers remain bytes instead of raising the reference error.
Legacy framing does not prove negotiation, authentication or cipher state; TLS
1.3 encrypted-handshake interpretation is unavailable.

NeedData identifies truncation. SSL3Exception now inherits UnpackError and covers
invalid format/recognition. ParseLimitError inherits UnpackError and the existing
LimitError/ValueError family. Packing limits remain separate LimitError errors;
invalid fields raise PackError. Programmer/allocation errors propagate. These
finite framing bounds do not guarantee process memory or latency limits. Failed
object state and exact exception text are unspecified.

`tools/tls_differential.py` checks 21 fixtures (17 equal and four differences),
ten constructors, defaults, mutations, incremental framing and metadata fields
against both pinned dpkt versions. Differences include empty-extension attribute
presence, 1.9.6 unknown-cipher handling, opaque Finished data class and unknown
handshake acceptance. Additional benign streams verify count/byte-budget
continuation, prefix parsing from larger buffers, truncation precedence, stale
lengths and reference flags. The partial type inventory remains explicit.
