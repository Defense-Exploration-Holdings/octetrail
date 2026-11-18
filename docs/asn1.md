# ASN.1

`octetrail.asn1` decodes BER the way dpkt 1.9.8's `asn1.decode` does. The
element walk runs in Rust. The module has dpkt's class, tag and type
constants and its `utctime` helper.

```python
from octetrail import asn1

found = asn1.decode(b"\x30\x06\x02\x01\x05\x04\x01x")
assert found == [(0x30, [(2, 5), (4, b"x")])]
```

## Results

`decode()` returns a list of `(identifier, value)` tuples:

- The value of a constructed element is another such list.
- An INTEGER of up to 4 bytes is an `int`.
- A UTCTime is seconds since the Epoch, from `utctime()`.
- Any other value is a slice of the buffer, of the same type as the buffer.

The tag checks look only at the low five bits, so a context-specific tag 2 or
23 is read as an INTEGER or UTCTime, as in dpkt.

dpkt's decoder is deliberately simple, and OctetRail keeps its results:

- The contents of a constructed element are decoded up to the end of the
  buffer, not the end of the element. Elements that follow inside the buffer
  appear both in the constructed element's list and after it.
- An indefinite-length constructed element appears twice, and the decoder
  then skips 128 bytes.
- A 3-byte INTEGER is read from 4 bytes. A 3-byte long-form length is read
  from the length octet itself and keeps 12 bits.
- Lengths past the end of the buffer give shorter values, not errors.

`utctime()` reads text in the form `yymmddhhmm`, with optional seconds and an
optional `+hhmm` or `-hhmm` offset, as dpkt does. The offset is applied only
to `str` input.

## Errors

- A long-form length of 5 or more bytes, or a primitive element with an
  indefinite length, raises `UnpackError` with dpkt's message. So does an
  INTEGER longer than 4 bytes.
- Where dpkt raises a builtin error, OctetRail raises a class that is both an
  `UnpackError` and that builtin, with dpkt's message:
  - `asn1.ShortIndexError` (`IndexError`) for a length or INTEGER byte past
    the end, or for UTCTime text that is too short;
  - `asn1.ShortStructError` (`struct.error`) for a cut-off multi-byte length
    or INTEGER;
  - `asn1.TimeValueError` (`ValueError`) for UTCTime text that is not digits
    where dpkt expects them;
  - `asn1.TimeTypeError` (`TypeError`) for UTCTime in a `memoryview` buffer.
- Constructed elements nested more than 512 levels deep raise
  `asn1.NestingError`, the same class as [`octetrail.NestingError`](nesting.md),
  which is both an `UnpackError` and a `RecursionError`.
  dpkt raises `RecursionError` somewhere near the interpreter's recursion
  limit.
- A decode that would produce more than 262,144 elements raises
  `asn1.ParseLimitError`, which is both an `UnpackError` and the native
  `LimitError`. Because of how dpkt decodes constructed elements, its result
  can double with each one, so a short hostile buffer can need more memory and
  time than any machine has.

## Verification

The [fixture driver](../tools/asn1_differential.py) decodes 644 buffers,
including every prefix of dpkt's LDAP test vector. It also checks other
buffer types and `utctime()`. OctetRail must equal dpkt 1.9.8 on all 666
observations, except the 70 where dpkt raises a builtin error. On those
OctetRail must raise the mapped class above with the same message:

```sh
python3 tools/asn1_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
