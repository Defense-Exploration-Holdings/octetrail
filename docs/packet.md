# Packet base class

`octetrail.Packet` is the base class of dpkt 1.9.8, `dpkt.Packet`, for writing
your own header classes. The checksum and hexdump helpers that dpkt keeps next to
it are here too. The class is pure Python, as in dpkt.

```python
import octetrail


class Note(octetrail.Packet):
    __hdr__ = (("kind", "B", 1), ("_v_len", "B", 0x10), ("id", "H", 0))
    __bit_fields__ = {"_v_len": (("v", 4), ("len", 4))}


n = Note(b"\x02\x31\x00\x07rest")
assert (n.kind, n.v, n.len, n.id, n.data) == (2, 3, 1, 7, b"rest")
assert bytes(Note(id=9)) == b"\x01\x10\x00\x09"
```

## Declaring a header

- `__hdr__` lists `(name, format, default)` rows. The formats are joined in
  order after `__byte_order__`, which is `>` unless the class sets it.
  The class gets `__hdr_fields__`, `__hdr_fmt__`, `__hdr_len__`,
  `__hdr_defaults__` and `__slots__` for the fields and `data`.
- `__bit_fields__` maps a header field to `(name, bits)` rows, from the high
  bits down. Each name becomes a property. Names starting with `_` only take
  up bits. The bit counts must add up to the field size, and the class
  definition fails an `assert` when they do not. A value too large for its
  bits raises `ValueError`. Deleting the property sets its default again.
- `__pprint_funcs__` maps a field name to a function whose result `pprint()`
  prints as a comment.
- A format that packs several values, such as `II`, takes a tuple.

## Using a packet

- `Packet(buf)` unpacks the header and sets `data` to the rest. Keyword
  arguments are then ignored. A `struct.error` during unpacking raises
  `NeedData` when the buffer is shorter than the header, and `UnpackError`
  otherwise.
- `Packet(**fields)` copies the defaults and sets each keyword as an attribute.
  Names outside the header are allowed and become plain attributes.
- `bytes()` and `pack()` return `pack_hdr()` followed by `bytes(data)`.
  `pack_hdr()` raises `PackError` when a value does not fit its format.
  `len()` is the header length plus `len(data)`. `str()` is the text of `bytes()`.
- Iterating yields `(name, value)` pairs for the header fields, so `dict(p)`
  works. `p[Cls]` returns the first payload of class `Cls` down the `data`
  chain, or raises `KeyError`, and `Cls in p` tests for one.
  `Cls in p` does not take the length of the layer it finds, so it also works
  when a TCP or UDP layer holds another layer object.
- `repr()` shows the public fields that differ from their defaults, the other
  attributes that do not start with `_`, and `data` when it is not empty.
  `pprint()` prints every field on its own line and descends into payloads.

## Helpers

- `hexdump(buf, length=16)` returns the offset, hex and printable text of each
  line.
- `in_cksum_add(s, buf)` adds `buf` to a running sum as little-endian 16-bit
  words. `in_cksum_done(s)` folds the sum and returns it in network order.
  `in_cksum(buf)` does both.

The module `octetrail.packet` holds all of these, with the error classes.

## Measured compatibility

The [fixture driver](../tools/packet_differential.py) defines the same classes
on both base classes and compares 37 observations, including the exception
classes and messages, against dpkt 1.9.6 and 1.9.8:

```sh
python3 tools/packet_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```

OctetRail matches 1.9.8 on all of them. 1.9.6 differs on bit fields, `repr()`,
`pprint()`, layer lookup and classes without `__hdr__`. `PackError` messages
come from `struct` and change between Python versions, so they are not compared.
