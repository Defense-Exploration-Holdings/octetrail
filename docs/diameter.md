# Diameter

`octetrail.diameter` parses and packs Diameter messages the way dpkt 1.9.8
does. `Diameter` and `AVP` use the [`Packet`](packet.md) base, as in dpkt, and
the AVP walk is read in Rust. The module has dpkt's command code constants.

```python
from octetrail import diameter

avp = diameter.AVP(code=264, flags=0x40, len=12, data=b"h002")
message = diameter.Diameter(len=32, cmd=280, flags=0x80, data=[avp])
parsed = diameter.Diameter(bytes(message))
assert parsed.request_flag == 1
assert parsed.avps[0].data == b"h002"
```

## Fields

`Diameter` has `v`, `len`, `flags`, `cmd`, `app_id`, `hop_id` and `end_id`,
with `request_flag`, `proxiable_flag`, `error_flag` and `retransmit_flag` as
bit properties of `flags`. `len` and `cmd` are 24-bit numbers after parsing.
After parsing, `avps` and `data` are the same list of `AVP` objects. Packing
reads `data`, so change that list in place or assign a new list to `data`.
Assigning a new list to `avps` alone does not change the packed bytes.

`AVP` has `code`, `flags` and `len`, with `vendor_flag`, `mandatory_flag` and
`protected_flag`. When the vendor flag is set, `vendor` is the unsigned 32-bit
integer in the 4 bytes after the header, in network byte order.

## Parsing

The message is cut to `len` bytes, and AVPs are read until it ends. As in dpkt:

- Each AVP moves past its header, its vendor id and the data its `len`
  selects. Padding to 4 bytes is not skipped, so a padded AVP leaves its
  padding at the start of the next one.
- A `len` below the 8-byte header selects everything after the header except
  the last `8 - len` bytes, the way a negative Python slice does.
- Bytes past the message `len` are dropped.

Each AVP is built from its own bytes, so a message with many AVPs parses in
linear time.

## Packing

`bytes()` packs the header and each AVP in `data`. `len` is packed as it is.
It is not computed. `len()` counts the header and the AVPs.

## Errors

- A message shorter than 20 bytes, or an AVP cut off inside its 8-byte header,
  raises `NeedData`.
- A vendor AVP with fewer than 4 bytes for its vendor id raises `UnpackError`
  with dpkt's "invalid AVP" message.

The messages are dpkt's. There are no declared differences.

## Verification

The [fixture driver](../tools/diameter_differential.py) parses 19 messages,
including dpkt's test vectors, and builds and repacks messages. OctetRail must
equal dpkt 1.9.8 on all 27 observations:

```sh
python3 tools/diameter_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
