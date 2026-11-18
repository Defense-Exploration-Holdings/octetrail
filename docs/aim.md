# AIM

`octetrail.aim` parses and packs AOL Instant Messenger OSCAR frames the way
dpkt 1.9.8 does. `FLAP` and `SNAC` use the [`Packet`](packet.md) base, as in
dpkt, and `tlv` reads one type, length and value.

```python
from octetrail import aim

frame = aim.FLAP(type=2, seq=1, len=11, data=aim.SNAC(family=1, subtype=2, data=b"x"))
snac = aim.SNAC(aim.FLAP(bytes(frame)).data)
assert (snac.family, snac.subtype, snac.data) == (1, 2, b"x")
assert aim.tlv(b"\x00\x01\x00\x02hirest") == (1, 2, b"hi", b"rest")
```

## Fields

`FLAP` has `ast`, `type`, `seq` and `len`. `SNAC` has `family`, `subtype`,
`flags` and `reqid`. `data` holds the bytes after the header. A parsed `FLAP`
keeps every byte after its header in `data`, even past `len`, and nothing is
decoded further, as in dpkt.

`tlv(buf)` returns `(type, length, value, rest)`. Call it in a loop to read a
TLV list.

## Packing

`bytes()` packs the header and then `data`. `len` is packed as it is. It is not
computed.

## Errors

- `FLAP` raises `UnpackError` with "invalid FLAP header" when the first byte
  is not `*`, and `NeedData` when fewer than `len` bytes follow the header.
- `tlv` raises `UnpackError` with "invalid type, length fields" when fewer than
  4 bytes are given, and `NeedData` when the value is cut off.
- A header shorter than its fields raises `NeedData`.

The messages are dpkt's. There are no declared differences.

## Verification

The [fixture driver](../tools/aim_differential.py) parses 17 frames and TLVs,
including dpkt's test vector, and builds frames from keywords. OctetRail must
equal dpkt 1.9.8 on all 29 observations:

```sh
python3 tools/aim_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
