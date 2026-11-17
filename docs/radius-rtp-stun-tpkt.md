# RADIUS, RTP, STUN and TPKT

`octetrail.radius`, `octetrail.rtp`, `octetrail.stun` and `octetrail.tpkt` parse
and pack these messages the way dpkt 1.9.8 does. The classes are
[`Packet`](packet.md) subclasses, as in dpkt, and the RADIUS and STUN attribute
lists are read in Rust. As in dpkt, UDP and TCP do not decode their payloads by
port, so build these classes from `udp.data` or `tcp.data` yourself.

```python
from octetrail import radius

request = radius.RADIUS(code=radius.RADIUS_ACCESS_REQUEST, id=7, auth=bytes(16))
request.data = b"\x01\x06user"
parsed = radius.RADIUS(bytes(request))
assert parsed.attrs == [(radius.RADIUS_USER_NAME, b"user")]
```

## RADIUS

`RADIUS` has `code`, `id`, `len` and a 16-byte `auth`. Parsing sets `attrs`, a
list of `(type, value)` tuples, and leaves `data` empty, as in dpkt. Packing
writes the header and `data`, not `attrs`. `parse_attrs(buf)` reads an attribute
list on its own. A length below 2 ends the list, and a value longer than the
bytes present is cut to them. Values are slices of the buffer passed in.

## RTP

`RTP` has `version`, `p`, `x`, `cc`, `m` and `pt` as properties over the first
two bytes, then `seq`, `ts` and `ssrc`. `csrc` is the next `cc * 4` bytes, cut
to the bytes present, and `data` is the rest. Packing writes the header, `csrc`
and `data`.

## STUN

`STUN` has `type`, `len` and a 16-byte `xid`. As in dpkt, `xid` defaults to 0,
so a message built without it raises `PackError` when packed, and the
attributes stay in `data`. `parse_attrs(buf)` returns `(type, value)` tuples,
and `tlv(buf)` returns `(type, length, value, rest)` for the first attribute.
Each attribute is padded to a multiple of four bytes, and a value longer than
the bytes present is cut to them.

## TPKT

`TPKT` has `v` (3 by default), `rsvd` and `len`. Anything after the four-byte
header is `data`.

## Errors

A header shorter than its fixed length raises `NeedData`.

Two differences are declared:

- One byte left at the end of a RADIUS attribute list raises `IndexError` in
  dpkt. OctetRail raises `radius.ShortAttributeError`, which subclasses both
  `UnpackError` and `IndexError` and keeps dpkt's message. `RADIUS` raises it
  from parsing too, as dpkt raises `IndexError`.
- Fewer than four bytes left for a STUN attribute header raise `struct.error`
  in dpkt. OctetRail raises `stun.ShortAttributeError`, which subclasses both
  `UnpackError` and `struct.error` and keeps dpkt's message.

## Verification

`tools/radius_rtp_stun_tpkt_differential.py` parses 32 messages and attribute
lists, including dpkt's test vectors, and builds and repacks messages from
keywords. OctetRail must equal dpkt 1.9.8 on every observation except the
declared ones. dpkt's own RADIUS, RTP and STUN tests also pass against
OctetRail.

```sh
python3 tools/radius_rtp_stun_tpkt_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
