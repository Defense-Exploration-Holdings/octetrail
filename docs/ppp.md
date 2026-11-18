# PPP and PPPoE

`octetrail.ppp` and `octetrail.pppoe` parse and pack PPP and PPP over Ethernet
frames the way dpkt 1.9.8 does. Both are fixed headers on the
[`Packet`](packet.md) base, as in dpkt. Ethernet decodes type 0x880B as PPP and
0x8864 as PPPoE, through the [type table](ethernet.md#the-type-table).

```python
from octetrail import ip, pppoe

frame = pppoe.PPPoE(session=7, len=21, data=pppoe.PPP(p=0x0021, data=ip.IP(p=59)))
parsed = pppoe.PPPoE(bytes(frame))
assert parsed.session == 7 and isinstance(parsed.ppp.ip, ip.IP)
```

## PPP

`PPP` has `addr`, `cntrl` and `p`. A `p` byte with its low bit set is the whole
protocol field; otherwise the field is two bytes, as with protocol field
compression off. The rest is decoded with `PPP.get_p(p)`. The table is filled
from the `PPP_*` names once every OctetRail module is loaded, so today it maps
0x21 to `IP` and 0x57 to `IP6`, as in dpkt. `PPP.set_p` adds a class. An
unknown protocol, or a payload that raises `UnpackError`, leaves the bytes.

Packing writes a two-byte protocol field when `p` is above 0xFF. A value that
does not fit raises `PackError`.

## PPPoE

`PPPoE` has `v` and `type` (the two halves of the first byte), `code`,
`session` and `len`. A session frame (code 0) carries `pppoe.PPP`, which has
only the protocol field, set as `data` and `ppp`. Discovery frames keep their
tags as bytes. `len` is kept as found and packed as assigned.

## Errors

A header shorter than its fixed length raises `NeedData`, and so does a
two-byte protocol field cut off by the buffer. Inside a PPPoE session or
Ethernet frame such a payload stays bytes.

One difference from dpkt 1.9.8 is declared. When PPP carries IPv6 whose fixed
header has `nxt` 44 while its last extension header is not a fragment header,
dpkt raises `AttributeError` out of `PPP`, out of the PPPoE session and out of the
Ethernet frame that carries them. OctetRail raises
[`FragmentOffsetError`](ipv6.md#errors) for the inner packet, which is an
`UnpackError`, so `PPP` keeps it as bytes, as `IP` and `AH` do. The same holds
for such IPv6 inside IPv4 inside PPP.

## Verification

`tools/ppp_differential.py` parses 33 frames, alone and inside Ethernet, and
builds and repacks frames from keywords. OctetRail must equal dpkt 1.9.8 on
every observation except the declared fragment offset cases. dpkt's own PPP and PPPoE tests also pass against OctetRail.

```sh
python3 tools/ppp_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
