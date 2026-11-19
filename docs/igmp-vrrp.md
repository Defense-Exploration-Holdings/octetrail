# IGMP and VRRP

`octetrail.igmp` and `octetrail.vrrp` parse and pack IGMP and VRRP messages the
way dpkt 1.9.8 does. The VRRP address list is split in Rust. The classes are
[`Packet`](packet.md) subclasses, as in dpkt, and IPv6 decodes protocol 2 as
IGMP and 112 as VRRP. IPv4 dispatch to them comes with IPv4 parity.

```python
from octetrail import igmp, vrrp

query = igmp.IGMP(type=0x11, maxresp=100)
assert igmp.IGMP(bytes(query)).sum == query.sum
advert = vrrp.VRRP(count=1, addrs=[b"\x0a\x00\x00\x01"], auth=b"")
assert vrrp.VRRP(bytes(advert)).addrs == [b"\x0a\x00\x00\x01"]
```

## IGMP

`IGMP` has `type`, `maxresp`, `sum` and `group`, and the rest of the bytes in
`data`. A `sum` of 0 is computed when packing, and the computed value is kept.

## VRRP

`VRRP` has `v` and `type` (the two halves of the first byte), `vrid`,
`priority`, `count`, `atype`, `advtime` and `sum`. Parsing reads `count`
four-byte addresses into `addrs`, cut to the bytes present, and the bytes after
them into `auth`. `data` is `b""` after parsing. Packing writes the header,
`addrs` and `auth`, and computes a `sum` of 0.

dpkt differs in three ways: with a `count` of 0 it skips the first four bytes
of `auth`, it sets `data` to the `str` `""`, and a default `VRRP()` has a `str`
`auth` that does not pack.

## Errors

A header shorter than eight bytes raises `NeedData`. There are no other parse
errors, and no differences from dpkt 1.9.8.

## Verification

`tools/igmp_vrrp_differential.py` parses 16 messages, alone and inside IPv6,
including dpkt's VRRP vector, and builds and repacks messages from keywords.
OctetRail must equal dpkt 1.9.8 on every observation:

```sh
python3 tools/igmp_vrrp_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
