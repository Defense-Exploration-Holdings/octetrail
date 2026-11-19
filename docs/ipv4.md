# IPv4

`octetrail.ip` parses and packs IPv4 datagrams the way dpkt 1.9.8 does. The
option and payload bounds and the header, TCP and UDP checksums are computed in
Rust. `IP` is a [`Packet`](packet.md) subclass, as in dpkt, and the module has
dpkt's `IP_*` constants. The native Rust API is
`octetrail::ipv4::{Header, Packet, checksum, transport_checksum, pseudo_checksum}`.

```python
from octetrail import ip

packet = ip.IP(src=bytes.fromhex("c0000201"), dst=bytes.fromhex("c6336402"),
               p=253, data=b"ordinary offline bytes")
raw = bytes(packet)
assert ip.IP(raw).data == packet.data
```

The addresses are documentation examples.

## Fields

`IP` has `v`, `hl`, `tos`, `len`, `id`, `rf`, `df`, `mf`, `offset`, `ttl`, `p`,
`sum`, `src`, `dst`, `opts` and `data`. `v` and `hl` are bit fields of `_v_hl`,
and `rf`, `df`, `mf` and `offset` of `_flags_offset`. `offset` is in eight-byte
units, as in 1.9.8. `off` reads `_flags_offset` and sets `offset`, and warns
that it is deprecated, as in dpkt. A new packet has version 4, header length 5,
TTL 64, zero addresses and a `len` of 20 plus its options and payload, unless
`len` is given.

## Parsing

1. The 20-byte header is read. A shorter buffer raises `NeedData`. Any version
   is accepted. A header length below five words raises `UnpackError`.
2. `opts` is the bytes from offset 20 to the header length, cut to the bytes
   present. The payload runs from there to `len`, also cut to the bytes
   present. A `len` inside the header gives an empty payload, and a `len` of 0,
   as seen with segmentation offload, keeps the rest of the buffer. Bytes after
   `len`, such as Ethernet padding, are dropped.
3. When `offset` is 0, the payload is decoded with `IP.get_proto(p)` and also
   set as an attribute named after its class, such as `tcp`, `udp`, `ip` or
   `ip6`. A later fragment stays bytes, and dpkt's quirk of setting it as
   `bytes` too is kept. A protocol without a class, and a payload class that
   raises `UnpackError`, `NeedData` or `KeyError`, leave the bytes, as in dpkt.
   Other errors propagate.

The slices keep the type of the buffer, so a `bytearray` gives `bytearray`
options and payload.

One difference from dpkt 1.9.8 is declared. When an IPv6 payload has `nxt` 44
in its fixed header while its last extension header is not a fragment header,
dpkt raises `AttributeError` out of `IP`. OctetRail raises
[`FragmentOffsetError`](ipv6.md#errors) for the payload, which is an
`UnpackError`, so `IP` keeps it as bytes.

## The protocol table

`IP.set_proto(p, cls)` and `IP.get_proto(p)` edit and read the table. As in
dpkt, `IP6` shares it, and it is filled from the `IP_PROTO_*` names: each one
maps to the class of the same name in the OctetRail module of that name when it
exists. Today that is `IP` (0 and 4, through `octetrail.ipip`), `ICMP`,
`IGMP`, `TCP`, `UDP`, `GRE`, `IP6`, `ESP`, `AH`, `ICMP6`, `OSPF`, `PIM`,
`VRRP` and `SCTP`. Protocol 118 is the Schedule Transfer Protocol and stays
bytes; dpkt decodes it with its Spanning Tree `STP` class.
`get_ip_proto_name(p)` returns the name of a protocol number, or `None`.

## Packing

Packing follows dpkt 1.9.8. When `sum` is 0, `len` is set to `len(packet)` and
`sum` to the checksum of the header and options. In that same step, a zero TCP
or UDP checksum is computed with the IPv4 pseudo-header when `p` is 6 or 17,
the datagram is not a fragment (MF and `offset` are 0) and the payload is a
layer object. A UDP checksum that computes to zero is sent as `0xffff`. A
nonzero `sum` keeps `len` and `sum` as they are, even after a change. Set `sum`
to 0 to refresh them. The header, `opts` and `data` are packed as assigned,
whatever `hl` says. Incoming checksums are kept, not validated.

`pack_hdr()` packs the fixed header only. A field that does not fit its format
raises `PackError`, so a zero-checksum datagram over 65535 bytes raises it too.
dpkt 1.9.6 differs: it rewrites `len` on every packing and uses byte units for
`offset`.

## Verification

`tools/ipv4_differential.py` parses 43 datagrams, including dpkt's IPv4 test
vectors, and builds, changes and repacks datagrams from keywords. OctetRail must
equal dpkt 1.9.8 on every observation except the declared one. TCP and UDP payloads are compared by
bytes, not by repr, until those modules are `Packet` subclasses too.

```sh
python3 tools/ipv4_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
