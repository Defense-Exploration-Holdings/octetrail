# OSPF and SCTP

`octetrail.ospf` and `octetrail.sctp` parse and pack OSPF and SCTP packets the
way dpkt 1.9.8 does. The SCTP chunk list and the CRC-32C checksum are computed
in Rust. The classes are [`Packet`](packet.md) subclasses, as in dpkt, and IPv4
and IPv6 decode protocol 89 as OSPF and 132 as SCTP, through the protocol table
filled from the `IP_PROTO_*` names.

```python
from octetrail import sctp

ack = sctp.Chunk(type=sctp.COOKIE_ACK, len=4, padding=b"")
packet = sctp.SCTP(sport=5000, dport=80, vtag=7, chunks=[ack])
parsed = sctp.SCTP(bytes(packet))
assert parsed.sum == packet.sum and parsed.chunks[0].type == sctp.COOKIE_ACK
```

## OSPF

`OSPF` has `v`, `type`, `len`, `router`, `area`, `sum`, `atype` and an
eight-byte `auth`, with the rest of the bytes in `data`. A `sum` of 0 is
computed over the whole packet when packing, and the computed value is kept.
`AUTH_NONE`, `AUTH_PASSWORD` and `AUTH_CRYPTO` are defined.

## SCTP

`SCTP` has `sport`, `dport`, `vtag` and `sum`, and a parsed packet has
`chunks`, a list of `Chunk` objects with `type`, `flags`, `len`, `data` and
`padding`. Chunks are read the way dpkt reads them:

- `data` is cut to `len` less the four header bytes. A `len` below four cuts
  that many bytes short of four from the end of the packet instead, as the
  slice in dpkt does.
- A DATA chunk whose `len` is not a multiple of four takes up to three bytes
  of `padding`.
- The next chunk starts `len` plus the padding bytes later, so a `len` below
  four makes chunks overlap. A chunk with a `len` and padding of 0 ends the
  list.

A parsed chunk copies its `data` out of the packet on first use, so parsing
takes linear time even when overlapping chunks each hold most of the packet.
Packing every such chunk copies each one, as in dpkt.

Packing writes the header and the chunks. A `sum` of 0 is computed as the
CRC-32C of the packet when packing, and kept. A packet built without `chunks`
raises `AttributeError` on `len()` and `bytes()`, as in dpkt. The
`octetrail.crc32c` module has dpkt's `crc32c_table`, `add`, `done` and `cksum`.

## Errors

A header shorter than its fixed length raises `NeedData`. A chunk header cut
off by the buffer raises `NeedData`, as in dpkt. Inside IPv4 or IPv6 such a
payload stays bytes.

## Verification

`tools/ospf_sctp_differential.py` parses 28 packets, alone and inside IPv4 and
IPv6, including dpkt's SCTP test vectors, and builds and repacks packets from
keywords. OctetRail must equal dpkt 1.9.8 on every observation. dpkt 1.9.6
never finishes a packet with a zero-length chunk, so those cases are not run on
it:

```sh
python3 tools/ospf_sctp_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
