# GRE and PIM

`octetrail.gre` and `octetrail.pim` parse and pack GRE and PIM packets the way
dpkt 1.9.8 does. The GRE option fields and source route entries are read in
Rust. The classes are [`Packet`](packet.md) subclasses, as in dpkt, and IPv4
and IPv6 decode protocol 47 as GRE and 103 as PIM, through the protocol table
filled from the `IP_PROTO_*` names.

```python
from octetrail import gre, ip6

tunnel = gre.GRE(flags=gre.GRE_KP, p=0x86DD, key=7, data=ip6.IP6(nxt=59))
parsed = gre.GRE(bytes(tunnel))
assert parsed.key == 7 and isinstance(parsed.ip6, ip6.IP6)
```

## GRE

`GRE` has `flags` and `p`, with `v` (the low three bits of `flags`) and `recur`
(bits 5 to 7). The option fields after the header depend on the flags, as
`opt_fields_fmts()` reports:

- Version 0: `sum` and `off` when the checksum or routing flag is set, then
  `key`, `seq` and `ack` when their flags are set.
- Other versions: `len` and `callid`, then `seq` and `ack` when their flags are
  set.

With the routing flag, `sre` is a list of `GRE.SRE` entries (`family`, `off`,
`len` and `data` cut to `len`), read until one with a `len` of 0. The payload is
decoded through the [Ethernet type table](ethernet.md#the-type-table) by `p`,
and also set as an attribute named after its class. A payload class that raises
`UnpackError` or `NeedData` leaves the bytes.

Packing writes the header, the option fields the flags select, the entries and
`data`. An option field the flags select but the packet lacks packs as 0. On a
version 0 packet built from fields with the checksum flag set, a `sum` of 0 is
computed over the GRE header and payload. A parsed packet keeps its `sum`.

## PIM

`PIM` has `v` and `type` (the two halves of the first byte), `_rsvd` and
`sum`, and the rest of the bytes in `data`. A `sum` of 0 is computed over the
whole message when packing, and the computed value is kept.

## Errors

A header shorter than four bytes raises `NeedData`. GRE option fields cut off by
the buffer raise `UnpackError`, and a source route entry header cut off, or a
missing last entry, raises `NeedData`, as in dpkt. Inside IPv4 or IPv6 such a payload
stays bytes. Long source route lists are read in linear time.

## Verification

`tools/gre_pim_differential.py` parses 32 packets, alone and inside IPv4 and IPv6,
including dpkt's GRE and PIM test vectors, and builds and repacks packets from
keywords. OctetRail must equal dpkt 1.9.8 on every observation:

```sh
python3 tools/gre_pim_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
