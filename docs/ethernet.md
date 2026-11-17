# Ethernet

`octetrail.ethernet` parses and packs Ethernet frames the way dpkt 1.9.8 does:
Ethernet II, IEEE 802.3 with LLC, LLC/SNAP and Novell raw 802.3, with 802.1Q,
MPLS and Cisco ISL decapsulation. The ISL walk, the tag and label stacks, the
802.3 trailer split and the frame check sequence are computed in Rust. The
classes are [`Packet`](packet.md) subclasses, as in dpkt. `octetrail.llc`,
`octetrail.stp` and `octetrail.ipx` hold the LLC, STP and IPX classes.

```python
from octetrail import ethernet, ip6

frame = ethernet.Ethernet(src=b"\x02" * 6, data=ip6.IP6(nxt=59))
wire = bytes(frame)
assert wire[12:14] == b"\x86\xdd"
assert isinstance(ethernet.Ethernet(wire).ip6, ip6.IP6)
```

## Parsing

`Ethernet` has `dst`, `src` and `type`. What follows depends on `type`:

- Above 1500, the frame is Ethernet II. `type` selects the payload class from
  the type table. For 802.1Q, 802.1ad and the legacy QinQ types, up to two tags
  are read into `vlan_tags` (`VLANtag8021Q` objects), and `vlanid`, `priority`
  and `cfi` copy the first tag. For MPLS, up to 24 labels are read into
  `mpls_labels` (`MPLSlabel` objects) and `labels` (tuples) until the bottom of
  the stack. The byte after the labels picks IPv4 (0x45), IPv6 (0x6_) or, with
  14 or more bytes left, an inner Ethernet frame, skipping a control word that
  starts with two zero bytes.
- Otherwise, a destination starting with `01:00:0c:00:00` or `03:00:0c:00:00`
  is a Cisco ISL tag. The frame after it is parsed again, and `vlan_tags` and
  `vlan` keep the innermost tag only.
- Otherwise, a payload starting with `ff ff` is Novell raw 802.3. `type`
  becomes 0x8137 and the bytes after those two are an `IPX` object.
- A `type` of 0 looks the payload up in the type table, so it stays bytes.
- Any other `type` is the length of an 802.3 LLC payload, also stored as `len`.
  The bytes after it are split by Wireshark's heuristic: zero `padding` up to a
  60-byte frame when more than four bytes follow, then a four-byte `fcs`, then
  a `trailer`. The payload is an `LLC` object in `data` and `llc`.

A decoded payload is also set as an attribute named after its class, such as
`ip`, `ip6`, `ipx`, `llc` or `ethernet`. A payload class that raises
`UnpackError` or `NeedData` leaves the bytes in `data`; other errors propagate.
Frames given as keywords decode a bytes `data` through the type table, but do
not walk tag or label stacks.

## The type table

`Ethernet.set_type(type, cls)`, `get_type(type)` and `get_type_rev(cls)` edit
and read the table. As in dpkt, it is filled from the `ETH_TYPE_*` names: each
one maps to the class of the same name in the OctetRail module of that name
when it exists. Today that is `IP`, `IP6`, `IPX` and `ARP`, plus `Ethernet` for
transparent bridging (0x6558). CDP, DTP, LLDP, PPP, PPPoE and the other
types dpkt decodes stay bytes until those modules exist.

## LLC, STP and IPX

`LLC` has `dsap`, `ssap` and `ctl`. When both SAPs are 0xaa it reads a SNAP
header into `oui` and `type`, and decodes the payload through the Ethernet type
table. Without SNAP, DSAP 0x06 decodes IPv4, 0x10 and 0xe0 decode IPX, and 0x42
decodes STP. `is_snap` tells which form it is.

`STP` has dpkt's BPDU fields, with `age`, `max_age`, `hello` and `fd` in whole
seconds. `IPX` has `sum`, `len`, `tc`, `pt`, `dst` and `src`.

## Packing

Packing follows dpkt. The type comes from the payload class when the table
knows it. MPLS labels get the bottom-of-stack bit on the last label only. One
802.1Q tag packs under 0x8100 and two under 0x88a8, unless `type` is already a
QinQ type, and the last tag carries the payload type. An ISL tag packs before
the Ethernet header. More than two tags raise `PackError`. An LLC payload packs
its length as the type, then `padding`, `fcs` and `trailer`. An `fcs` of 0 or
None is computed as the CRC-32 of the frame and its padding, without the ISL
tag.

## Errors

A header shorter than it needs raises `NeedData`. An ISL tag followed by fewer
than 14 bytes and a SNAP header shorter than five bytes raise `UnpackError`.
An MPLS stack with no byte after it raises `ethernet.MPLSIndexError`, which is
both an `UnpackError` and an `IndexError`, where dpkt raises `IndexError` with
the same message.

dpkt reads nested ISL tags recursively and raises `RecursionError` after about
a thousand of them. OctetRail reads any number in one pass.

## Verification

`tools/ethernet_differential.py` parses 41 frames, including dpkt's ISL, MPLS
pseudowire and 802.3 trailer vectors, and builds and repacks frames from
keywords. OctetRail must equal dpkt 1.9.8 on every observation except the
declared MPLS index error:

```sh
python3 tools/ethernet_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
