# CDP, DTP and EDP

`octetrail.cdp`, `octetrail.dtp` and `octetrail.edp` parse and pack the Cisco
Discovery, Dynamic Trunking and Extreme Discovery protocols the way dpkt 1.9.8
does. The CDP and DTP entry lists are read in Rust. The classes are
[`Packet`](packet.md) subclasses, as in dpkt, and Ethernet decodes them through
the [type table](ethernet.md#the-type-table): 0x2000 as CDP, 0x2004 as DTP and
0x00BB as EDP, usually after an LLC/SNAP header.

```python
from octetrail import cdp

name = cdp.CDP.TLV(type=cdp.CDP_DEVID, data=b"switch")
packet = cdp.CDP(bytes(cdp.CDP(data=bytes(name))))
assert packet.tlvs == [b"\x00\x01\x00\x0aswitch"]
```

## CDP

`CDP` has `version`, `ttl` and `sum`. A `sum` of 0 is computed when packing,
and kept. Parsing reads type-length-value entries to the end of the buffer and,
as dpkt does, keeps each one as the bytes it packs to: `tlvs` is that list and
`data` is their concatenation. An entry's value is cut to `len` less its
header; a `len` of 0 takes the rest of the packet and packs as the entry's own
length. An address list entry (type 2) has a four-byte address count after its
header. `CDP.TLV`, `CDP.Address` and `CDP.TLV_Addresses` build entries, and an
entry built with a `len` of 0 gets its length when packed.

## DTP

`DTP` has the version `v`, and `data` is a list of `(type, value)` pairs, each
value cut to the bytes present. As in dpkt, packing writes the entries but not
the version, and `len()` counts the header and the number of entries.

## EDP

`EDP` has `version`, `reserved`, `hlen`, `sum`, `seq`, `mid` and a six-byte
`mac`, with the rest in `data`. A `sum` of 0 is computed over the whole packet
when packing.

## Errors

A header shorter than its fixed length raises `NeedData`. A CDP entry header
cut off by the buffer raises `NeedData`. A DTP entry header cut off raises
`UnpackError`, which dpkt reports as `invalid DTP` with the buffer. Inside an
Ethernet frame such a payload stays bytes. Long entry lists are read in linear
time.

## Verification

`tools/cdp_dtp_edp_differential.py` parses 27 packets, alone and inside
Ethernet LLC/SNAP frames, including dpkt's test vectors, and builds and repacks
packets from keywords. OctetRail must equal dpkt 1.9.8 on every observation.
dpkt's own CDP and DTP tests also pass against OctetRail.

```sh
python3 tools/cdp_dtp_edp_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
