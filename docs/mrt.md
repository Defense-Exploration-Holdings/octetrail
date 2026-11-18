# MRT

`octetrail.mrt` parses and packs MRT routing records the way dpkt 1.9.8 does.
`MRTHeader`, `TableDump`, `BGP4MPMessage` and `BGP4MPMessage_32` use the
[`Packet`](packet.md) base with dpkt's fields, and the module has dpkt's type,
subtype and address family constants.

```python
from octetrail import bgp, mrt

raw = bytes.fromhex("00010002000000030405000000060000000700080002" "01010102")
record = mrt.TableDump(raw)
assert record.peer_as == 8
assert isinstance(record.attributes[0].data, bgp.BGP.Update.Attribute.Origin)
assert bytes(record) == raw[:22]
```

## Fields

As in dpkt, `MRTHeader` reads only the common header, and the message bodies
are separate classes the caller picks by type and subtype. `BGP4MPMessage` and
`BGP4MPMessage_32` read only their fixed headers, with 2-byte and 4-byte AS
numbers.

`TableDump` reads attributes with [`bgp.BGP.Update.Attribute`](bgp.md) until
`attr_len` bytes are used and keeps them as `attributes`. `data` is what
follows the last attribute. As in dpkt, `bytes()` packs the header and `data`
but not the attributes.

## Errors

The errors are those of dpkt and of the [BGP module](bgp.md). An EVPN route
inside an attribute that ends before an address length byte raises
`bgp.EVPNIndexError`, which is both an `UnpackError` and the `IndexError` dpkt
raises, with the same message.

dpkt slices the rest of the record once per attribute, so a long attribute list
takes quadratic time. OctetRail gives each attribute only its own bytes and
walks the record by offset, with the same result.

## Verification

The [fixture driver](../tools/mrt_differential.py) parses 509 records,
including dpkt's TABLE_DUMP test vector, every prefix of each record and byte
edits of the table dumps. It also builds, edits and packs records. OctetRail
must equal dpkt 1.9.8 on all 514 observations, except the 67 where dpkt raises
the EVPN `IndexError`:

```sh
python3 tools/mrt_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
