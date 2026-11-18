# NetFlow

`octetrail.netflow` parses and packs Cisco NetFlow version 1, 5, 6 and 7
exports the way dpkt 1.9.8 does. `Netflow1`, `Netflow5`, `Netflow6`,
`Netflow7` and their `NetflowRecord` classes use the [`Packet`](packet.md)
base, as in dpkt, and the record split is read in Rust. Versions 8 and 9 are
not supported, as in dpkt.

```python
from octetrail import netflow

record = netflow.Netflow5.NetflowRecord(src_addr=0x0A000001, dst_port=443)
export = netflow.Netflow5(sys_uptime=10, data=[record])
parsed = netflow.Netflow5(bytes(export))
assert parsed.count == 1
assert parsed.data[0].dst_port == 443
```

## Fields

Every export has `version`, `count`, `sys_uptime`, `unix_sec` and
`unix_nsec`. Versions 5, 6 and 7 add `flow_sequence` and engine or reserved
fields. After parsing, `data` is the list of records. Each record class has
dpkt's fields for its version and no payload.

## Parsing

The bytes after the header are split into records of the record class's fixed
size. `count` is not checked against the number of records, and `version` is
not checked against the class, as in dpkt. Each record is built from its own
bytes, so a long export parses in linear time.

## Packing

`bytes()` sets `count` to the number of records, then packs the header and
each record. `len()` is the header plus the size of the first record times
`count`, as in dpkt.

## Errors

A header shorter than its fields, or a record cut off at the end, raises
`NeedData`. The messages are dpkt's. There are no declared differences.

## Verification

The [fixture driver](../tools/netflow_differential.py) parses 23 exports,
including dpkt's test vectors, and builds and repacks exports of each version.
OctetRail must equal dpkt 1.9.8 on all 30 observations:

```sh
python3 tools/netflow_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
