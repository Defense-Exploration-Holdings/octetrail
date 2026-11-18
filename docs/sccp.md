# SCCP

`octetrail.sccp` parses and packs Cisco Skinny Client Control Protocol
messages the way dpkt 1.9.8 does. `SCCP` and the message classes use the
[`Packet`](packet.md) base, as in dpkt. The module has dpkt's message id
constants.

```python
from octetrail import sccp

wire = bytes.fromhex("08000000000000001601000001000000") + b"next"
message = sccp.SCCP(wire)
assert message.activatecallplane.line_instance == 1
assert message.data == b"next"
```

## Fields

`SCCP` has `len`, `rsvd` and `msgid`, little-endian, and `msg`. Parsing puts
the `len - 4` bytes after the header in `msg` and the rest in `data`. A known
`msgid` decodes `msg` into an attribute named after the message class in lower
case, such as `keypadbutton` or `startmediatransmission`. Unknown ids, and
messages too short for their class, stay as bytes in `msg`. As in dpkt, a
`SelectStartKeys` class exists but `SELECT_SOFTKEYS` messages are not decoded.

## Packing

`msg` is a zero-width field, as in dpkt, so `bytes()` packs the 12-byte header
and then `data`, without `msg`. Put the message bytes in `data` to pack them.
`len` is packed as it is.

## Errors

A header shorter than 12 bytes raises `NeedData`. A `len` that runs past the
buffer raises `NeedData` with "not enough data". The messages are dpkt's. There
are no declared differences.

## Verification

The [fixture driver](../tools/sccp_differential.py) parses 27 messages,
including dpkt's test vectors and every decoded message id, and builds messages
from keywords. OctetRail must equal dpkt 1.9.8 on all 33 observations:

```sh
python3 tools/sccp_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
