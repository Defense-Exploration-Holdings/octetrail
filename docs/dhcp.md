# DHCP

`octetrail.dhcp` parses and packs DHCP messages the way dpkt 1.9.8 does. The
fixed header uses the [`Packet`](packet.md) base, as in dpkt, and the options
are read in Rust. The module has dpkt's `DHCP` class and its `DHCP_*`
constants.

```python
from octetrail import dhcp

offer = dhcp.DHCP(op=dhcp.DHCP_OP_REPLY, opts=[(dhcp.DHCP_OPT_MSGTYPE, bytes([dhcp.DHCPOFFER]))])
assert dhcp.DHCP(bytes(offer)).opts == [(53, b"\x02")]
```

## Fields

`DHCP` has dpkt's 240-byte header: `op`, `hrd`, `hln`, `hops`, `xid`, `secs`,
`flags`, `ciaddr`, `yiaddr`, `siaddr`, `giaddr`, `chaddr`, `sname`, `file` and
`magic`. After parsing, `chaddr` is cut to `hln` bytes. `opts` is a list of
`(type, data)` tuples and `data` holds the bytes after the end option.

## Parsing

The options are read until an end option (255) or the end of the buffer. Pad
options (0) are skipped. An option whose data runs past the buffer keeps the
bytes present. The magic cookie is not checked. Option data keeps the type of
the buffer, so a `bytearray` gives `bytearray` values.

## Packing

Each option packs as its type, its length and its data, followed by an end
option. With no options nothing is packed after the header, not even the end
option. `len()` counts one end byte either way, as in dpkt.

A new `DHCP` defaults to a DHCPDISCOVER that asks for an address, router,
netmask and DNS servers. dpkt's defaults are `str` values that do not pack.

## Errors

A header shorter than 240 bytes raises `NeedData`. An option type in the last
byte, with no length byte after it, raises `dhcp.MissingLengthError`, which is
both an `UnpackError` and an `IndexError` with dpkt's message. dpkt raises
`IndexError` there.

## Verification

The [fixture driver](../tools/dhcp_differential.py) parses 14 messages,
including dpkt's test vector, and builds and repacks messages from keywords.
OctetRail must equal dpkt 1.9.8 on all 27 observations except the declared
missing length error and its `UnpackError` base:

```sh
python3 tools/dhcp_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
