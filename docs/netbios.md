# NetBIOS

`octetrail.netbios` parses and packs NetBIOS over TCP/IP messages the way dpkt
1.9.8 does. As in dpkt, the name service is a [DNS](dns.md) subclass with its
own record class, and the session and datagram headers are
[`Packet`](packet.md) subclasses. UDP and TCP do not decode their payloads by
port, so build these classes from `udp.data` or `tcp.data` yourself.

```python
from octetrail import netbios

query = netbios.NS(
    id=7, op=0x0110, qd=[netbios.NS.Q(name=netbios.encode_name("WORKGROUP"), type=netbios.NS_NB)]
)
parsed = netbios.NS(bytes(query))
assert netbios.decode_name(parsed.qd[0].name) == "WORKGROUP"
```

## Names

`encode_name(name)` pads or cuts the text to 16 bytes and turns each half-byte
into a letter from `A` to `P`. `decode_name(nbname)` reverses it up to the
first NUL, and returns a name that is not 32 characters long as it is.
`node_to_service_name((name, service, flags))` looks a NODE STATUS entry up in
`nbstat_svcs`, dpkt's table of well-known services, and returns `""` when none
matches.

## Name service

`NS` is a `dns.DNS` subclass, so it has the same header, sections, flags and
packing. Its `NS.RR` records set `ip` for type `NS_A` and `nodenames` for
`NS_NBSTAT`: a list of `(name, service, flags)` tuples, one per name the count
byte announces. As in dpkt, the statistics after the names are not read, and
other types, including `NS_NB`, keep only `rdata`.

## Session and datagram service

`Session` has `type`, `flags` and `len`. `Datagram` has `type`, `flags`, `id`,
`src`, `sport`, `len` and `off`. Anything after the header is `data`. The
`SSN_*`, `DGRAM_*` and `NS_*` constants are dpkt's.

## Errors

A header shorter than its fixed length raises `NeedData`, and a NODE STATUS
record with fewer names than its count raises `UnpackError`, as in dpkt. Name
service errors are otherwise those of [DNS](dns.md).

One difference is declared: a NODE STATUS record with empty resource data
raises `IndexError` in dpkt. OctetRail raises `netbios.NodeStatusError`, which
subclasses both `UnpackError` and `IndexError` and keeps dpkt's message.

## Verification

`tools/netbios_differential.py` parses 16 messages and builds, packs and
decodes names, comparing 32 observations with dpkt 1.9.8. OctetRail must equal
it on every observation except the declared one. dpkt's own NetBIOS tests also
pass against OctetRail.

```sh
python3 tools/netbios_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
