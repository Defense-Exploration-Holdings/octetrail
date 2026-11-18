# SLL, SLL2 and loopback

`octetrail.sll`, `octetrail.sll2` and `octetrail.loopback` parse and pack the
link-layer headers of Linux cooked captures and of BSD null/loopback captures
the way dpkt 1.9.8 does. All three are fixed headers on the
[`Packet`](packet.md) base, as in dpkt. Choose the class from the capture's
link type; nothing here reads a capture file.

```python
from octetrail import ip, sll

frame = sll.SLL(type=4, hdr=b"\x02" * 6, data=ip.IP(p=59))
parsed = sll.SLL(bytes(frame))
assert parsed.ethtype == 0x0800 and isinstance(parsed.ip, ip.IP)
```

## SLL and SLL2

`SLL` has `type` (0 to us, 1 broadcast, 2 multicast, 3 other, 4 from us),
`hrd`, `hlen`, an eight-byte `hdr` and `ethtype`. `SLL2` has `ethtype`, `mbz`,
a signed `intindex`, `hrd`, `type`, `hlen` and `hdr`. Both decode the payload
through the [Ethernet type table](ethernet.md#the-type-table), which they
share, and also set it as an attribute named after its class. An unknown type,
or a payload that raises `UnpackError`, leaves the bytes.

## Loopback

`Loopback` has one `family` word in the byte order of the machine that reads
it, as in dpkt. Families 2, 24, 28 and 30, in either byte order, are stored as
those values and decode the payload as IPv4 or IPv6. Any other family decodes
the payload as Ethernet. Errors from the payload are not caught, as in dpkt,
so a short payload raises `NeedData`.

## Errors

A header shorter than its fixed length raises `NeedData`.

One difference from dpkt 1.9.8 is declared. When the payload is IPv6 whose fixed
header has `nxt` 44 while its last extension header is not a fragment header,
dpkt raises `AttributeError` out of `SLL`, `SLL2` and `Loopback`. OctetRail raises
[`FragmentOffsetError`](ipv6.md#errors) for that packet, which is an
`UnpackError`. `SLL` and `SLL2` keep it as bytes, as `IP` and `Ethernet` do.
So do IPv4 carrying such IPv6 under any of the three headers, and Ethernet
carrying it under `Loopback`.
`Loopback` decodes IPv6 without catching errors, as dpkt does, so the error
escapes. It subclasses `AttributeError` and has dpkt's message.

## Verification

`tools/sll_loopback_differential.py` parses 28 captured headers, including
dpkt's test vectors, and builds and repacks headers from keywords. OctetRail
must equal dpkt 1.9.8 on every observation except the declared fragment offset
cases. dpkt's own SLL, SLL2 and loopback
tests also pass against OctetRail.

```sh
python3 tools/sll_loopback_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
