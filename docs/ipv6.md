# IPv6 and raw-IP decoding

`octetrail.ip6` parses and packs IPv6 packets and their extension headers the
way dpkt 1.9.8 does. The extension header chain is read in Rust. `IP6` and the
extension header classes are [`Packet`](packet.md) subclasses, as in dpkt.

```python
from octetrail import ethernet, ip6, raw, udp

child = udp.UDP(sport=32000, dport=32001, ulen=12, data=b"note")
packet = ip6.IP6(src=bytes.fromhex("20010db8000000000000000000000001"),
                 dst=bytes.fromhex("20010db8000000000000000000000002"),
                 nxt=17, plen=len(child), hlim=32, data=child)
wire = bytes(packet)
assert raw.decode(wire).udp.data == b"note"
frame = ethernet.Ethernet(data=packet)
assert ethernet.Ethernet(bytes(frame)).ip6.udp.data == b"note"
```

## Fields

`IP6` has `v`, `fc`, `flow`, `plen`, `nxt`, `hlim`, `src`, `dst` and `data`.
A parsed packet also has `extension_hdrs`, a dict from header type to the last
header of that type, `all_extension_headers`, a list in wire order, and `p`, the
protocol after the last extension header. A new packet has none of these three.
The version is not checked.

## Parsing

1. The payload is `plen` bytes after the 40-byte header, cut to the bytes
   present. When `plen` is 0, it is everything after the header.
2. Extension headers are read while the next header is hop-by-hop options (0),
   routing (43), fragment (44), AH (51), ESP (50) or destination options (60):

   | Class | Length moved past | Other attributes |
   | --- | --- | --- |
   | `IP6HopOptsHeader`, `IP6DstOptsHeader` | `(len + 1) * 8` | `options`, a list of dicts with `type`, `opt_length` and `data`, skipping Pad1 and PadN |
   | `IP6RoutingHeader` | `len * 8 + 8` | `addresses`, `sl_bits` |
   | `IP6FragmentHeader` | 8 | `frag_off`, `m_flag` |
   | `IP6AHHeader` | `(len + 2) * 4` | `auth_data` |
   | `IP6ESPHeader` | everything left | none, and no `nxt` |

   Each header has `length` and `data` too. As in dpkt, options are read past
   the declared length when an option says so, an AH header's `data` is
   everything after its fixed fields, and ESP ends the chain without setting `p`.
3. When `nxt` is 44 and the last extension header has a nonzero `frag_off`,
   `data` is the rest as bytes. If that last header is not a fragment header,
   dpkt raises `AttributeError`. OctetRail raises `FragmentOffsetError`, which
   subclasses both `UnpackError` and `AttributeError`, so Ethernet keeps the
   payload as bytes.
4. Otherwise the rest is decoded with `IP6.get_proto(p)`. TCP, UDP, IPv4 and
   IPv6 are decoded, and `.tcp`, `.udp`, `.ip` or `.ip6` is set. Other protocols,
   and payloads that raise `UnpackError`, stay bytes. `IP6.set_proto` adds a
   class. A UDP payload larger than 65535 bytes, possible when `plen` is 0, is
   decoded as UDP without the standalone UDP size limit and packs back as it
   is. dpkt also decodes ICMP, ICMPv6, IGMP, GRE, OSPF, PIM, VRRP, STP and
   SCTP, which OctetRail does not have yet.

## Errors

- `NeedData`: the input is shorter than 40 bytes, an extension header is
  shorter than its fixed fields, or an option runs past the end. The headers
  read before it stay in `extension_hdrs` and `all_extension_headers`.
- `FragmentOffsetError`: see step 3 above.
- `ValueError`: a bit field value does not fit.
- `PackError`: a header field does not fit its format.

There are no size or count limits. A parsed AH header copies its `data` and
`auth_data` out of the packet on first use, so long AH chains parse in linear
time.

## Packing

`bytes()` packs the 40-byte header, then the extension headers, then `data`:

- A parsed packet packs `all_extension_headers` in order and takes `p` from the
  last one. A packet with only `extension_hdrs` packs them in the order of
  `ip6.EXT_HDRS` and takes `p` from the last.
- When `p` is 6, 17 or 58 and the payload has a `sum` of 0, the checksum is
  computed over the IPv6 pseudo-header and set on the payload. A UDP checksum
  of 0 is not changed to `0xffff`, as in dpkt. A nonzero `sum` is kept.
- `plen` is packed as it is. It is not computed.

`len()` is 40 plus the extension headers and `len(data)`.

## Raw IP

`raw.decode(bytes)` selects IPv4 or IPv6 from the version nibble. Empty input
raises `NeedData`, other versions raise `UnpackError`, and non-bytes input
raises `TypeError`. Capture readers do not call it, so call it on each
raw-IP record yourself. dpkt has no such function.

## Measured compatibility

The [fixture driver](../tools/ipv6_differential.py) parses 35 packets, including
dpkt's own test vectors, builds and changes packets and extension headers, and
compares 66 observations against dpkt 1.9.6 and 1.9.8:

```sh
python3 tools/ipv6_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```

OctetRail matches 1.9.8 on all of them except the `FragmentOffsetError` case,
which the driver lists as a declared difference. The packets only use payload
protocols both libraries decode.
