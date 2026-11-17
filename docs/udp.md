# UDP

`octetrail.udp` parses and packs UDP datagrams the way dpkt 1.9.8 does. The
header is fixed, so the [`Packet`](packet.md) base reads it, as in dpkt. The
module has `UDP_HDR_LEN` and `UDP_PORT_MAX`. The native Rust API is
`octetrail::udp`.

```python
from octetrail import udp

datagram = udp.UDP(sport=32000, dport=53, ulen=12, data=b"note")
assert udp.UDP(bytes(datagram)).data == b"note"
```

`UDP` has `sport`, `dport`, `ulen`, `sum` and `data`, with dpkt's defaults:
source port `0xdead` and `ulen` 8. A buffer shorter than 8 bytes raises
`NeedData`, and everything after the header is `data`, whatever `ulen` says.
`ulen` and `sum` are packed as assigned and never inferred. IPv4 and IPv6 fill a
zero `sum` when they pack a datagram, and send a sum that computes to zero as
`0xffff`. There is no size limit, so a jumbo IPv6 payload decodes as UDP too.

`tools/tcp_udp_differential.py` checks UDP together with TCP; see the
[TCP guide](tcp.md#verification).
