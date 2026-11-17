# ARP

`octetrail.arp` parses and packs ARP messages the way dpkt 1.9.8 does, with
dpkt's class and constants. ARP has a fixed header only, so the
[`Packet`](packet.md) base reads it, as in dpkt. Ethernet decodes type 0x0806
as ARP, directly, after 802.1Q tags and inside LLC/SNAP, and packs an `ARP`
payload with that type.

```python
from octetrail import arp, ethernet

request = arp.ARP(sha=b"\x02" * 6, spa=b"\x0a\x00\x00\x01", tpa=b"\x0a\x00\x00\x02")
frame = ethernet.Ethernet(dst=b"\xff" * 6, src=b"\x02" * 6, data=request)
assert ethernet.Ethernet(bytes(frame)).arp.tpa == b"\x0a\x00\x00\x02"
```

`ARP` has `hrd`, `pro`, `hln`, `pln`, `op`, `sha`, `spa`, `tha` and `tpa`.
As in dpkt, the addresses are always six and four bytes, whatever `hln` and
`pln` say, and any bytes after them, such as Ethernet padding, are in `data`.
A message shorter than 28 bytes raises `NeedData`. There are no other parse
errors, and no differences from dpkt 1.9.8.

`tools/arp_differential.py` parses 10 messages and frames and builds and
repacks messages from keywords. OctetRail must equal dpkt 1.9.8 on every
observation:

```sh
python3 tools/arp_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
