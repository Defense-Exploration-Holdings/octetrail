# Portmap, Rx, TNS, Yahoo Messenger, SMB and RFB

These modules parse and pack fixed protocol headers the way dpkt 1.9.8 does.
Each class is a [`Packet`](packet.md) subclass, as in dpkt, and anything after
the header is `data`. UDP and TCP do not decode their payloads by port, so
build these classes from `udp.data` or `tcp.data` yourself.

```python
from octetrail import smb

header = smb.SMB(cmd=0x72, uid=2048)
header.pid = 528416
assert smb.SMB(bytes(header)).pid == 528416
```

| Module | Classes | Notes |
| --- | --- | --- |
| `pmap` | `Pmap` | `prog`, `vers`, `prot`, `port`; `PMAP_*` constants |
| `rx` | `Rx` | The Rx header of AFS, with dpkt's type, flag and security constants |
| `tns` | `TNS` | `msg` is the next `length - 8` bytes and `data` the rest |
| `yahoo` | `YHOO`, `YMSG` | `YHOO` is little-endian |
| `smb` | `SMB` | Little-endian; `pid` joins `_pidhi` and `_pidlo`; `SMB_FLAGS*` constants |
| `rfb` | `RFB`, `SetPixelFormat`, `SetEncodings`, `FramebufferUpdateRequest`, `KeyEvent`, `PointerEvent`, `FramebufferUpdate`, `SetColourMapEntries`, `CutText` | Message type and message bodies; `CLIENT_*` and `SERVER_*` constants |

As in dpkt, the text fields of `YHOO` and `YMSG` default to strings, so a
header built without them raises `PackError` when packed. A `TNS` packet packs
its header and `data`, not `msg`.

## Errors

A header shorter than its fixed length raises `NeedData`. A TNS packet whose
`length` runs past the bytes present raises `NeedData` with dpkt's "short
message" text. There are no declared differences.

## Verification

`tools/small_apps_differential.py` parses 27 messages, including dpkt's SMB
and TNS vectors, and builds and packs each class, comparing 47 observations
with dpkt 1.9.8. dpkt's own SMB and TNS tests also pass against OctetRail.

```sh
python3 tools/small_apps_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
