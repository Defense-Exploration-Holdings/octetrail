# HTTP/2

`octetrail.http2` parses and packs HTTP/2 frames (RFC 7540) the way dpkt 1.9.8
does. The frame classes use the [`Packet`](packet.md) base, as in dpkt, and
`frame_multi_factory` finds frame boundaries in Rust. Header blocks are kept as
bytes. HPACK is not decoded, as in dpkt.

```python
from octetrail import http2

wire = b"\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x10\x00"
frames, used = http2.frame_multi_factory(wire + b"\x00\x00")
assert frames[0].window_increment == 4096
assert used == len(wire)
```

## Frames

`Frame` has `length_bytes`, `type`, `flags` and `stream_id`, and `length` is
the 24-bit length as a number. `FrameFactory(buf)` builds the class for the
frame type: `DataFrame`, `HeadersFrame`, `PriorityFrame`, `RSTStreamFrame`,
`SettingsFrame`, `PushPromiseFrame`, `PingFrame`, `GoAwayFrame`,
`WindowUpdateFrame` or `ContinuationFrame`. Each sets dpkt's attributes, such
as `payload`, `block_fragment`, `priority`, `settings`, `error_code` or
`window_increment`. `Preface` checks the client connection preface.

`frame_multi_factory(buf, preface=False)` returns the frames read from `buf`
and the number of bytes they used. A cut-off frame at the end is left unread,
and so is everything after a frame whose own fields are cut off. Each frame is
built from its own bytes, so a long stream parses in linear time.

## Packing

`bytes()` packs the 9-byte header and `data`. `length_bytes` is packed as it
is. It is not computed.

## Errors

- A buffer shorter than a frame header or its stated length raises `NeedData`.
- An unknown frame type, a bad preface and frames whose payload does not fit
  their type raise `HTTP2Exception` with dpkt's messages.

dpkt derives `HTTP2Exception` from `Exception` only. Here it is also an
`UnpackError`, so code that catches parse errors handles it.

## Verification

The [fixture driver](../tools/http2_differential.py) parses 47 frames and
streams, including every frame type and error, and builds frames from
keywords. OctetRail must equal dpkt 1.9.8 on all 57 observations except the
declared exception class:

```sh
python3 tools/http2_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
