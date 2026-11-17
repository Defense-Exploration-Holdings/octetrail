# Telnet

`octetrail.telnet` strips Telnet option negotiation the way dpkt 1.9.8 does,
with the scan in Rust. dpkt has no Telnet packet class, and neither does
OctetRail. TCP does not decode its payload by port, so call `strip_options` on
`tcp.data` yourself.

```python
from octetrail import telnet

lines, options = telnet.strip_options(b"\xff\xfa\x27\x00USER\x01bob\x00\xff\xf0ls\r\x00")
assert lines == [b"ls"] and options == {b"USER": b"bob"}
```

## strip_options

`strip_options(buf)` returns a list of lines and a dict of suboption values.
As in dpkt, the buffer is split at each IAC byte (255), and each piece is read
by its first byte:

- WILL, WONT, DO, DONT and IAC drop two bytes.
- SE drops one byte and ends a suboption.
- SB starts a suboption. Its `USER`, `DISPLAY` and `TERM` values, each up to
  the next NUL, go into the dict, and the piece is dropped.
- Other pieces are dropped inside a suboption and kept outside one.

Kept text has NUL bytes turned into line breaks, is split with
`bytes.splitlines()`, and loses one trailing empty line. Lines and values are
slices of the buffer, so a `bytearray` gives `bytearray` slices. A buffer
without a `split` method fails as it does in dpkt. The constants, such as
`IAC`, `SB` and `SE`, are dpkt's.

## Verification

`tools/telnet_differential.py` runs dpkt's three captures, 14 edge cases and
300 generated buffers made of the bytes the scan treats specially, and
compares every result with dpkt 1.9.8. There are no declared differences.
dpkt's own Telnet tests also pass against OctetRail.

```sh
python3 tools/telnet_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
