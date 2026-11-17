# NTP, RIP, TFTP and HSRP

`octetrail.ntp`, `octetrail.rip`, `octetrail.tftp` and `octetrail.hsrp` parse
and pack these UDP application messages the way dpkt 1.9.8 does. The classes
are [`Packet`](packet.md) subclasses, as in dpkt, and RIP's route entries are
found in Rust. As in dpkt, UDP does not decode its payload by port, so build
these classes from `udp.data` yourself.

```python
from octetrail import tftp

request = tftp.TFTP(opcode=tftp.OP_RRQ, filename=b"boot.img", mode=b"octet")
parsed = tftp.TFTP(bytes(request))
assert (parsed.filename, parsed.mode) == (b"boot.img", b"octet")
```

## NTP

`NTP` has `flags`, with `li`, `v` and `mode` as bit fields, then `stratum`,
`interval`, `precision`, `delay`, `dispersion`, a four-byte `id` and the four
eight-byte timestamps. Anything after the 48-byte header is `data`. As in dpkt,
the byte-string fields default to 0, so a message built without them raises
`PackError` when packed.

## RIP

`RIP` has `cmd`, `v` and `rsvd`, then 20-byte entries. Entries with an address
family of 0xFFFF are authentication entries; the last one is `auth`, and the
others are `RTE` objects in `rtes`, which is also `data`. Packing writes the
header, `auth` when it is set, and `rtes`.

## TFTP

`TFTP` has `opcode` and the fields it selects: `filename` and `mode` for read
and write requests, `block` and `data` for data and acknowledgments, and
`errcode` and `errmsg` for errors. Other opcodes keep the rest in `data`.
`len()` is the length of the packed message.

## HSRP

`HSRP` has `version`, `opcode`, `state`, `hello`, `hold`, `priority`, `group`,
`rsvd`, an eight-byte `auth` (`cisco` by default) and a four-byte `vip`.

## Errors

A header shorter than its fixed length raises `NeedData`, and so does a RIP
entry cut off by the buffer. A TFTP data, acknowledgment or error message
without its two-byte field raises `UnpackError`, as in dpkt.

One difference is declared: a TFTP read or write request without a NUL after
the file name raises `IndexError` in dpkt. OctetRail raises
`tftp.RequestError`, which subclasses both `UnpackError` and `IndexError` and
keeps dpkt's message.

## Verification

`tools/ntp_rip_tftp_hsrp_differential.py` parses 26 messages, including dpkt's
test vectors, and builds and repacks messages from keywords. OctetRail must
equal dpkt 1.9.8 on every observation except the declared one. dpkt's own NTP,
RIP and TFTP tests also pass against OctetRail.

```sh
python3 tools/ntp_rip_tftp_hsrp_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
