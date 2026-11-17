# TCP

`octetrail.tcp` parses and packs TCP segments the way dpkt 1.9.8 does. The
option bounds and option splitting are computed in Rust. `TCP` is a
[`Packet`](packet.md) subclass, as in dpkt, and the module has dpkt's `TH_*`
and `TCP_*` constants, `tcp_flags_to_str` and `parse_opts`. The native Rust API
is `octetrail::tcp::{Header, Segment, parse_options}`.

```python
from octetrail import tcp

segment = tcp.TCP(sport=32000, dport=80, flags=tcp.TH_SYN | tcp.TH_ACK,
                  off=6, opts=b"\x02\x04\x05\xb4", data=b"ordinary bytes")
parsed = tcp.TCP(bytes(segment))
assert tcp.parse_opts(parsed.opts) == [(tcp.TCP_OPT_MSS, b"\x05\xb4")]
assert tcp.tcp_flags_to_str(parsed.flags) == "SYN,ACK"
```

## Fields

`TCP` has `sport`, `dport`, `seq`, `ack`, `off`, `flags`, `win`, `sum`, `urp`,
`opts` and `data`. `off` (4 bits) and `flags` (9 bits, including the nonce bit)
are bit fields of `_off_flags`, and the 3 reserved bits between them are kept
in `_off_flags`. The defaults are dpkt's: source port `0xdead`, sequence
`0xdeadbeef`, offset 5, SYN and window 65535.

## Parsing and packing

A buffer shorter than 20 bytes raises `NeedData`. A data offset below five
words raises `UnpackError`. `opts` is the bytes from offset 20 to the data
offset, cut to the bytes present, and `data` is everything after it. Slices keep
the type of the buffer.

`bytes()` packs the header, `opts` and `data` as assigned. `off` is not inferred
from the options, and `sum` is packed as it is. IPv4 and IPv6 fill a zero `sum`
when they pack a segment, as described in [composition](composition.md) and
[IPv6](ipv6.md). `len()` is 20 plus `len(opts)` and `len(data)`. There is no
size limit.

`parse_opts(buf)` splits option bytes into `(kind, data)` tuples. EOL and NOP
have no length byte. A length below two moves past two bytes, and an option
whose length byte is missing ends the list with `None`, as in dpkt.

## Verification

`tools/tcp_udp_differential.py` parses 22 segments and datagrams, alone and
inside IPv6, including dpkt's TCP test vectors, and builds, changes and repacks
them from keywords. OctetRail must equal dpkt 1.9.8 on every observation:

```sh
python3 tools/tcp_udp_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
