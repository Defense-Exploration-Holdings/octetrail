# TCP headers with opaque options

`octetrail.tcp.TCP` reads and writes an offline TCP header, opaque option bytes and
an opaque payload the way dpkt 1.9.8 does. The native Rust core borrows the input
payload; the Python interface returns owned bytes. This API performs no network
operation.

```python
from octetrail import tcp

segment = tcp.TCP(sport=49152, dport=443, seq=1, ack=2,
                  flags=tcp.TH_PUSH | tcp.TH_ACK, sum=0x1234, data=b"offline")
wire = bytes(segment)
parsed = tcp.TCP(wire)
assert parsed.data == b"offline"
assert parsed.sum == 0x1234
assert len(parsed) == 20 + len(parsed.data)
```

The checksum is caller-supplied. Its value, including zero, is preserved exactly
when other fields or the payload change. It is not automatically validated. Standalone TCP serialization never computes
it. The [IPv4 composition path](composition.md) can fill a zero sum.

## Supported fields and operations

Construct with field keywords or one positional `bytes` buffer. A positional
buffer ignores field keywords, matching both pinned references. More positional
arguments and unknown constructor keywords raise `TypeError`.

| Field | Wire width | Default |
| --- | --- | --- |
| `sport`, `dport` | Unsigned 16 bits each | `0xdead`, `0` |
| `seq`, `ack` | Unsigned 32 bits each | `0xdeadbeef`, `0` |
| `_off_flags` | Unsigned 16 bits: offset, reserved bits and flags | `0x5002` |
| `off` | High four bits of `_off_flags`, in 32-bit words | `5` |
| `_rsv` | Next three bits of `_off_flags` | `0` |
| `flags` | Low nine bits of `_off_flags`, including `TH_NS` | `TH_SYN` (`2`) |
| `win` | Unsigned 16 bits | `65535` |
| `sum`, `urp` | Unsigned 16 bits each | `0`, `0` |
| `opts` | Opaque bytes | `b''` |
| `data` | Opaque bytes | `b''` |

All fields are mutable. `off`, `_rsv` and `flags` read and write their bits of
`_off_flags`; assigning a value too large for its bits raises `ValueError`, as
dpkt does. `bytes(segment)` writes the header, then `opts`, then `data`, exactly as
assigned: `off` is not derived from the options and is not checked against them.
`len(segment)` returns 20 plus the option and payload lengths. `pack_hdr()` returns
only the 20-byte header. Repeated serialization does not change fields or
checksum values.

`tcp.parse_opts(buf)` splits option bytes into `(kind, data)` tuples as dpkt does.
Kinds 0 and 1 are single bytes. Other kinds read a length byte, counted as at
least two, and take the bytes after it up to that length or the end of the
buffer. A kind with no length byte ends the list with `None`.
`tcp.tcp_flags_to_str(flags)` names the set flags, for example `'SYN,ACK'`.

The exported constants are `TH_FIN` through `TH_CWR` (1 through 128), `TH_NS`
(256), the `TCP_OPT_*` option kinds, `TCP_PORT_MAX` and `TCP_WIN_MAX` (65535) and
`TCP_HDR_LEN` (20).

## Errors, limits and excluded behavior

A buffer shorter than 20 bytes raises `NeedData`, a subclass of `UnpackError` and
`Error`. A data offset below five raises `UnpackError`. Nothing else is checked
when parsing: the options are the bytes from 20 up to the declared header length
that are present, and the payload is whatever follows. A buffer shorter than the
declared header gives short options and no payload, as in dpkt. Reserved and
nonce bits are kept. The error messages are not a compatibility promise.

For the scalar fields in the table, non-integers and out-of-range values raise
`PackError` when serialized. `PackError` inherits from `Error`. Non-bytes input,
payload or option objects raise `TypeError` when used by their corresponding
operations.

The default complete-segment limit is 16 MiB, including the 20-byte header.
Parsing and complete serialization reject a one-byte excess with `tcp.LimitError`,
a `ValueError` subclass; dpkt has no such limit. Native serialization validates
before reserving its output buffer. Rust callers can choose `tcp::Limits`. This is
an offline resource policy, not a TCP/IP maximum or a total process-memory bound.
Allocation errors are mapped but not deliberately induced in tests.

dpkt 1.9.6 keeps the nonce and reserved bits in one offset byte and has eight
flags; 1.9.8 has nine flags and a separate `_rsv`. OctetRail follows 1.9.8, and
the comparison below records those cases as version differences. Implicit
payload conversion, application protocols, generic `dpkt.Packet` methods,
connection state, retransmission and stream reassembly are outside this API.
Ethernet/IPv4 dispatch is documented in the composition guide.

## Reproduce the comparisons

All fixtures are original offline byte sequences. A reviewed
[literal header/payload](../tests/fixtures/tcp-base.hex) and an independent
[struct encoder](../tools/tcp_cases.py) define expected fields and bytes. Fixture
tests also decode unsigned values using direct byte arithmetic. No packet
library encodes the oracle inputs.

```sh
python3 -B -I -m unittest discover -s tests/python -p test_tcp_fixtures.py -v
```

Install the two references in separate environments using
`tools/oracle-1.9.6.txt` and `tools/oracle-1.9.8.txt` with
`pip install --require-hashes --only-binary=:all: -r REQUIREMENTS`. Build wheels
with the [existing build instructions](python-reader.md#build-locally) and
install each into a fresh environment containing no dpkt. Then run:

```sh
python3 -B tools/tcp_differential.py --oracle-196 /tmp/oracle-196/bin/python --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
/tmp/octetrail-wheel/bin/python -B -I -m unittest discover -s tests/python -p 'test_tcp*.py' -v
```

The probe verifies isolated installed module origins and distribution versions.
Fields, exact bytes, header bytes, lengths, mutation, stable outputs and error
families/phases are checked against independent expectations. Five cases where
dpkt 1.9.6 and 1.9.8 differ are measured separately; OctetRail must match 1.9.8
on them.
Omitting `--python` validates only the oracles and reports OctetRail pending.
These comparisons do not establish downstream compatibility.

Probe provenance and comparison checks use explicit failures that remain active
under Python optimization. Wrong requested versions, non-isolated execution and
incorrect module origins fail before a verified report is emitted. Optimized-mode
negative controls exercise those failures and corrupted comparison results:

```sh
/tmp/octetrail-wheel/bin/python -B -I -O -m unittest discover -s tests/python -p 'test_tcp*.py' -v
```
