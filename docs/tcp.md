# TCP headers with opaque options

`octetrail.tcp.TCP` reads and writes an offline 20-byte TCP base header, 0..40 option bytes and an opaque payload. The native Rust core borrows the input payload; the Python
interface returns owned bytes. This API performs no network operation.

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
| `off` | Four bits, in 32-bit words | `5`; values 5..15 are supported |
| `flags` | Shared eight-bit flag surface | `TH_SYN` (`2`) |
| `win` | Unsigned 16 bits | `65535` |
| `sum`, `urp` | Unsigned 16 bits each | `0`, `0` |
| `opts` | Opaque bytes, at most 40 | `b''` |
| `data` | Opaque bytes | `b''` |

All fields are mutable. `bytes(segment)` serializes the fixed header and exact
payload with no padding. `len(segment)` returns 20 plus options and payload length for the
supported fields. `pack_hdr()` returns only the 20-byte header. `unpack(bytes)`
replaces fields only after a complete supported header is validated. Repeated
serialization does not change fields or checksum values.

The exported control constants are `TH_FIN`, `TH_SYN`, `TH_RST`, `TH_PUSH`,
`TH_ACK`, `TH_URG`, `TH_ECE` and `TH_CWR`, with values 1 through 128. `TCP_PORT_MAX`
and `TCP_WIN_MAX` are 65535. `TCP_HDR_LEN` is 20. These are selected constants,
not the full upstream inventory.

## Errors, limits and excluded behavior

An explicitly supplied buffer shorter than 20 bytes raises `NeedData`, a subclass
of `UnpackError` and `Error`. A header whose data offset is below five raises
`UnpackError`. Incomplete option bytes raise `NeedData`; nonzero nonce/reserved bits
raise `NotImplementedError`. The error messages are not a compatibility promise.

For the scalar fields in the table, non-integers and out-of-range values raise
`PackError` when serialized, with field validation deferred until that call.
`PackError` inherits from `Error`. Option bytes must match the assigned data
offset; mismatches raise `PackError`, a deliberate stricter packing rule. Non-bytes input, payload or option
objects raise `TypeError` when used by their corresponding operations.

The default complete-segment limit is 16 MiB, including the 20-byte header.
Parsing and complete serialization reject a one-byte excess with `tcp.LimitError`,
a `ValueError` subclass. Native serialization validates before reserving its
output buffer. Rust callers can choose `tcp::Limits`. This is an offline resource
policy, not a TCP/IP maximum or a total process-memory bound. Caller input,
native output, Python copies and retained objects are separate memory costs.
Allocation errors are mapped but not deliberately induced in tests.

The required flag surface is the eight bits shared by dpkt 1.9.6 and 1.9.8.
In 1.9.8 the nonce bit is exposed as a ninth flag; in 1.9.6 it remains in a
separate internal header byte. This implementation rejects that bit instead of
claiming equivalence across those different interfaces. Nine-bit flags, reserved
bits, option-value parsers, implicit payload conversion, application protocols,
generic `dpkt.Packet` methods, full constant inventories, arbitrary subclass
behavior, connection state, retransmission and stream reassembly are excluded.
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
families/phases are checked against independent expectations. Three declared
scope differences are measured separately and never counted as matching cases.
Omitting `--python` validates only the oracles and reports OctetRail pending.
These comparisons do not establish full TCP or downstream compatibility.

Probe provenance and comparison checks use explicit failures that remain active
under Python optimization. Wrong requested versions, non-isolated execution and
incorrect module origins fail before a verified report is emitted. Optimized-mode
negative controls exercise those failures and corrupted comparison results:

```sh
/tmp/octetrail-wheel/bin/python -B -I -O -m unittest discover -s tests/python -p 'test_tcp*.py' -v
```
