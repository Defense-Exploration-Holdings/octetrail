# Offline PCAPNG reader

The native `octetrail::pcapng::Reader` and Python `octetrail.pcapng.Reader` read
a bounded PCAPNG 1.0 Enhanced Packet Block subset. They use only ordinary local
files or caller-supplied synchronous binary streams. They perform no collection,
protocol decoding, service startup or network operation.

```python
from octetrail import pcapng

with pcapng.open("synthetic.pcapng", max_packet_bytes=1024 * 1024) as reader:
    for timestamp, payload in reader:
        print(timestamp, len(payload))
```

`Reader(fileobj)` borrows the input. `open(path)` owns its local file and supports
a context manager. The inherited classic-reader convenience methods and explicit
close behavior are described in [python-reader.md](python-reader.md). The two
formats are selected explicitly; the classic CLI and Reader do not autodetect
PCAPNG. The separate [UniversalReader factory](universal-reader.md) picks the format
from the magic bytes.

## Covered format and time model

Construction validates the initial Section Header Block and scans to the first
Interface Description Block. Empty captures with an interface are accepted;
a file with no interface is rejected. New sections reset interface numbering
and may change byte order. Finite section lengths and unknown-length sections
are supported. Version 1.0 is accepted; other versions are rejected.

Enhanced Packet Blocks use the referenced section-local interface. Default
resolution is decimal microseconds. `if_tsresol` supports decimal and binary
exponents, including the full encoded exponent range. `if_tsoffset` is a signed
64-bit seconds offset. Snap length zero means unlimited in this format; the
independent allocation limits still apply. Captured length cannot exceed a
nonzero snap length or the declared original length.

Rust returns exact unsigned ticks, a decimal/binary resolution descriptor and
the signed offset, alongside section index, interface id, link type, original
length and owned bytes. It performs no float conversion. Python yields
`offset + ticks / float(base ** exponent)` and owned bytes by default. PCAPNG timestamps
are floats even at nanosecond resolution, matching both measured dpkt baselines.
This differs from classic-pcap nanosecond Decimal timestamps.

The optional `decimal_timestamps=True` keyword on `Reader` and `open` instead
returns exact Decimal values, using each packet's interface clock and signed
offset. Both binary and decimal clocks have finite decimal representations.
Conversion uses integer fields directly and is independent of Decimal context.
See the [Decimal timestamp guide](decimal-timestamps.md). This is an OctetRail
extension; the default tuple values and types retain their existing behavior.

Python metadata attributes describe the first interface. Its `(timestamp, bytes)`
tuples omit packet-level interface identity and link type. Mixed-link captures
therefore need the Rust record API when that metadata matters. Do not decode all
records using the first interface's link type. No Python block/idb objects are
provided. Reentrant reading, concurrent iterator use from threads, external
seeking and append-after-EOF behavior are outside the contract.

Each block's declared length, alignment and repeated trailer length are checked.
Option lengths and padding boundaries are checked; padding byte values are
ignored and never returned as payload. If options are present, this implementation
requires a final zero-length end marker with no extra bytes after it. Duplicate
resolution or offset options and wrong lengths for those options are rejected.
Unknown options are skipped. Unknown and uninterpreted metadata blocks are
skipped only after generic framing validation; their internal semantics are not
validated. A block body is read before an interface or packet is interpreted.

Deprecated Packet Blocks and timestamp-less Simple Packet Blocks raise
NotImplementedError in Python, rather than silently losing packets. Native
unsupported-block errors preserve the block type. The separate
[limited writer](pcapng-writer.md) emits an EPB subset. Block/option object APIs,
full constant exports and filter execution remain absent.

## Limits and error behavior

| Keyword / Rust Limits field | Default | Scope |
| --- | --- | --- |
| max_packet_bytes | 16 MiB | Captured packet copy |
| max_block_bytes | 32 MiB | Entire framed block, including metadata and unknown types |
| max_interfaces | 1024 | Interface table within one section |
| max_blocks_per_read | 4096 | Blocks scanned to the first interface or next packet/EOF |

The initial Section Header Block is checked separately before constructor
scanning. A scan reaching its budget fails even if the next read would have
found EOF. Limits are unsigned 32-bit policy values and may be reduced, including
to zero. Block length is checked before body allocation or body reading. Packet
length policy is checked after block framing but before making the owned packet
copy. Peak native memory can include one block body, one packet copy and a bounded
interface table. Python outputs, input buffers and retained records add memory.
Unknown blocks are also subject to the block cap. No process memory cap, total
capture byte cap, total packet cap, benchmark, deadline or timeout is claimed.
Custom read methods can allocate or block independently.

EOF and any native read or validation error terminate iteration. Truncated block
headers, bodies and trailers map to NeedData. Invalid framing, options, references
and supported-version checks raise ValueError. `pcapng.LimitError` is the same
ValueError subclass used for classic-pcap policy limits. Caller input exceptions
propagate by identity, and owned-path constructor failures close their file.
Allocator failures map to MemoryError but have not been deterministically injected.
These error families and strict policies are not full dpkt error parity.

The format references are the published dpkt artifacts and the field descriptions
in [the PCAPNG format draft](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-05.html),
a work in progress. No code or prose from that draft is copied into the parser.

## Verify installed wheels

Use the existing pinned [wheel build process](python-reader.md#build-locally).
Install only into a fresh environment outside the source tree. No package is
published and no existing application environment is changed.

```sh
python3 tools/check_wheel.py dist/*.whl
NEW_ENV/bin/python -I -m unittest discover -s "$PWD/tests/python"
python3 tools/pcapng_differential.py --python NEW_ENV/bin/python --oracle-198 "$PWD/.venv-oracle-198/bin/python" --oracle-196 "$PWD/.venv-oracle-196/bin/python"
```

Replace NEW_ENV and oracle paths with those actually created. Tests use independent
synthetic field encoders, two reviewed literal fixtures and exact expected values.
