# Offline PCAPNG writer subset

`octetrail.pcapng.Writer` emits one PCAPNG 1.0 section with unknown section length,
one interface and Enhanced Packet Blocks. It writes to a supplied binary file
or in-memory file-like output. The core is `octetrail::pcapng_writer::Writer`.
The writer does not start services, collect traffic or open network interfaces.

```python
from octetrail import pcapng

with open("synthetic.pcapng", "xb") as output:
    writer = pcapng.Writer(output, snaplen=64, linktype=147,
                          section_comment=b"synthetic", interface_name=b"if0")
    writer.writepkt(b"ordinary synthetic bytes", ts=1.25)
    writer.flush()
```

The example creates a local file without overwriting an existing one. As with
classic Writer, close() and the writer context manager close the supplied file.
The outer file context in this example owns cleanup. flush(), closed and writer
context-manager support are OctetRail additions; no durability promise is made.

## Seconds-based methods and exact ticks

The covered dpkt-style call shape is
`Writer(fileobj, snaplen=1500, linktype=1, shb=None, idb=None)`, with only None
accepted for shb and idb. Non-None block arguments raise NotImplementedError
before output. Full block classes and multiple interface descriptions are not
implemented. Python uses host byte order, executed here only on little-endian
Linux. Native Options also support big endian, verified with literal fixtures.

For the default microsecond clock with zero offset, writepkt, writepkt_time,
writepkts and close form the measured API subset. Packet arguments must be bytes.
There is no implicit bytes() conversion or EPB-object input. writepkts consumes
`(seconds, bytes)` pairs incrementally and does not collect them. Methods return
None. writepkt without a timestamp uses local time(); tests fix that clock.

Seconds inputs are nonnegative int or float. Total ticks are `round(ts * 1e6)`,
matching both references on the tested cases. This is total-tick rounding, not
classic pcap's separate fractional rounding. Decimal seconds, arbitrary numeric
objects, negative seconds and out-of-u64 rounded values are unsupported.

`writepkt_ticks(bytes, ticks)` is an explicit OctetRail addition. It accepts an
unsigned 64-bit integer count without time conversion, including zero and the
maximum field value. The native API likewise writes exact ticks, and additionally
accepts an original wire length distinct from the captured length.

## Supported metadata options

The following keyword-only additions expose primitive options without pretending
to implement dpkt's block object model:

| Keyword | Wire option | Accepted value |
| --- | --- | --- |
| section_comment | SHB comment, code 1 | UTF-8 bytes, at most 65535 bytes |
| interface_name | IDB name, code 2 | UTF-8 bytes, at most 65535 bytes |
| timestamp_resolution | IDB if_tsresol, code 9 | Encoded byte 0 through 255 |
| timestamp_offset | IDB if_tsoffset, code 14 | Signed 64-bit seconds |

None omits an option; an empty byte value or an explicit 6/0 clock value remains
an option on the wire. Resolution byte bit 0x80 selects base two; otherwise the
base is ten. The remaining seven bits are the negative-power exponent. The
absent default is decimal exponent six. Offset is encoded as signed seconds.
Options have deterministic order, zero padding and a final end marker whenever
an option is present. Packet blocks have no options and use interface zero.

These options describe the clock; they do not silently transform raw ticks.
Seconds methods are enabled only for absent/explicit decimal-microsecond
resolution and absent/explicit zero offset. Other clocks require writepkt_ticks:

```python
writer = pcapng.Writer(output, timestamp_resolution=0x8a, timestamp_offset=-2)
writer.writepkt_ticks(b"abc", 1024)
```

Here the declared time is -2 + 1024/1024 = -1 seconds. Calling writepkt_time with
this custom clock raises NotImplementedError before a packet is emitted. Both
dpkt baselines' buffer methods continue to encode microseconds regardless of
custom interface clock options. OctetRail does not reproduce that mismatch.
The comparison harness uses upstream SHB/IDB/EPB objects as controls for explicit
option/tick bytes. That verifies serialization, not those object APIs in OctetRail.

## Limits and failure behavior

max_packet_bytes defaults to 16 MiB; max_block_bytes defaults to 32 MiB. The
block limit covers SHB, IDB and padded EPB lengths, including framing and trailers.
Both initial metadata blocks are fully validated before either is written.
Metadata text bounds, UTF-8, clock bounds and all record lengths are checked.
Snap length zero means unlimited by that field; the policy limits still apply.
Packet bytes cannot exceed original length or a nonzero snap length.

All record validation precedes output and leaves the writer usable on failure.
Any I/O or flush failure is terminal and may leave a block prefix, including a
partially written trailer. No rollback, implicit resume, total capture size cap,
packet-count cap, timeout, concurrency guarantee or benchmark is provided.
close() remains available for cleanup. Original Python output exceptions retain
identity; Rust-native interrupted writes retry normally. Short writes complete,
zero progress is an OSError, and invalid sink counts are errors. Exact write-call
patterns and error messages are outside parity. The native wrapper does not
flush on drop or into_inner; the sink's own lifetime behavior still applies.

Native output uses fixed headers and borrowed payload/metadata bytes, without
allocating a packet/block serialization buffer. The shared Python adapter copies
at most 64 KiB per output call. Caller buffers, metadata already created by the
caller and retained sink data add memory; this is not a process memory bound.

## Verify installed wheels

Use the [isolated wheel build process](python-reader.md#build-locally), install
only into fresh environments and run the offline checks:

```sh
NEW_ENV/bin/python -I -m unittest discover -s "$PWD/tests/python"
python3 tools/pcapng_writer_differential.py --python NEW_ENV/bin/python --oracle-198 "$PWD/.venv-oracle-198/bin/python" --oracle-196 "$PWD/.venv-oracle-196/bin/python"
```

Replace environment paths with real paths. Seconds-method comparisons and raw
tick/option byte comparisons are separate checks; neither establishes full
object API or application compatibility.

Multiple sections/interfaces, finite section lengths, arbitrary options, packet
options, block-object mutation and serialization, full constants, other packet
block types and full subclass/private-attribute behavior are not implemented.
Protocol objects, a dpkt namespace and package resolver substitution remain
outside the supported API. A verified wheel or writer output does not establish
application compatibility.
