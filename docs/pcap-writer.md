# Offline classic-PCAP writing

`octetrail.pcap.Writer` writes classic pcap 2.4 to a provided binary output file.
It uses the Rust `octetrail::Writer` core. No network interface, packet injection,
collection or live send operation is exposed by this workflow.

```python
from octetrail import pcap

with open("synthetic.pcap", "xb") as output:
    writer = pcap.Writer(output, snaplen=64, linktype=147)
    writer.writepkt(b"ordinary synthetic bytes", ts=1.25)
    writer.flush()
```

The example creates a new local file without overwriting an existing one. Link
type 147 denotes user-defined bytes; no protocol construction is needed. The
underlying file context owns the output in this example. `Writer.close()` and
the writer's optional context manager close the supplied file, matching dpkt's
close behavior. That differs from Reader, which never closes a borrowed stream.

## Covered Python subset

`Writer(fileobj, snaplen=1500, linktype=1, nano=False, *, max_packet_bytes=16777216)`
emits its global header immediately. Python output uses the host byte order,
as the two published dpkt baselines do. The actual verified host is Linux
x86_64, little endian. Other Python host orders have not been executed.

- `writepkt(pkt, ts=None)` calls `bytes(pkt)` once. The covered conversions include
  bytes, bytearray, memoryview and an ordinary object's `__bytes__`. An omitted
  timestamp uses local `time.time()`. Tests replace that clock with a fixed value.
- `writepkt_time(pkt, ts)` accepts bytes directly. It does not convert bytearray,
  memoryview or packet-like objects; those should use writepkt. This narrow direct
  input rule also applies to batches and is not all upstream buffer behavior.
- `writepkts(iterable)` consumes `(timestamp, bytes)` pairs one at a time and never
  collects the iterable. A later source exception preserves earlier valid records.
- These methods return None. `close()` closes the supplied file and is idempotent.
  `flush()`, `closed` and context-manager support are explicit OctetRail additions.

Timestamps in the covered subset are nonnegative int, float or Decimal values.
Seconds are `int(ts)`, and fractional ticks use `round(ts % 1 * scale)` with scale
10^6 or 10^9. The measured half-even rounding and active Decimal context behavior
match both references for the valid cases. Python conversion and Decimal errors
propagate. Unsupported numeric objects, private attributes and subclass override
semantics are outside the supported subset.

Both Python record lengths equal the converted payload length, as in dpkt's
methods. There is no automatic packet truncation, padding, checksum or protocol
work. The payload bytes are emitted exactly as supplied.

## Native API and policy

Rust accepts `std::io::Write`, `writer::Options`, `Limits` and exact `Timestamp`
components. Options choose byte order, resolution, snap length and link type.
Both native byte orders and both resolutions are verified against explicit wire
bytes, including the existing reviewed hex fixtures. Native `write_packet`
also accepts a separate original wire length for captures with shorter payloads.

The writer rejects zero snap length, fractions outside the configured resolution,
mismatched timestamp resolutions, captured length beyond snap length or original
length, lengths beyond the u32 wire field, and captured length beyond the policy
limit. The default policy limit is 16 MiB. A zero packet limit permits only empty
packets. All record validation occurs before any record bytes are emitted.
Validation errors leave the writer usable for a later valid record.

The Python layer additionally rejects negative timestamps and seconds beyond
u32. A fractional value that rounds to a full second is rejected; it is not
normalized silently. Both dpkt baselines can emit a full-scale fractional field
in this case. Strict timestamp, snap-length, size and input rules are documented
differences. Header-class objects and struct/PackError message parity are absent.

Rust borrows each payload and allocates no packet-sized serialization buffer.
It writes a fixed record header followed by the payload. The Python adapter uses
temporary output chunks of at most 64 KiB and completes short writes. The caller's
input and sink buffers can still be large. `bytes(pkt)` can allocate or run caller
code before the post-conversion packet check. No process memory cap, capture-size
cap, packet-count cap, timeout or performance claim is made.
Concurrent or reentrant writing is outside the covered contract.

The sink's write method must return a valid count. None becomes BlockingIOError;
invalid counts are errors; zero progress becomes OSError. Original Python sink
exceptions, including InterruptedError, propagate by identity and are not retried
as Rust interruptions. Rust-native interrupted writes follow Write's normal
retry behavior. Exact callback counts and write boundaries are not parity claims.

An I/O or flush error can leave a header, record header or payload prefix in the
output. The writer then rejects further records and flushes. It never rolls back
or resumes that stream. close() remains available for cleanup; close failures
propagate and the wrapper releases its native writer. Constructor I/O failure
may leave a global-header prefix in the caller's stream. The caller retains
responsibility for that failed output.

Explicit flush reports sink flush errors and does not promise fsync or durable
storage. The Rust wrapper does not flush implicitly on drop or into_inner; the
sink's own drop behavior still applies. File closure and context exit may run the
underlying file's normal flush/close behavior.

## Verification and remaining scope

Use the [existing isolated wheel build process](python-reader.md#build-locally),
then install only into fresh environments. The tests run offline:

```sh
NEW_ENV/bin/python -I -m unittest discover -s "$PWD/tests/python"
python3 tools/pcap_writer_differential.py --python NEW_ENV/bin/python --oracle-198 "$PWD/.venv-oracle-198/bin/python" --oracle-196 "$PWD/.venv-oracle-196/bin/python"
```

Replace paths with actual environments. The writer comparison requires exact
byte equality with each baseline and independent expected fields decoded using
struct. Reader round trips are supplementary, never the only oracle. Tests use
only local synthetic bytes.

The separate [PCAPNG writer](pcapng-writer.md) implements a limited output subset.
Protocol Packet objects, writer block classes, complete constants, a dpkt
namespace and package resolver substitution remain absent.
