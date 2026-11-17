# Exact Decimal capture timestamps

Pass `decimal_timestamps=True` when reading offline classic PCAP or PCAPNG:

```python
from octetrail import pcap

with open("synthetic.capture", "rb") as source:
    reader = pcap.UniversalReader(source, decimal_timestamps=True)
    for timestamp, data in reader:
        print(timestamp, len(data))
```

The keyword is also accepted by `pcap.Reader`, `pcapng.Reader`, `pcap.open` and
`pcapng.open`. It must be a boolean. The owned-file `open` helpers retain their
existing close behavior; streams passed to a Reader remain caller-owned.
Iteration, `next`, `dispatch`, `loop` and `readpkts` all use the chosen mode.
The two-item `(timestamp, bytes)` tuple shape, cursor and native limits remain
the same. The option does not add packet metadata or protocol dispatch.

When enabled, every timestamp is a `decimal.Decimal` built directly from integer
capture fields, without an intermediate float. Classic PCAP uses microsecond or
nanosecond resolution. PCAPNG uses the section-local interface's decimal or binary
resolution and signed offset for each packet. The full existing encoded exponent
range is supported. Binary fractions have finite decimal representations, too.

Construction is exact regardless of the active Decimal precision, rounding mode,
traps or exponent limits. It leaves the caller's context and flags unchanged.
Subsequent arithmetic on the returned Decimal still follows the caller's context.
The Decimal exponent follows the source clock's exponent; equal values from
different clocks can therefore have different trailing zeros. Clock accuracy is
limited to the fields recorded in the capture.

For example, an integer microsecond clock can represent
`Decimal("1700000000.123456")` exactly. Converting an already rounded float to
Decimal cannot recover the original ticks. For PCAPNG, the conversion evaluates
`offset + ticks / base**exponent` exactly, including binary clocks and negative
offsets. This does not change reader validation or supported block types.

Omitting the keyword or passing `False` preserves the existing defaults:
classic microseconds yield float, classic nanoseconds yield Decimal using the
active context, and PCAPNG yields float. Both pinned dpkt versions reject the new
keyword. The opt-in mode is a deliberate extension, separate from default parity.
It adds no writer support: in particular, the PCAPNG seconds writer still accepts
only int/float. Use the existing explicit tick writer for custom clocks.

To reproduce the offline checks, use fresh installed-wheel and separate
hash-pinned dpkt 1.9.6/1.9.8 environments as described in the
[build guide](python-reader.md#build-locally):

```sh
NEW_ENV/bin/python -B -I -m unittest discover -s tests/python -p test_decimal_timestamps.py
NEW_ENV/bin/python -B -I -O -m unittest discover -s tests/python -p test_decimal_timestamps.py
python3 -B tools/timestamp_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python NEW_ENV/bin/python
python3 -B -O tools/timestamp_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python NEW_ENV/bin/python
```

Inputs are independently encoded ordinary offline captures plus reviewed literal
fixtures. Default observations are compared to both references. Exact opt-in
values are compared to independent rational arithmetic. A known dpkt
first-interface clock difference is measured separately. No full dpkt parity,
performance, live capture, traffic sending or downstream-application claim follows.
