# Offline UniversalReader subset

`octetrail.pcap.UniversalReader(fileobj)` supplies the measured dpkt 1.9.8
format-selection contract for ordinary PCAP 2.4 and the supported PCAPNG Enhanced
Packet Block subset. It is also accessible through
`octetrail.capture.pcap.UniversalReader`. The published dpkt 1.9.6 wheel has no
UniversalReader attribute. This API is outside the common two-version consumer
denominator.

```python
from octetrail import capture

with open("synthetic.capture", "rb") as source:
    reader = capture.pcap.UniversalReader(source)
    for timestamp, payload in reader:
        print(timestamp, len(payload))
```

UniversalReader is a thin compatibility factory. It returns a concrete
`pcap.Reader` or `pcapng.Reader`, not a UniversalReader instance or a proxy.
The existing Rust parsers still perform framing, decoding, allocation checks and
incremental reads. The factory adds no parser, dependency or native allocation.
Keeping Python selection separate preserves the caller's original file object
and its Python exception identity.

## Selection, cursor and ownership

1. Construct a classic Reader at the input's current position.
2. Only if construction raises ValueError or a subclass, call `fileobj.seek(0)`.
   This is absolute file offset zero, not the original input position.
3. Construct a PCAPNG Reader from that position.
4. If that construction also raises ValueError, raise a ValueError with
   `unknown pcap format; libpcap error: ..., pcapng error: ...`, using the two
   reader messages and implicit exception context.

Seek failures and non-ValueError reader failures propagate without replacement.
An initial classic NeedData therefore does not trigger fallback. Packet iteration
errors after construction never trigger a second format attempt. The factory
does no extra magic read, buffering or position restoration.

A valid classic stream needs only read(size). PCAPNG fallback needs seek(0), so
nonseekable PCAPNG inputs fail even though the direct PCAPNG Reader can read them.
A classic capture embedded at the current offset can be selected there. A PCAPNG
capture encountered at a nonzero offset causes fallback to file zero. These
surprising rules are intentional compatibility behavior, verified separately
from explicit format-specific reading.

The caller retains input ownership after success and failure. Reader timestamps,
owned bytes, shared iterators, callbacks, metadata and EOF rules are those of the
selected reader. Nano classic timestamps remain Decimal, while PCAPNG timestamps
remain floats. No payload decoding or networking is performed.

## Limits and explicit differences

The factory accepts only fileobj, as the pinned 1.9.8 API does. It uses existing
reader defaults: 16 MiB captured packets, and for PCAPNG a 32 MiB block limit,
1,024 interfaces and 4,096 scanned blocks per read. A ValueError subclass from
construction follows the same fallback/combination rule. Call a format-specific
Reader with explicit limit keywords when limits need adjustment. There is no
total-capture or process-wide memory limit, deadline or nonblocking I/O guarantee.

The factory retains native strict validation. Examples of known differences:

| Input | dpkt 1.9.8 | OctetRail |
| --- | --- | --- |
| 64 zero bytes | Combined ValueError; cursor 28 | Combined ValueError with native PCAPNG text; cursor 8 |
| Initial PCAPNG header of 24 or 27 bytes | Combined ValueError | NeedData from the native PCAPNG reader |
| Short classic packet payload | Yields the available short bytes | NeedData during iteration |
| Classic header version 9.4 | Accepts the capture | Rejects version and attempts PCAPNG fallback |

NeedData message text is not claimed identical. Other existing differences also
remain, including version/length/fraction validation, modified pcap and packet
block exclusions, per-interface PCAPNG clocks, explicit scan limits and incomplete
object/constant inventories. The five recorded differences are measured examples,
not an exhaustive difference list. Full subclass customization, exact traceback
frames, package/module identity and arbitrary file-like objects remain unverified.

## Reproduce the offline checks

Use fresh installed-wheel environments and the separate hash-pinned published
reference environments from the root README. The probe uses `-I`, validates
distribution versions and package/native origins, and uses only the existing
reviewed synthetic hex fixtures and bounded derivatives.

```sh
cargo test --locked --workspace
/path/to/fresh-cp312/bin/python -I -m unittest discover -s tests/python -q
python3 tools/universal_differential.py \
  --python /path/to/fresh-cp312/bin/python \
  --python /path/to/fresh-cp313/bin/python \
  --oracle-198 /path/to/oracle-198/bin/python \
  --oracle-196 /path/to/oracle-196/bin/python
```

The harness compares its declared inputs and observations. It records 1.9.6
absence separately, since that release has no UniversalReader factory. Passing
these checks does not establish every format, error or file-like behavior.

The default wheel still installs only octetrail and cannot satisfy dpkt package
requirements. No import shim is supplied, and no whole-format, whole-library
or application parity is claimed.
