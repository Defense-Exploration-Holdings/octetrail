# UniversalReader

`octetrail.pcap.UniversalReader(fileobj)` reads the first four bytes of a
capture and returns the reader for that format. It is also available as
`octetrail.capture.pcap.UniversalReader`.

```python
from octetrail import capture

with open("synthetic.capture", "rb") as source:
    reader = capture.pcap.UniversalReader(source)
    for timestamp, payload in reader:
        print(timestamp, len(payload))
```

## Selection

| Magic bytes | Returns |
| --- | --- |
| `a1b2c3d4`, `d4c3b2a1` (microseconds), `a1b23c4d`, `4d3cb2a1` (nanoseconds) | `pcap.Reader` |
| `0a0d0d0a` | `pcapng.Reader` |
| Anything else | `ValueError("unknown capture format: magic ...")` |

Fewer than four bytes raise `NeedData`. The magic is read from the current
position and the stream is never seeked, so a capture that starts partway into
a stream works, and so does a stream that only has `read()`. An error from
`read()` propagates unchanged, and the selected reader's errors are its own:
nothing falls back to the other format.

The result is a plain `pcap.Reader` or `pcapng.Reader`, not a UniversalReader.
The caller keeps ownership of the stream; closing the reader does not close
it. `decimal_timestamps=True` is passed on to the selected reader (see
[Decimal timestamps](decimal-timestamps.md)). Limits are the readers'
defaults. Construct a format-specific reader directly to change them.

## Differences from dpkt

dpkt 1.9.8 tries the classic reader first, seeks to offset 0 on a `ValueError`
and tries PCAPNG from there, then combines both errors into one message.
OctetRail does not copy those rules:

- A PCAPNG capture is read from the current position, not from offset 0, and
  needs no `seek()`.
- A `ValueError` from the stream is raised as it is, with no second attempt.
- A classic header with an unsupported version is rejected by the classic
  reader instead of being retried as PCAPNG.
- Unknown input fails after four bytes with a short message.

dpkt 1.9.6 has no UniversalReader. The `tools/universal_differential.py`
harness compares the cases that still match dpkt 1.9.8 and checks the changed
ones against their OctetRail results.
