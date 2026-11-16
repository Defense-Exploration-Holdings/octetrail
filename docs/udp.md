# Offline UDP base headers

`octetrail.udp.UDP` parses and serializes the fixed eight-byte UDP header with
an opaque owned bytes payload. The Rust API is
`octetrail::udp::{Header, Datagram, Limits}`. These APIs operate only on supplied
buffers. They perform no network operation or application-protocol dispatch. The enclosing
[IPv4 composition API](composition.md) can fill a zero UDP checksum; it still
does not infer or update the stored `ulen` field.

```python
from octetrail import udp

packet = udp.UDP(sport=12345, dport=54321, ulen=12, sum=0x1234, data=b"rail")
raw = bytes(packet)
assert raw.hex() == "3039d431000c12347261696c"
assert udp.UDP(raw).data == b"rail"
```

The sample checksum is a caller-supplied field, not a validated UDP checksum.
Pseudoheader checksum calculation, checksum validation, IPv4/IPv6 integration,
dispatch, packet sending and collection are outside this module.

## Fields and buffer semantics

The mutable unsigned 16-bit fields are `sport`, `dport`, `ulen`, and `sum`.
Their defaults are `0xdead`, zero, eight and zero. `data` defaults to `b""`.
The selected constants are `UDP_HDR_LEN = 8` and `UDP_PORT_MAX = 65535`.

Construct with those keyword fields or one positional bytes buffer. A positional
buffer ignores keyword overrides, following both reference versions. `unpack(buf)`
replaces fields and payload. Unknown constructor fields and multiple positional
arguments are unsupported.

Both dpkt 1.9.6 and 1.9.8 preserve the assigned `ulen` and `sum` on serialization,
including zero and values inconsistent with the payload. This module does the
same. Changing `data` never updates either field. Set them explicitly when an
application needs new values. `pack_hdr()` emits only the assigned eight-byte
header. `len(packet)` is eight plus the actual payload length, independent of
`ulen` and of whether the header fields can currently be packed.

Parsing retains every supplied byte following the fixed header. It does not
trim data to `ulen`, require that many bytes, infer missing bytes, or remove
enclosing-frame padding. A caller that knows the containing packet's boundary
must supply the intended UDP buffer. Successful parsing or packing does not
prove that the fields describe a valid network datagram.

Rust borrows the supplied payload slice while Python returns owned bytes.
The Python API accepts ordinary bytes input and payloads. Generic Packet methods,
arbitrary buffer/numeric objects, subclasses, full constants and layered packet
objects are outside the measured surface.

## Limits and errors

The default complete-buffer budget is 65535 bytes, including the eight-byte
header. The Python limit is fixed; Rust callers can supply `Limits` for their
offline buffer budget. This is an allocation policy independent of `ulen`, an
IP-layer datagram limit, an MTU or a process-memory limit. Python input, copied
payload, temporary Rust output and Python output incur separate memory costs.

Both dpkt versions accept larger opaque buffers. The differential suite measures
that resource-policy difference separately, including the 65535/65536 boundary;
those cases are not counted as equal behavior. Parse and serialization enforce
the cap before payload copying or native output allocation. `len(packet)` and
`pack_hdr()` remain descriptive operations and do not enforce the payload cap.

Fewer than eight input bytes raise the public `NeedData` exception. Invalid
unsigned field widths or ordinary scalar types raise `PackError` when packed.
Unsupported input/payload types and constructor signatures raise `TypeError`.
Buffers beyond the cap raise `udp.LimitError`, a native `ValueError` subclass.
Full exception messages and failed-object mutation timing are not claimed
compatible. No full UDP, dpkt, downstream or performance parity is claimed.

## Reproduce the local checks

Use the [wheel build guide](python-reader.md#build-locally) and the two isolated,
hash-pinned reference environments from the [README](../README.md). Install the
distinct `octetrail` wheel only into a fresh disposable environment, then run:

```sh
cargo test --locked --workspace
NEW_ENV/bin/python -B -I -m unittest discover -s tests/python -p 'test_udp*.py'
NEW_ENV/bin/python -B -I -O -m unittest discover -s tests/python -p 'test_udp*.py'
python3 tools/udp_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python NEW_ENV/bin/python
python3 -O tools/udp_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python NEW_ENV/bin/python
```

The corpus uses preconstructed benign synthetic bytes, an independent struct
encoder and a byte-arithmetic fixture check. The comparison checks fields before
and after serialization, exact bytes and header bytes, payload ownership/type,
length, stable repeated serialization and declared error family/phase. Resource
differences remain separate. Provider version, isolation, distribution/module
origins and result coverage use explicit failures that stay active under `-O`.
The optimized driver passes the same optimization level to its isolated probes.
Negative controls reject wrong versions/origins and corrupted observations.
