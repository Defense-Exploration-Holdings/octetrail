# IPv4 datagrams and bounded transport composition

`octetrail.ip.IP` parses IPv4 headers with up to 40 opaque option bytes and
dispatches TCP/UDP when fragment offset is zero. Unknown or undecodable payloads
remain bytes. Fragment reassembly is not implemented. The native Rust API is `octetrail::ipv4::{Header, Packet, checksum}`.

```python
from octetrail import ip

packet = ip.IP(src=bytes.fromhex("c0000201"), dst=bytes.fromhex("c6336402"),
               p=253, data=b"ordinary offline bytes")
raw = bytes(packet)
assert ip.IP(raw).data == packet.data
```

The addresses are documentation examples. This API performs no collection or
network operation. Packet construction accepts field keywords, or one positional
bytes buffer. Positional parsing ignores keyword fields as dpkt does. Unknown
constructor fields and extra positional arguments are unsupported.

## Fields and checksum state

The covered mutable fields are `v`, `hl`, `tos`, `len`, `id`, `ttl`, `p`, `sum`,
`src`, `dst`, `data`, and the named `rf`, `df`, `mf`, `offset` bit fields.
`opts` is bytes of at most 40 bytes, with its length matching `hl`. Defaults are version 4, header length 5, TTL 64,
zero addresses, empty payload and zero checksum. Constructor length defaults to
20 plus options and payload length unless explicitly supplied. `len(packet)` reports the
actual header-plus-payload length, independently of the stored `packet.len`.

Serialization follows dpkt 1.9.8: when `sum == 0`, the native serializer updates
`len` and computes the header's Internet checksum. It mutates those two fields
after successful serialization. If `sum` is nonzero, it preserves both assigned
fields, including after a payload mutation. Set `sum = 0` to refresh them.
`pack_hdr()` emits only the assigned fixed header and does not calculate a sum.
Incoming checksums are preserved, not validated. During a zero-IP-sum update,
zero TCP/UDP sums are computed with the IPv4 pseudoheader for nonfragments.
See [composition](composition.md) for precise update and mutation semantics.

dpkt 1.9.6 differs: it rewrites length on every serialization, even with a nonzero
checksum. Its `offset` getter/setter also uses byte units; this API follows
1.9.8's eight-octet units. Those are separate version differences, not equivalent
observations. The deprecated `off` alias is unsupported; use named flags/offset.
For example, assigning `offset = 24` stores wire offset 24 here and in 1.9.8,
but wire offset 3 in 1.9.6. Mutating the offset retains the other flag bits;
reset `sum` when the header checksum needs refreshing.

Parsing retains the declared IPv4 datagram and ignores trailing enclosing-frame
bytes. It never reassembles fragments. Rust borrows option/payload slices;
the Python facade returns TCP/UDP objects where supported, otherwise owned bytes. Serialized packets are
limited to 65535 bytes. Temporary native output, Python output and retained input
are separate memory costs; this is not a process-memory or wall-clock limit.

## Errors and exclusions

Incomplete fixed headers raise `NeedData`. An IHL below five raises `UnpackError`.
Non-IPv4 versions and offload-style zero total lengths raise
`NotImplementedError`. On parsing, declared lengths below the complete header length raise `ValueError`, and an
incomplete declared payload raises `NeedData`. The latter two are stricter than
the references' permissive slicing. Unsupported field widths/types raise
`PackError` during packing; full error messages and failed-object mutation
timing are not claimed compatible.

Within Ethernet, that specific inconsistent-length parse failure retains the
original payload as bytes. Direct IPv4 behavior remains `ValueError`; generic
value/type errors and resource failures are not swallowed by nested decoding.
Snaplen-truncated datagrams likewise remain raw Ethernet payloads, without an
`ip` alias, rather than the references' possible partial nested objects.

Parsing and serialization cover bytes payloads, ordinary unsigned numeric fields
and byte-string addresses. Generic Packet methods, arbitrary numeric or buffer
types, subclass customization, registries, full constants remain outside the supported surface. Address packing uses fixed-width
four-byte strings, including padding/truncation. No full IPv4 or dpkt parity,
application compatibility or performance claim is made.

## Reproduce offline verification

Use the [wheel build guide](python-reader.md#build-locally) and separate pinned
reference environments from the [README](../README.md). Install only into a
fresh test environment, then run:

```sh
cargo test --locked --workspace
NEW_ENV/bin/python -I -m unittest discover -s tests/python -p 'test_ipv4*.py'
python3 tools/ipv4_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python NEW_ENV/bin/python
```

The driver reports equal cases, measured version differences and explicit strict
or unsupported cases separately. It compares fields before/after serialization,
exact wire bytes, lengths, and declared exception family/phase. The inputs use
an independently assembled literal, struct fields and a separate word-sum checksum;
neither packet library generates them. Passing the declared cases does not
establish broader input compatibility.

Provider isolation, installed version and origin checks, and result validation
use explicit failures that remain active with Python `-O`. The harness regression
tests exercise optimized mode with incorrect versions, origins, coverage and
results. A failed verification produces no successful provider report.
