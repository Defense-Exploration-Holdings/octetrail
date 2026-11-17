# Bounded IPv6 and explicit raw-IP decoding

`octetrail.ip6.IP6` supplies the IPv6 base fields `v`, `fc`, `flow`, `plen`,
`nxt`, `hlim`, `src`, `dst` and `data`. Complete supported transport payloads
become TCP/UDP objects, with parsed `.tcp`/`.udp` aliases. Ethernet EtherType
`0x86dd` creates an IP6 child and `.ip6` alias. Aliases are snapshots, as in the
existing IPv4 facade. This API performs no network operation.

```python
from octetrail import ethernet, ip6, raw, udp

child = udp.UDP(sport=32000, dport=32001, ulen=12, data=b"note")
packet = ip6.IP6(src=bytes.fromhex("20010db8000000000000000000000001"),
                 dst=bytes.fromhex("20010db8000000000000000000000002"),
                 nxt=17, plen=len(child), hlim=32, data=child)
wire = bytes(packet)
assert raw.decode(wire).udp.data == b"note"
frame = ethernet.Ethernet(data=packet)
assert ethernet.Ethernet(bytes(frame)).ip6.udp.data == b"note"
```

`raw.decode(bytes)` explicitly selects IPv4 or IPv6 from the version nibble.
Empty input raises `NeedData`, other versions raise `UnpackError`, and non-bytes
input raises `TypeError`. IPv4 retains its existing parsing and fragment policies.
No reader iteration, capture link-type inference or dpkt namespace is changed.
For a raw-IP capture, call the selector on each returned record yourself.

## Extensions, incomplete inputs and fragments

Native parsing covers opaque framing for Hop-by-Hop (0), Routing (43), Fragment
(44), Authentication (51) and Destination Options (60). It preserves order and
duplicates. `all_extension_headers` is an immutable tuple of frozen
`ExtensionHeader(type, raw)` values, exposing `nxt`, `length`, `bytes()` and
`len()`. It is not dpkt's extension-specific class/dictionary/option API.
Construction or tuple replacement must supply a complete consistent chain;
serialization validates framing and links. Extension option values, routing
addresses, authentication and encryption are not interpreted or generated.
ESP (50), No Next Header (59) and unknown protocols retain opaque bytes.

The input buffer is capped at 65575 bytes, including any enclosing padding.
Positive `plen` selects that many payload bytes and ignores trailing padding.
A short base header raises `NeedData`; a non-6 version raises
`NotImplementedError`. A captured payload shorter than `plen` remains entirely
bytes with `payload_status == "truncated_payload"`, without extension or transport
decoding. An incomplete extension retains its unconsumed bytes after earlier
complete extensions, with status `incomplete_extension`. Zero `plen` with captured
bytes is retained with status `unsupported_zero_length`; jumbo/offload semantics
are not supplied. A complete empty No Next Header packet is supported.

Every Fragment header is inspected wherever it occurs in the chain. If its
offset is nonzero or M is set, traversal stops after that header and remaining
data stays bytes. No TCP/UDP object is created and no transport checksum is
computed. Atomic fragments (zero offset, M clear) can continue decoding. `p` is
the next protocol after consumed extensions, which can itself identify an
unconsumed extension inside a fragment. There is no reassembly.

Defaults allow at most 16 extension headers and 2048 extension bytes. Complete
serialized payloads, including extensions, are capped at 65535 bytes. Native
views borrow input; the Python facade owns bytes. Limits raise the existing
`PacketLimitError`/`ip6.LimitError`, a ValueError subclass, for direct IP6 and
raw-IP decoding. Ethernet catches only that bounded child refusal, retaining the
exact IPv6 payload as bytes so a caller can continue its capture loop. Ethernet's
own frame limit, allocation errors and unrelated programmer errors propagate.
These are parser bounds, not whole-process memory or wall-clock guarantees.

## Mutation, serialization and measured differences

`plen` and UDP `ulen` remain caller-owned, following both pinned dpkt versions.
Neither is inferred or silently repaired during serialization. Set them when
constructing or changing payload sizes. Zero TCP/UDP checksums are filled using
the IPv6 pseudoheader for nonfragments/atomic fragments. Nonzero sums are retained;
reset the child sum after a relevant mutation. Active Routing headers with
nonzero Segments Left cannot generate a missing checksum; that operation raises
`NotImplementedError` for constructed or changed packets. An unchanged parsed
packet instead preserves its captured bytes and zero checksum when this
recomputation is unsupported. The snapshot compares base fields, ordered raw
extensions and serialized payload bytes. Any change to those fields leaves the
refusal in place. Safe ordinary pseudoheader checksum behavior is unchanged;
no routing checksum calculation is added. Supplied authentication data is opaque
and never updated.
Serialization rejects packet-object cycles and typed non-atomic fragment data.

The [independent comparison](../tools/ipv6_differential.py) checks 19 benign
fixtures against published hash-pinned dpkt 1.9.6 and 1.9.8 and fresh installed
wheels. Fourteen equal cases cover fields, exact bytes/lengths, nested Ethernet,
opaque protocols, ordered/duplicate extensions and atomic fragments. Two ordinary
TCP/UDP construction/mutation sequences cover checksum and bit-field behavior.
Five fixture differences are recorded explicitly:

- First fragments with M set remain bytes here; both references expose TCP on
  the covered complete-header first-fragment fixture.
- A short declared payload stays bytes here; both references expose partial TCP.
- An incomplete extension stays bytes here; both references raise `NeedData`.
- Zero payload length with data stays opaque here; both references decode it.
- For the Authentication-header fixture, parsing fields agree but the references
  duplicate following transport bytes when serializing; OctetRail emits one copy.

A separate ordinary checksum word case records computed UDP zero as `0xffff`
here, while both references retain zero. This is an explicit difference, not a
claim of equal output. Out-of-range bit-field assignments are rejected rather
than masked or leaked into adjacent bits. Complete exception messages, generic
Packet methods, registries, arbitrary subclass dispatch, ICMPv6, extension value
parsers and broader protocol behavior remain outside the contract.

```sh
python3 tools/ipv6_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```

The driver requires both pinned references and an installed candidate, uses
isolated optimized probes and explicitly verifies versions/module origins.
Passing these cases does not establish full IPv6 or dpkt compatibility.
The [DNS message API](dns.md) is explicit and does not alter this dispatch.
The [explicit HTTP subset](http.md) and [passive TLS subset](tls.md) are separate.

Two additional benign type-2 Routing-header capture fixtures cover retained zero
TCP/UDP checksums. OctetRail preserves those unchanged bytes; both references fill
the missing checksum instead. A changed typed payload still raises the explicit
unsupported-checksum error. The pinned routing-header source also rounds its
address bytes to whole 16-byte entries, whereas OctetRail retains bounded opaque
extension bytes. No new unusual-layout test or broad routing parity claim is
made here; the tested ordinary complete type-2 layouts retain their headers.
