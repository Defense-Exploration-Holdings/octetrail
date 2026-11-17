# Offline packet composition

The covered path is `ethernet.Ethernet` to `ip.IP` to `tcp.TCP` or `udp.UDP`.
Parsing creates nested `.data` objects and the familiar `.ip`, `.tcp` or `.udp`
aliases. Unknown Ethernet/IP protocols remain opaque bytes. Known children that
raise `UnpackError` or `NeedData` also remain bytes; direct parsing still raises
those errors. Resource, allocation and unexpected errors
are not swallowed. Payloads below TCP/UDP remain bytes with no application
dispatch. ARP remains unsupported. The separate [DNS API](dns.md) must be called
explicitly and does not change transport payloads. This API performs no network
operation.

The separate [IPv6/raw-IP contract](ipv6.md) covers EtherType `0x86dd`, bounded
opaque extension framing and its stricter non-atomic fragment policy. The IPv4
rules below remain unchanged.

IPv4 parsing follows dpkt 1.9.8: a declared length below the header, a zero
length or a datagram cut off by the capture is sliced from the bytes present, so
Ethernet exposes an `ip` alias for it. A transport header that does not decode
leaves `ip.data` as bytes. Unrelated `ValueError`, type errors and resource
failures still propagate.

```python
from octetrail import ethernet, ip, tcp

segment = tcp.TCP(sport=32000, dport=32001, data=b"ordinary offline data")
packet = ip.IP(src=bytes.fromhex("c0000201"), dst=bytes.fromhex("c6336402"),
               p=ip.IP_PROTO_TCP, data=segment)
frame = ethernet.Ethernet(data=packet)
wire = bytes(frame)
decoded = ethernet.Ethernet(wire)
assert decoded.ip.tcp.data == b"ordinary offline data"
```

Ethernet infers the wire EtherType from an IP child without changing its stored
`type`. IPv4 does not infer `p`; set it explicitly. Ethernet also decodes an IPv4
bytes payload supplied through constructor keywords. Construction with nested
objects does not create parsed aliases. Aliases are ordinary snapshot attributes,
as in dpkt; replacing `.data` or reusing `unpack()` can leave older aliases.

## Lengths, checksums and options

The update policy follows dpkt 1.9.8. When `IP.sum == 0`, serialization updates
`IP.len` and the IPv4 checksum, including option bytes. During that same update,
it fills a zero TCP/UDP checksum with the IPv4 pseudoheader only if both fragment
offset and MF are zero. A computed zero UDP checksum is encoded as `0xffff`.
Standalone TCP/UDP serialization preserves its checksum, including zero.
Incoming checksums are retained rather than validated.

Explicit nonzero sums are retained after mutation. To refresh a changed packet,
reset both the IP and transport `sum` fields to zero. Resetting only the IP sum
leaves an explicit transport sum untouched. `UDP.ulen` is always caller-owned;
set it to `len(datagram)` when appropriate. No silent length correction is added.
dpkt 1.9.6 rewrites IP length even with a nonzero IP checksum, while 1.9.8 and
OctetRail retain it. That difference is measured separately, not called parity.

IP and TCP option bytes are opaque. Set `hl` or `off` to five plus the option
length divided by four; the values are not inferred from option contents. IPv4
packs and parses options as dpkt 1.9.8 does, including inconsistent or short
layouts, and so does TCP. `tcp.parse_opts` splits TCP option bytes like dpkt;
IPv4 option-value parsing is absent.

Noninitial IPv4 fragments stay bytes. An initial fragment can expose a transport
header, matching the references, but MF suppresses automatic transport checksum
updates. There is no reassembly. A nonzero IPv4 total length drops trailing
bytes, so enclosing Ethernet padding is not treated as IP payload. Unknown Ethernet
types retain every payload byte. VLAN, MPLS, 802.3 and FCS retain their prior
exclusions. TCP nonce and reserved bits are kept as dpkt 1.9.8 keeps them. IPv4 offset-unit differences and the legacy `off` exclusion remain documented in the
[IPv4 guide](ipv4.md).

## Bounds and verification

Ethernet frames are bounded to 16 MiB, IPv4 datagrams to 65535 bytes, standalone
TCP segments to 16 MiB and UDP buffers to 65535 bytes. Header options are checked
before native output allocation. Native views borrow input; Python objects own
their bytes. Rust `ipv4::Packet` and `tcp::Segment` now include borrowed `opts`
fields; base-header struct literals must supply `opts: &[]`. Dispatch has two
fixed layers, and serialization accepts only the declared child classes, so arbitrary packet-object cycles are rejected. These
limits are not process-memory or wall-clock limits.

The [independent fixture tool](../tools/composition_differential.py) constructs
ordinary bytes with stdlib integer/struct operations and a separate checksum
calculation. It compares 30 fixtures against both hash-pinned dpkt versions and
fresh installed OctetRail wheels: fields, bytes, lengths, options, parsed aliases,
construction and round trips. Four mutation cases include the two version
differences. Seven error cases distinguish three shared truncation outcomes and
four deliberate option-layout differences. Installed tests also traverse literal
PCAP and PCAPNG records without a writer round-trip oracle.

```sh
python3 tools/composition_differential.py --oracle-196 /path/to/oracle196/bin/python --oracle-198 /path/to/oracle198/bin/python --python /path/to/fresh-wheel/bin/python
```

Probes run under isolated optimized Python and explicitly verify distribution
version, module ownership and native extension origin. Missing implementations
or provenance fail rather than skip. This covers the declared offline slice,
not full dpkt compatibility, a replacement distribution, application protocols,
downstream applications or performance.
