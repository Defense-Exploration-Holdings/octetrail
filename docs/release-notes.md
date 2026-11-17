# Release notes

## 0.2.0

Ethernet II parsing now connects IPv4 to TCP or UDP as nested Python objects.
The covered API supports ordinary construction, mutation and byte serialization,
with unknown or undecodable protocols retained as bytes. IPv4 and TCP support
up to 40 opaque option bytes with explicit header-layout checks.

When the IPv4 checksum is zero, serialization updates its length and checksum.
During that update, eligible zero TCP/UDP checksums use the IPv4 pseudoheader.
Explicit checksums remain caller-owned, as does UDP length. The update policy
follows dpkt 1.9.8; measured 1.9.6 differences remain documented.

Rust `ipv4::Packet` and `tcp::Segment` struct literals now require the borrowed
`opts` field. Existing base-header callers can supply `opts: &[]`.

This remains an Alpha release for bounded offline processing. Snaplen-truncated
IPv4 payloads can remain raw Ethernet bytes instead of partial nested objects.
Strict option/length handling and other measured differences remain explicit.
There is no IPv6, ARP, application protocol decoding, reassembly, live capture
or full dpkt compatibility claim.

See the [composition contract](composition.md) and
[compatibility scope](compatibility.md) before adopting the new behavior.
