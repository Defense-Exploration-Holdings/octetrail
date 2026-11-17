# Release notes

## Unreleased

DNS now parses and packs the way dpkt 1.9.8 does:

- A name that runs past the end raises `NeedData`. A short fixed field, a forward
  pointer, an over-long name, a reserved label form or an unsupported record type
  raises `UnpackError`.
- `rdata` is cut to the bytes present, and `rlen` keeps the declared length.
  Bytes after the declared sections are dropped, and `data` is not packed.
- A nonempty `rdata` packs as it is for every record type. Clear it to pack
  changed typed fields. MX `preference` is a one-item tuple when parsed.
- Names keep dots inside labels and allow 255 label bytes. Packing writes labels
  without checking them, as `pack_name` does.
- The 1024-record cap, the 65535-byte message cap and the 128-pointer cap are
  gone. A work budget still raises `ParseLimitError`.
- New: `dns.pack_name`, `dns.unpack_name` and the remaining `DNS_RCODE_*`
  constants. `dns.MAX_RECORDS` and `dns.MAX_MESSAGE_BYTES` are removed.

HTTP now parses and packs the way dpkt 1.9.8 does:

- Chunked bodies are decoded. Responses with 1xx, 204 or 304 status keep any
  bytes after the headers in `data`.
- Lines follow dpkt's whitespace rules, non-ASCII bytes are dropped from start
  lines and headers, and HTTP/0.9 requests, extra request-line words and empty
  reasons parse.
- Headers pack as they are, with list values as Python list text, and
  non-ASCII characters are dropped. Header names, values and lengths are no
  longer checked.
- New: `http.Message`, `http.parse_headers` and `http.parse_body`. The size
  limits, `http.ParseLimitError`, `http.LimitError` and the `MAX_*` constants are
  removed.

New: `octetrail.Packet`, dpkt's base class for header classes, with
`__hdr__`, `__bit_fields__`, `repr()`, `pprint()` and layer lookup, and the
`hexdump`, `in_cksum`, `in_cksum_add` and `in_cksum_done` helpers
([Packet guide](packet.md)).

## 0.3.1

First PyPI upload of the 0.3.0 changes. The code is the same as 0.3.0, which
was published only as a GitHub Release. The release workflow now waits for a
newly created release draft to appear in the release listing before it uploads
files, instead of failing when the listing lags.

## 0.3.0

One stable-ABI wheel (abi3, CPython 3.10 and later) per platform replaces the
version-specific Linux wheels of 0.2.0: Linux glibc and musl on x86-64 and arm64,
macOS on x86-64 and arm64, and Windows on x64 and arm64, plus a source
distribution. Each wheel is tested on its own platform.

New protocol modules, each with a Rust core and a Python interface:

- IPv6 with ordered opaque extension headers and raw IP dispatch
  ([IPv6 guide](ipv6.md)).
- DNS messages with bounded name compression ([DNS guide](dns.md)).
- HTTP/1.0 and HTTP/1.1 requests and responses ([HTTP guide](http.md)).
- Passive TLS record framing and ServerHello metadata ([TLS guide](tls.md)).

IPv4 and TCP now parse and pack the way dpkt 1.9.8 does:

- IPv4 accepts any version nibble. Only a buffer shorter than 20 bytes
  (`NeedData`) and an IHL below 5 (`UnpackError`) are rejected. Options and payload
  are sliced from the bytes present, and the length and checksum are computed on
  packing only when the checksum is zero.
- TCP keeps reserved and nonce bits. `off`, `_rsv` and the nine-bit `flags` are
  views of `_off_flags`. Only a short buffer and a data offset below 5 are
  rejected, and options are packed as assigned.
- New: `tcp.parse_opts`, `tcp.tcp_flags_to_str`, `TH_NS` and the `TCP_OPT_*`
  constants.

Rust API changes:

- `ipv4::Error` no longer has `UnsupportedVersion`, `InvalidOptionsLength`,
  `OffloadLengthUnsupported` or `InvalidTotalLength`.
- `tcp::Header` stores `off_flags: u16` with `off()`, `reserved()` and `flags()`
  accessors, and `to_bytes` no longer returns a `Result`. `tcp::Error` no longer
  has `InvalidOptionsLength`, `TruncatedOptions` or `ReservedBitsUnsupported`.
- New `tcp::parse_options`.

This remains an Alpha release for bounded offline processing. Measured
differences from dpkt are documented in each guide.

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
