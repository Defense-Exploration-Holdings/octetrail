# Release notes

## 0.7.1

0.7.1 also carries the 0.7.0 changes below. 0.7.0 was not published, because
the release workflow did not acquire a macOS arm64 runner and its fallback
build did not start.

- SCTP chunks parsed from a `bytearray` keep their bytes when the caller
  changes the buffer afterwards, as in dpkt. Lazy SCTP chunk data and AH
  fields are also safe to read from several threads.
- `dns.unpack_name` raises `dns.ShortPointerError`, both an `UnpackError` and
  a `struct.error`, for a name that ends one byte into a compression pointer.
  dpkt raises `struct.error` with the same message.
- NetFlow record subclasses that replace `__len__` or `unpack` are read one
  record at a time, as in dpkt.
- Documentation fixes for Ethernet, DNS, SIP, PPP, SLL, IPv4, AH, Diameter,
  SCCP and NetFlow.
- Stricter differential checks: declared differences in the SLL, PPP and AH
  drivers must keep the whole inner IPv6 packet, the DNS driver checks that
  dpkt still raises in each declared case, the DHCP driver checks the
  `UnpackError` base of `MissingLengthError`, and the OSPF and SCTP summary no
  longer lists cases that dpkt 1.9.6 did not run.
- New radiotap fixture with aligned fields, and tests that check SCTP parsing
  memory and the AH copy taken when parsing a `bytearray`.
- The macOS arm64 fallback wheel builds on the macOS 26 runner, since GitHub
  retired macOS 14. The probe for an unacquired macOS 15 arm64 runner now runs
  whatever the matrix result is, and also counts a job reported as cancelled
  with no runner and no steps.

## 0.7.0

Packets whose headers nest deeper than the Python recursion limit now raise
`octetrail.NestingError`, both an `UnpackError` and a `RecursionError`, where
dpkt raises `RecursionError`. Payload decoders that keep bytes on an
`UnpackError` let it through to the caller, so long chains of IPv4 in IPv4,
IPv6 in IPv4, AH or GRE headers fail as they do in dpkt.

MRT routing records now parse and pack the way dpkt 1.9.8 does: the new
`octetrail.mrt` module has dpkt's `MRTHeader`, `TableDump`, `BGP4MPMessage` and
`BGP4MPMessage_32` classes and constants. Table dump attributes are read with
`octetrail.bgp` in linear time.

BGP-4 messages now parse and pack the way dpkt 1.9.8 does:

- New module: `octetrail.bgp` with dpkt's message, attribute and route classes
  and constants.
- An EVPN route that ends before its MAC or IP address length byte raises
  `bgp.EVPNIndexError`, both an `UnpackError` and an `IndexError`, with dpkt's
  message. dpkt raises `IndexError`.
- Long route, attribute and community lists parse in linear time, where dpkt
  takes quadratic time.

H.225.0 call signaling now parses and packs the way dpkt 1.9.8 does: the new
`octetrail.h225` module has dpkt's `H225` and `H225.IE` classes and constants,
with information element boundaries found in Rust in linear time.

ASN.1 now decodes the way dpkt 1.9.8 does:

- New module: `octetrail.asn1` with `decode`, `utctime` and dpkt's constants.
  The element walk runs in Rust.
- Where dpkt raises `IndexError`, `struct.error`, `ValueError` or `TypeError`,
  `asn1.ShortIndexError`, `asn1.ShortStructError`, `asn1.TimeValueError` and
  `asn1.TimeTypeError` are both an `UnpackError` and that error, with dpkt's
  message.
- Nesting deeper than 512 levels raises `asn1.NestingError`, which is
  `octetrail.NestingError`. A decode that would produce more than 262,144 elements
  raises `asn1.ParseLimitError`, because dpkt's result can grow exponentially
  with the input.

Snoop capture files now read and write the way dpkt 1.9.8 does:

- New module: `octetrail.snoop` with `Reader`, `Writer`, `FileHdr`, `PktHdr`
  and dpkt's constants.
- A file without the snoop magic raises `snoop.HeaderError`, an `UnpackError`
  and `ValueError` subclass, and an unknown link type raises
  `snoop.LinktypeError`, an `UnpackError` and `KeyError` subclass. dpkt raises
  `ValueError` and `KeyError`.
- Record bodies are read in bounded pieces, so a hostile record length does not
  allocate memory for data the file does not hold.

## 0.6.2

0.6.2 carries the 0.6.1 and 0.6.0 changes below. 0.6.1 was never published,
because its release lint step failed. The code is the same as 0.6.0.

## 0.6.1

Fix the release workflow so it publishes when the macOS arm64 fallback is not
needed. 0.6.1 carries the 0.6.0 changes below. 0.6.0 was never published,
because its publish jobs were skipped. The code is the same as 0.6.0.

## 0.6.0

HTTP/2 now parses and packs the way dpkt 1.9.8 does: the new `octetrail.http2`
module has dpkt's frame classes, `FrameFactory` and `frame_multi_factory`, with
frame boundaries found in Rust in linear time. `HTTP2Exception` is also an
`UnpackError`.

AH and ESP now parse and pack the way dpkt 1.9.8 does:

- New modules: `octetrail.ah` with `AH` and `octetrail.esp` with `ESP`.
- IPv4 decodes protocol 51 as AH and 50 as ESP. An AH header decodes its
  next header through the IP protocol table.
- An AH header whose inner IPv6 packet raises `ip6.FragmentOffsetError` keeps
  that packet as bytes, where dpkt raises `AttributeError`.

OSPF and SCTP now parse and pack the way dpkt 1.9.8 does:

- New modules: `octetrail.ospf` with `OSPF`, `octetrail.sctp` with `SCTP`,
  `Chunk` and dpkt's chunk type constants, and `octetrail.crc32c`. Zero OSPF
  and SCTP checksums are computed when packing.
- IPv4 and IPv6 decode protocol 89 as OSPF and 132 as SCTP.

HTTP now follows dpkt 1.9.8's classes and errors:

- API: `Message`, `Request` and `Response` are `Packet` subclasses with dpkt's
  `repr()`. A subclass can set `__methods` and `__proto` under the class name
  `Request` or `Response`, as dpkt's SIP module does.
- Errors: a short body and an invalid header raise dpkt's messages. A
  Content-Length that is not an integer, a repeated Content-Length and a
  repeated Transfer-Encoding raise `http.HeaderValueError`,
  `http.HeaderTypeError` and `http.HeaderAttributeError`. A Content-Length or
  chunk size outside `Py_ssize_t` raises `http.LengthOverflowError`. Each is
  both an `UnpackError` and the builtin error dpkt raises, with dpkt's message.

ATA over Ethernet now parses and packs the way dpkt 1.9.8 does: the new
`octetrail.aoe`, `octetrail.aoeata` and `octetrail.aoecfg` modules have dpkt's
classes, command table and constants, and Ethernet decodes type 0x88A2 as AoE.

NetBIOS now parses and packs the way dpkt 1.9.8 does:

- New module: `octetrail.netbios`, with `NS` (a `DNS` subclass), `Session`,
  `Datagram`, `encode_name`, `decode_name`, `node_to_service_name` and dpkt's
  constants.
- A NODE STATUS record with empty resource data raises
  `netbios.NodeStatusError`, an `UnpackError` and `IndexError` subclass, where
  dpkt raises `IndexError`.

DNS now follows dpkt 1.9.8's classes:

- API: `DNS`, `DNS.Q` and `DNS.RR` are `Packet` subclasses with dpkt's
  `repr()` and its `pack_q`, `unpack_q`, `pack_rr`, `unpack_rr`, `pack_rdata`
  and `unpack_rdata` steps, so subclasses can replace them. A new question or
  record has `name` set to `b""`, as in dpkt.
- Packing: out-of-range fields, long labels and long text raise `struct.error`
  instead of `PackError`, and text that is not bytes, a name that is not a
  string and a parsed MX `preference` tuple fail as they do in dpkt.
- Parsing: a name or string that is not UTF-8 raises `dns.TextDecodeError`, an
  `UnpackError` and `UnicodeDecodeError` subclass, where dpkt raises
  `UnicodeDecodeError`. A name cut off by the buffer raises `NeedData` with
  no message, as in dpkt. The parse budget is unchanged.

PPP and PPPoE now parse and pack the way dpkt 1.9.8 does:

- New modules: `octetrail.ppp` with `PPP` and its protocol table, and
  `octetrail.pppoe` with `PPPoE`, the session `PPP` class and dpkt's codes.
- Ethernet decodes type 0x880B as PPP and 0x8864 as PPPoE.
- A PPP frame whose inner IPv6 packet raises `ip6.FragmentOffsetError` keeps
  that packet as bytes, where dpkt raises `AttributeError`.

RADIUS, RTP, STUN and TPKT now parse and pack the way dpkt 1.9.8 does:

- New modules: `octetrail.radius`, `octetrail.rtp`, `octetrail.stun` and
  `octetrail.tpkt`, with dpkt's constants and the `parse_attrs` and `tlv`
  functions. RADIUS and STUN attribute lists are read in Rust.
- One byte left in a RADIUS attribute list raises
  `radius.ShortAttributeError`, an `UnpackError` and `IndexError` subclass,
  where dpkt raises `IndexError`. A cut-off STUN attribute header raises
  `stun.ShortAttributeError`, an `UnpackError` and `struct.error` subclass,
  where dpkt raises `struct.error`.

Linux cooked capture and loopback headers now parse and pack the way dpkt
1.9.8 does: the new `octetrail.sll`, `octetrail.sll2` and `octetrail.loopback`
modules have `SLL`, `SLL2` and `Loopback`. The cooked headers decode their
payload through the Ethernet type table. An IPv6 payload that raises
`ip6.FragmentOffsetError` stays bytes, or escapes from `Loopback` as that
error, where dpkt raises `AttributeError`.

CDP, DTP and EDP now parse and pack the way dpkt 1.9.8 does:

- New modules: `octetrail.cdp` with `CDP` and its entry classes,
  `octetrail.dtp` with `DTP` and `octetrail.edp` with `EDP`, with dpkt's
  constants. Zero CDP and EDP checksums are computed when packing.
- Ethernet decodes type 0x2000 as CDP, 0x2004 as DTP and 0x00BB as EDP.

NTP, RIP, TFTP and HSRP now parse and pack the way dpkt 1.9.8 does:

- New modules: `octetrail.ntp`, `octetrail.rip` with `RIP`, `RTE` and `Auth`,
  `octetrail.tftp` and `octetrail.hsrp`, with dpkt's constants.
- A TFTP request without a NUL after the file name raises
  `tftp.RequestError`, an `UnpackError` and `IndexError` subclass, where dpkt
  raises `IndexError`.

Portmap, Rx, TNS, Yahoo Messenger, SMB and RFB now parse and pack the way dpkt
1.9.8 does: the new `octetrail.pmap`, `octetrail.rx`, `octetrail.tns`,
`octetrail.yahoo`, `octetrail.smb` and `octetrail.rfb` modules have dpkt's
classes and constants.

Telnet option stripping now works the way dpkt 1.9.8 does: the new
`octetrail.telnet` module has `strip_options`, scanned in Rust, and dpkt's
constants.

SIP now parses and packs the way dpkt 1.9.8 does: the new `octetrail.sip`
module has `Request` and `Response` on the HTTP classes.

Gzip now parses and packs the way dpkt 1.9.8 does: the new `octetrail.gzip`
module has `Gzip`, `GzipExtra` and dpkt's constants. A file name that is not
UTF-8 raises `gzip.FilenameDecodeError`, which is both an `UnpackError` and a
`UnicodeDecodeError`.

NetFlow now parses and packs the way dpkt 1.9.8 does: the new
`octetrail.netflow` module has `Netflow1`, `Netflow5`, `Netflow6` and
`Netflow7`, with the records split in Rust in linear time.

Diameter now parses and packs the way dpkt 1.9.8 does: the new
`octetrail.diameter` module has `Diameter`, `AVP` and dpkt's constants, with
the AVPs read in Rust in linear time.

QQ now parses and packs the way dpkt 1.9.8 does: the new `octetrail.qq` module
has `QQBasicPacket`, `QQ3Packet`, `QQ5Packet` and dpkt's constants.

SCCP now parses and packs the way dpkt 1.9.8 does: the new `octetrail.sccp`
module has `SCCP`, dpkt's message classes and its message id constants.

AIM now parses and packs the way dpkt 1.9.8 does: the new `octetrail.aim`
module has `FLAP`, `SNAC` and `tlv`.

RPC now parses and packs the way dpkt 1.9.8 does: the new `octetrail.rpc`
module has `RPC` and its call, reply and authentication classes, dpkt's
constants and the XDR list helpers.

DHCP now parses and packs the way dpkt 1.9.8 does: the new `octetrail.dhcp`
module has `DHCP` and dpkt's constants, with the options read in Rust. An
option type with no length byte raises `dhcp.MissingLengthError`, which is both
an `UnpackError` and an `IndexError`.

Fixed:

- IPv6 given a `bytearray` or `memoryview` keeps that type in `data` and in its
  extension header fields, as dpkt 1.9.8 does. Earlier releases returned bytes.

IEEE 802.11 and radiotap now parse and pack the way dpkt 1.9.8 does: the new
`octetrail.ieee80211` and `octetrail.radiotap` modules have dpkt's classes and
constants, with information elements and radiotap present words read in Rust.
Present words cut off by the buffer raise `radiotap.PresentFlagsError`, which is
both an `UnpackError` and an `IndexError`.

## 0.5.1

0.5.1 carries the 0.5.0 changes below. 0.5.0 was never published, because
its release build did not finish. The code is the same as 0.5.0.

## 0.5.0

Breaking changes:

- `IP`, `TCP`, `UDP` and `Ethernet` are now `Packet` subclasses, as in dpkt.
  Unknown constructor keywords become attributes instead of raising
  `TypeError`, and `repr()` follows dpkt.
- `tcp.LimitError`, `udp.LimitError` and `ethernet.LimitError` are removed,
  with the TCP, UDP and Ethernet size limits and their `DEFAULT_MAX_*`
  constants.

GRE and PIM now parse and pack the way dpkt 1.9.8 does:

- New modules: `octetrail.gre` with `GRE` and `GRE.SRE`, with dpkt's `GRE_*`
  flags, and `octetrail.pim` with `PIM`. A zero PIM checksum is computed when
  packing.
- GRE payloads are decoded through the Ethernet type table.
- IPv4 and IPv6 decode protocol 47 as GRE and 103 as PIM.

ARP now parses and packs the way dpkt 1.9.8 does: the new `octetrail.arp`
module has `ARP` and dpkt's constants, and Ethernet decodes type 0x0806 as ARP.

TCP and UDP now parse and pack the way dpkt 1.9.8 does:

- API: `TCP` and `UDP` are `Packet` subclasses with dpkt's `repr()`,
  `pprint()`, `dict()` and bit fields. Unknown constructor keywords become
  attributes, and a positional `bytearray` or `memoryview` is accepted, instead
  of raising `TypeError`. `opts` and `data` may be any byte-like or layer
  object.
- Limits: the 16 MiB TCP and 65535-byte UDP limits are removed, with
  `tcp.LimitError`, `udp.LimitError`, `DEFAULT_MAX_SEGMENT_BYTES` and
  `DEFAULT_MAX_DATAGRAM_BYTES`.
- Packing: a packet-object cycle raises `RecursionError`, as in dpkt.

IPv4 now parses and packs the way dpkt 1.9.8 does:

- API: `IP` is a `Packet` subclass with dpkt's `repr()`, `pprint()`, `dict()`,
  bit fields and `IP_*` constants. `off` works and warns that it is deprecated,
  as in dpkt. Unknown constructor keywords become attributes instead of
  raising `TypeError`.
- Protocol table: `IP.set_proto`, `IP.get_proto` and `get_ip_proto_name` are
  added. The table is filled from the `IP_PROTO_*` names and shared with
  `IP6`, as in dpkt. The new `octetrail.ipip` module decodes protocol 4.
- Parsing: a payload class that raises `KeyError` leaves the bytes, as in dpkt,
  and the options and payload keep the type of the buffer.
- Packing: a packet-object cycle raises `RecursionError`, as in dpkt, instead
  of `TypeError`.

ICMP and ICMPv6 now parse and pack the way dpkt 1.9.8 does:

- New modules: `octetrail.icmp` with `ICMP` and its message classes, and
  `octetrail.icmp6` with `ICMP6` and its message classes, with dpkt's constants.
- IPv6 decodes protocol 1 as ICMP and 58 as ICMPv6.

IGMP and VRRP now parse and pack the way dpkt 1.9.8 does:

- New modules: `octetrail.igmp` with `IGMP` and `octetrail.vrrp` with `VRRP`.
  A zero checksum is computed when packing.
- IPv6 decodes protocol 2 as IGMP and 112 as VRRP, and 118 as the Spanning
  Tree `STP` class, as dpkt does.

Ethernet now parses and packs the way dpkt 1.9.8 does:

- Frames: Ethernet II, IEEE 802.3 with LLC, LLC/SNAP and Novell raw 802.3, with
  802.1Q and QinQ tags, MPLS labels and pseudowires, and Cisco ISL tags. 802.3
  frames keep their `padding`, `fcs` and `trailer`, and a zero `fcs` is
  computed when packing.
- New classes: `VLANtag8021Q`, `VLANtagISL` and `MPLSlabel`, and the new
  `octetrail.llc`, `octetrail.stp` and `octetrail.ipx` modules. The type table
  has `set_type`, `get_type` and `get_type_rev`, and dpkt's `ETH_*` constants
  are present.
- Errors: follow dpkt, except that an MPLS stack with nothing after it raises
  `ethernet.MPLSIndexError`, an `UnpackError` and an `IndexError`. Nested ISL
  tags are read in one pass, where dpkt raises `RecursionError`.
- API: `Ethernet` is a `Packet` subclass. Unsupported framing no longer raises
  `NotImplementedError`. `ethernet.LimitError`, `DEFAULT_MAX_FRAME_BYTES` and
  the 16 MiB frame limit are removed.

## 0.4.1

- `Cls in p` no longer raises `TypeError` when the TCP or UDP layer it walks
  through holds another layer object instead of bytes. `p[Cls]` already worked.
- Packing an IPv6 packet with a zero TCP or UDP checksum now computes it for a
  jumbo payload over 65535 bytes too. The pseudo-header carries a 32-bit
  length, as RFC 8200 and RFC 2675 specify. dpkt 1.9.8 raises `struct.error`
  here. Checksums of smaller payloads are unchanged.

## 0.4.0

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
- Header names are looked up in a hash map, so a message with many distinct
  header names parses in linear time.
- New: `http.Message`, `http.parse_headers` and `http.parse_body`. The size
  limits, `http.ParseLimitError`, `http.LimitError` and the `MAX_*` constants are
  removed.

New: `octetrail.Packet`, dpkt's base class for header classes, with
`__hdr__`, `__bit_fields__`, `repr()`, `pprint()` and layer lookup, and the
`hexdump`, `in_cksum`, `in_cksum_add` and `in_cksum_done` helpers
([Packet guide](packet.md)).

IPv6 now parses and packs the way dpkt 1.9.8 does:

- Extension headers are `IP6HopOptsHeader`, `IP6RoutingHeader`,
  `IP6FragmentHeader`, `IP6AHHeader`, `IP6ESPHeader` and `IP6DstOptsHeader`
  objects with dpkt's fields, in `extension_hdrs` and `all_extension_headers`.
- The payload is `plen` bytes, or everything when `plen` is 0, and a payload
  cut short is still passed to its protocol class. Any version is accepted.
- When `nxt` is 44 and the last extension header has a nonzero `frag_off`, the
  payload stays bytes. Otherwise it is decoded through `IP6.get_proto`,
  including a fragment that follows another extension header.
- When `nxt` is 44 and the last extension header is not a fragment header,
  `ip6.FragmentOffsetError` (an `UnpackError` and an `AttributeError`) is
  raised where dpkt raises `AttributeError`.
- Packing takes `p` from the last extension header and fills a zero TCP or UDP
  checksum without mapping 0 to `0xffff`. Checksums behind a routing header are
  computed too.
- `IP6.get_proto` and `IP6.set_proto` choose payload classes. IPv4 and IPv6
  payloads are decoded as well as TCP and UDP. A UDP payload over 65535 bytes,
  possible when `plen` is 0, is decoded as UDP as dpkt does, instead of raising
  `udp.LimitError`.
- `p[udp.UDP]`, `p[tcp.TCP]` and `p[ip.IP]` find those layers, and `udp.UDP in p`
  tests for them, as in dpkt.
- `ip6.ExtensionHeader`, `payload_status`, `fragmented`, `IP6_HDR_LEN`,
  `MAX_EXTENSIONS`, `MAX_EXTENSION_BYTES` and `ip6.LimitError` are removed, with
  the extension count and byte limits.

SSL and TLS now parse and pack the way dpkt 1.9.8 does:

- New classes: `TLS`, `SSL2`, `SSLFactory`, `TLSClientHello`, `TLSCertificate`,
  `TLSChangeCipherSpec`, `TLSAlert`, `TLSAppData`, `TLSHelloRequest`,
  `TLSUnknownHandshake` and its aliases, and the `ssl_ciphersuites` module.
  Every handshake type dpkt knows is decoded.
- `TLSServerHello` has `ciphersuite` as a `CipherSuite` object and the
  deprecated `cipher_suite` and `compression` properties of dpkt.
  `cipher_suite_code` is removed.
- Records, handshakes and hellos are `Packet` subclasses. Errors follow dpkt,
  except that `SSL3Exception` is also an `UnpackError` and an SSLv2 record
  without a padding byte raises `SSL2IndexError`.
- The size limits, `ssl.ParseLimitError`, `ssl.LimitError` and the `MAX_*`
  constants are removed.

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
