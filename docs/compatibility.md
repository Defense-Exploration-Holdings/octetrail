# Compatibility and supported scope

OctetRail supplies a limited offline capture API, not a drop-in dpkt replacement.
The behavior reference is the [published dpkt 1.9.8 release](https://pypi.org/project/dpkt/1.9.8/).
The [1.9.6 release](https://pypi.org/project/dpkt/1.9.6/) is a separate comparison
baseline. Hash-pinned reference requirements are in
[oracle-1.9.8.txt](../tools/oracle-1.9.8.txt) and
[oracle-1.9.6.txt](../tools/oracle-1.9.6.txt). A comparison covers its declared
inputs and observations, not every upstream API or malformed input.

## Capture behavior

| Surface | Supported scope |
| --- | --- |
| Native classic PCAP | Version 2.4, both byte orders, microsecond/nanosecond integer timestamps, owned bytes |
| Native PCAPNG | Version 1.0, Enhanced Packet Blocks, section-local interfaces and clocks |
| Python readers | Concrete Reader classes, iteration, metadata and callback methods |
| Python timestamps | Classic microseconds as float, classic nanoseconds as Decimal, PCAPNG as float |
| Output | Classic records and one-section/one-interface PCAPNG EPBs with bounded primitive options |
| UniversalReader | 1.9.8-style selection over supported formats; absent from the 1.9.6 reference |
| Package identity | octetrail distribution and imports; no installed dpkt namespace or resolver substitute |

See the [capture API reference](capture-api-ledger.md), [Python reader
guide](python-reader.md), [PCAPNG reader](pcapng-reader.md), [classic
writer](pcap-writer.md), [PCAPNG writer](pcapng-writer.md) and
[UniversalReader](universal-reader.md) for exact call shapes and exclusions.

## Strict differences and resource limits

Native readers reject incomplete payloads, unsupported versions, invalid
fractions and inconsistent lengths. Some upstream paths accept those inputs.
PCAPNG packets use their own interface clocks; the references use first-interface
interpretation on some multi-interface inputs. Error classes are mapped for the
covered subset, while complete messages, timing and object identity are not
claimed compatible. UniversalReader retains additional format-selection and
cursor differences documented in its guide.

Streaming is incremental. EOF and native record errors are terminal. Readers
borrow Python streams; path-opening helpers own their files; Writer.close closes
its supplied sink. Default packet allocation is limited to 16 MiB. PCAPNG adds
block, interface and scan limits. These are parser policies, not total process
memory, capture-size, packet-count or time limits. Caller-provided I/O can block.

The [composition subset](composition.md) covers Ethernet to IPv4 to TCP/UDP,
opaque IP/TCP options and ordinary IPv4/transport checksum updates. The
[IPv6 module](ipv6.md) parses and packs IPv6 and its extension headers the way
dpkt 1.9.8 does. Payload protocols without an OctetRail module stay bytes.
The [DNS module](dns.md) parses and packs messages, questions, records and
compressed names the way dpkt 1.9.8 does, with dpkt's classes and subclass
hooks, except one declared difference for text that is not UTF-8. It does not
add transport dispatch.
The [HTTP module](http.md) parses and packs HTTP/1.x requests and responses,
including chunked bodies, the way dpkt 1.9.8 does. Three header errors that
dpkt raises as builtin errors are declared. No automatic application dispatch
is added.
The [SIP module](sip.md) parses and packs SIP requests and responses the way
dpkt 1.9.8 does, with no declared differences.
including chunked bodies, the way dpkt 1.9.8 does. Three header errors and
the overflow of a Content-Length or chunk size, which dpkt raises as builtin
errors, are declared. No automatic application dispatch is added.
The [IPv4 module](ipv4.md) parses and packs IPv4 datagrams, their options and
checksums, and the shared protocol table the way dpkt 1.9.8 does, except one
declared difference for an IPv6 payload.
The [Packet base class](packet.md) follows dpkt 1.9.8, including bit fields,
`repr()`, `pprint()` and the checksum helpers.
The [Ethernet module](ethernet.md) parses and packs Ethernet II, IEEE 802.3 LLC,
Novell raw, 802.1Q, MPLS and Cisco ISL frames, and the LLC, STP and IPX classes,
the way dpkt 1.9.8 does. An MPLS stack with nothing after it raises an
`UnpackError` subclass where dpkt raises `IndexError`.
The [ICMP and ICMPv6 modules](icmp.md) parse and pack those messages the way
dpkt 1.9.8 does, except one declared difference for an ICMPv6 quote.
The [GRE and PIM modules](gre-pim.md) parse and pack those packets the way
dpkt 1.9.8 does, with no declared differences.
The [IGMP and VRRP modules](igmp-vrrp.md) parse and pack those messages the way
dpkt 1.9.8 does, with no declared differences.
The [Telnet module](telnet.md) strips option negotiation the way dpkt 1.9.8
does, with no declared differences.
The [ATA over Ethernet modules](aoe.md) parse and pack AoE and its commands the
way dpkt 1.9.8 does, with no declared differences.
The [Portmap, Rx, TNS, Yahoo Messenger, SMB and RFB modules](small-apps.md)
parse and pack those headers the way dpkt 1.9.8 does, with no declared
differences.
The [NetBIOS module](netbios.md) parses and packs the name, session and datagram
services the way dpkt 1.9.8 does, except one declared difference for an empty
NODE STATUS record.
The [RADIUS, RTP, STUN and TPKT modules](radius-rtp-stun-tpkt.md) parse and
pack those messages the way dpkt 1.9.8 does, except two declared differences
for attribute lists cut off inside an attribute header.
The [NTP, RIP, TFTP and HSRP modules](ntp-rip-tftp-hsrp.md) parse and pack
those messages the way dpkt 1.9.8 does, except one declared difference for a
TFTP request without a NUL.
The [CDP, DTP and EDP modules](cdp-dtp-edp.md) parse and pack those packets
the way dpkt 1.9.8 does, with no declared differences.
The [PPP and PPPoE modules](ppp.md) parse and pack those frames the way
dpkt 1.9.8 does. A PPP frame that carries an IPv6 packet failing with
The [AH and ESP modules](esp-ah.md) parse and pack those headers the way
dpkt 1.9.8 does. An AH header that carries an IPv6 packet failing with
`FragmentOffsetError` keeps that packet as bytes, where dpkt raises
`AttributeError`.
The [OSPF and SCTP modules](ospf-sctp.md) parse and pack those packets the way
dpkt 1.9.8 does, with no declared differences.
The [ARP module](arp.md) parses and packs ARP the way dpkt 1.9.8 does, with no
declared differences.
The [SCCP module](sccp.md) parses and packs Skinny messages the way dpkt 1.9.8
does, with no declared differences.
The [AIM module](aim.md) parses and packs OSCAR frames the way dpkt 1.9.8
does, with no declared differences.
The [IEEE 802.11 and radiotap modules](ieee80211-radiotap.md) parse and pack
frames the way dpkt 1.9.8 does. Radiotap present words cut off by the buffer
raise an error that is both an `UnpackError` and dpkt's `IndexError`.
The [RPC module](rpc.md) parses and packs ONC RPC the way dpkt 1.9.8 does, with
no declared differences.
The [DHCP module](dhcp.md) parses and packs DHCP the way dpkt 1.9.8 does. An
option type with no length byte raises an error that is both an `UnpackError`
and dpkt's `IndexError`.
The [SLL, SLL2 and loopback modules](sll-loopback.md) parse and pack those
headers the way dpkt 1.9.8 does. An IPv6 payload failing with
`FragmentOffsetError` stays bytes, or escapes from `Loopback` as that error,
where dpkt raises `AttributeError`.
The [SSL and TLS module](tls.md) parses and packs records, handshakes, hellos,
certificate lists and SSLv2 records the way dpkt 1.9.8 does. Two errors are
also `UnpackError` subclasses where dpkt raises other classes.
Other protocols, full header/block object models and constant inventories,
filter execution, live capture and asynchronous I/O are outside the supported
API. Import compatibility and distribution compatibility are separate: an
explicit provider or test-only namespace map cannot satisfy a dpkt dependency
pin. No unchanged application compatibility or performance claim is made.

Snaplen-truncated and inconsistent IPv4 datagrams parse as they do in dpkt
1.9.8: options and payload are sliced from the bytes present. See the
[composition contract](composition.md) for exception boundaries.
