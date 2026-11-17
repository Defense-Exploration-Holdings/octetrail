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

The [composition subset](composition.md) covers Ethernet II to IPv4 to TCP/UDP,
opaque IP/TCP options and ordinary IPv4/transport checksum updates. The
[IPv6/raw-IP subset](ipv6.md) adds base fields, ordered opaque extensions,
bounded transport dispatch and explicit version selection. Non-atomic IPv6
fragments remain bytes.
The [DNS module](dns.md) parses and packs messages, questions, records and
compressed names the way dpkt 1.9.8 does. It does not add transport dispatch.
The [explicit HTTP subset](http.md) covers HTTP/1.0 and HTTP/1.1 request/response
fields and Content-Length or Content-Type body selection, with caller lengths
retained and transfer encoding deferred. No automatic application dispatch is added.
The [passive TLS subset](tls.md) adds bounded record framing and explicit
ServerHello metadata, with opaque fallback for other handshake kinds. Its
record-type dispatch inventory is deliberately partial.
Other protocols, full header/block object models and constant inventories,
filter execution, live capture and asynchronous I/O are outside the supported
API. Import compatibility and distribution compatibility are separate: an
explicit provider or test-only namespace map cannot satisfy a dpkt dependency
pin. No unchanged application compatibility or performance claim is made.

Snaplen-truncated and inconsistent IPv4 datagrams parse as they do in dpkt
1.9.8: options and payload are sliced from the bytes present. See the
[composition contract](composition.md) for exception boundaries.
