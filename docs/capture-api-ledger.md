# Capture API ledger

This reference lists the supported capture API and intentional differences.
It does not claim full import, object or package parity. The published dpkt
1.9.8 and 1.9.6 releases are separate behavioral references.

| Surface | dpkt 1.9.8 / 1.9.6 | OctetRail behavior |
| --- | --- | --- |
| Classic Reader construction and valid pcap 2.4 iteration | Reference | Supported classic subset |
| PCAPNG Reader, single interface, Enhanced Packet Blocks | Reference | Supported EPB subset |
| Reader name, snaplen, dloff, filter, fd, fileno, datalink | Reference | Compared on tested link types |
| next, saved iterator, interleaved generators, readpkts | Reference | Compared for both readers |
| dispatch and loop with callback arguments | Reference | Compared for both readers |
| setfilter | Raises NotImplementedError | Same measured behavior |
| Classic nano timestamps | Decimal | Measured current-context arithmetic |
| PCAPNG timestamps, including nano and binary resolution | Float | Measured float arithmetic |
| Multiple PCAPNG interface clocks | First-interface interpretation | Per-interface interpretation; explicit difference |
| Multiple PCAPNG sections, byte-order changes and finite lengths | Outside parity slice | Independent expected values and strict framing tests |
| PCAPNG idb object, block/header/option classes and serialization | Available | Absent |
| Classic Writer construction, writepkt, writepkt_time, writepkts, close | Reference | Measured valid subset; strict differences recorded |
| PCAPNG Writer, raw bytes with default clock | Available | Measured seconds-method subset |
| PCAPNG custom metadata and exact timestamp ticks | Block-based APIs | Primitive options plus explicit ticks; byte comparisons only |
| PCAPNG Writer block arguments and multiple interfaces | Available | Not implemented |
| UniversalReader | 1.9.8 only; absent in 1.9.6 | Measured ordinary PCAP/EPB subset; strict differences retained |
| Selected magic, block, version and DLT constants | Sixteen common exports | Compared through the offline consumer |
| Full magic, block, option and DLT constant exports | Available, version-dependent | Remaining inventory not implemented |
| Public offset dictionaries and private bookkeeping attributes | Available | Only covered metadata behavior, not object parity |
| Modified pcap and deprecated Packet Block support | Available paths | Unsupported |
| PCAPNG Simple Packet Blocks | Ignored by these readers | Explicit NotImplementedError |
| Open helper, context manager, close, allocation/scan limits | Different API boundary | Explicit OctetRail additions |
| Root dpkt import and dpkt distribution metadata | Upstream package | Not supplied by OctetRail |
| Explicit capture provider | Covered objects under dpkt | octetrail.capture exports the covered modules and three exception classes |
| Protocol Packet classes, mutable fields, subclassing and checksums | Broad dpkt surface | Not implemented |

The unsupported class families include classic FileHdr/PktHdr and little-endian
variants, PCAPNG SectionHeaderBlock, InterfaceDescriptionBlock,
EnhancedPacketBlock, PacketBlock and PcapngOption, and their endian variants.
Returning packets successfully does not implement these
construction, mutation or serialization APIs. Full exception message and timing
compatibility also remains unmeasured.

The [classic writer](pcap-writer.md) supports the documented bytes methods and
strict validation. The [PCAPNG writer](pcapng-writer.md) emits one unknown-length
section, one interface and EPBs. Primitive options and exact ticks are additions;
they do not implement upstream block classes. The [explicit provider
guide](capture-compatibility.md) explains import selection, and the
[UniversalReader guide](universal-reader.md) describes the 1.9.8-only factory.

Keep two separate gates: an isolated wheel can be installed and verified under
the `octetrail` namespace, while unchanged downstream source still requires its
`dpkt` imports, resolver pin and all accessed objects. No import shim, distribution
substitution, unchanged application compatibility or complete library parity is
claimed here.
