# OctetRail

OctetRail is a Rust rewrite of [dpkt](https://github.com/kbandla/dpkt), working
toward a compatible Python API. It currently provides native offline
pcap and PCAPNG readers, bounded output subsets and an experimental `octetrail`
Python wheel. It is not a drop-in dpkt replacement.

The classic reader supports ordinary pcap 2.4, both byte orders and microsecond or
nanosecond timestamps. It preserves raw packet bytes, original lengths, capture
metadata and exact integer timestamp components. It has no runtime dependencies
and forbids unsafe Rust.

The separate [PCAPNG reader](docs/pcapng-reader.md) supports a measured Enhanced
Packet Block subset, section-local interface clocks and explicit resource limits.
The [classic-PCAP writer](docs/pcap-writer.md) emits validated offline records,
with explicit rounding and I/O behavior. The [PCAPNG writer](docs/pcapng-writer.md)
supports one section, one interface and Enhanced Packet Blocks with bounded
metadata options. Modified pcap, broad protocol decoding and a `dpkt` import layer are not
implemented. The [compatibility contract](docs/compatibility.md) tracks these
separately from import names, distribution metadata and downstream behavior.
The [explicit capture provider](docs/capture-compatibility.md) supplies the
covered Python reader/writer subset without changing normal `dpkt` imports.
The [UniversalReader guide](docs/universal-reader.md) describes measured
1.9.8-style format selection over the native readers.

Ethernet, IPv4/IPv6 and opaque TCP/UDP objects can be composed and decoded offline.
See the [composition guide](docs/composition.md) for dispatch, options, checksum
update rules, resource bounds and measured compatibility limits.
The [IPv6 module](docs/ipv6.md) parses and packs IPv6 and its extension headers
the way dpkt 1.9.8 does, and adds explicit raw-IP version selection.
The [DNS module](docs/dns.md) parses and packs messages and common record fields
the way dpkt 1.9.8 does, without changing transport payloads or performing lookups.
The [HTTP module](docs/http.md) parses and packs HTTP/1.x requests and responses
the way dpkt 1.9.8 does, without stream reassembly.
The [SIP module](docs/sip.md) parses and packs SIP requests and responses the
way dpkt 1.9.8 does, on the HTTP classes.
The [Packet base class](docs/packet.md) is dpkt's, for writing your own header
classes, with the checksum and hexdump helpers.
The [Ethernet module](docs/ethernet.md) parses and packs Ethernet II, 802.3 LLC,
Novell, 802.1Q, MPLS and ISL frames the way dpkt 1.9.8 does, with LLC, STP and IPX.
The [ICMP and ICMPv6 modules](docs/icmp.md) parse and pack those messages the way
dpkt 1.9.8 does, and IPv6 decodes them.
The [GRE and PIM modules](docs/gre-pim.md) parse and pack those packets the way
dpkt 1.9.8 does, and IPv6 decodes them.
The [IGMP and VRRP modules](docs/igmp-vrrp.md) parse and pack those messages the
way dpkt 1.9.8 does, and IPv6 decodes them.
The [Telnet module](docs/telnet.md) strips option negotiation the way dpkt 1.9.8
does.
The [ATA over Ethernet modules](docs/aoe.md) parse and pack AoE and its ATA and
configuration commands the way dpkt 1.9.8 does, and Ethernet decodes them.
The [Portmap, Rx, TNS, Yahoo Messenger, SMB and RFB modules](docs/small-apps.md)
parse and pack those headers the way dpkt 1.9.8 does.
The [NetBIOS module](docs/netbios.md) parses and packs the name, session and
datagram services the way dpkt 1.9.8 does.
The [RADIUS, RTP, STUN and TPKT modules](docs/radius-rtp-stun-tpkt.md) parse and
pack those messages the way dpkt 1.9.8 does.
The [NTP, RIP, TFTP and HSRP modules](docs/ntp-rip-tftp-hsrp.md) parse and pack
those messages the way dpkt 1.9.8 does.
The [CDP, DTP and EDP modules](docs/cdp-dtp-edp.md) parse and pack those
packets the way dpkt 1.9.8 does, and Ethernet decodes them.
The [PPP and PPPoE modules](docs/ppp.md) parse and pack those frames the way
dpkt 1.9.8 does, and Ethernet decodes them.
The [AH and ESP modules](docs/esp-ah.md) parse and pack those headers the way
dpkt 1.9.8 does, and IPv4 decodes them.
The [OSPF and SCTP modules](docs/ospf-sctp.md) parse and pack those packets the
way dpkt 1.9.8 does, and IPv4 and IPv6 decode them.
The [ARP module](docs/arp.md) parses and packs ARP the way dpkt 1.9.8 does, and
Ethernet decodes it.
The [DHCP module](docs/dhcp.md) parses and packs DHCP messages and their options
the way dpkt 1.9.8 does.
The [SLL, SLL2 and loopback modules](docs/sll-loopback.md) parse and pack the
link-layer headers of Linux cooked and null/loopback captures the way dpkt
1.9.8 does.
The [SSL and TLS module](docs/tls.md) parses and packs records, handshakes,
hellos and certificate lists the way dpkt 1.9.8 does, with dpkt's cipher suite table.

See the [0.5.1 release notes](docs/release-notes.md) for the changes
and their compatibility limits.

## Use the classic-pcap reader

Install Rust with rustup. `rust-toolchain.toml` pins Rust 1.85.1 and its formatting
and lint components. The crate declares a Rust 1.85 floor; only the pinned
toolchain has been tested. Run commands from this directory.

```sh
cargo build --locked
cargo run --locked --bin pcap-read -- /path/to/synthetic.pcap
cargo run --locked --bin pcap-read -- --max-packet-bytes 1048576 /path/to/synthetic.pcap
```

The CLI writes JSON lines: one metadata object, then one object per packet with
`seconds`, `fraction`, `original_len` and `hex` fields. Check its exit status.
Output before a read error describes only the prefix processed successfully.
Payload hex is for inspection and differential testing, not a performance API.
The command reads a local file and does no live collection or protocol work.

The library accepts any synchronous `std::io::Read`:

```rust
use octetrail::{Limits, Reader};
use std::fs::File;

fn inspect() -> Result<(), Box<dyn std::error::Error>> {
    let reader = Reader::new(File::open("synthetic.pcap")?, Limits::default())?;
    println!("link type: {}", reader.header().linktype);
    for packet in reader {
        let packet = packet?;
        println!("{} captured bytes", packet.data.len());
    }
    Ok(())
}
```

Construction consumes the 24-byte global header. Each iterator step consumes
one record. EOF and record errors are terminal; no resynchronization is tried.
No seek is required. `into_inner()` returns the owned input at its current logical
position. An input adapter such as `BufReader` may buffer bytes internally.
Stopping early leaves subsequent records unread by the parser. Dropping the
reader drops its owned input. Borrow an input with `&mut` to keep ownership.

The default maximum captured packet length is 16 MiB. A limit of zero permits
only empty packets. Captured length must not exceed snap length or original
length. Versions other than 2.4, zero snap length, out-of-range fractions and
incomplete headers or payloads are errors. Unknown link types and nonzero reserved
header fields are retained without interpretation. These checks deliberately
differ from dpkt on some inputs. The core does not map errors to Python classes.

The parser holds at most one packet buffer and fixed headers. Memory also depends
on input buffering and any outputs the caller retains. There is no process-wide
memory cap, total capture-size cap, packet-count cap or wall-clock timeout. A
caller-provided `Read` can block; the host must supply its own I/O policy.

## Verify

```sh
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked --doc
cargo build --locked
python3 -m compileall -q tools python tests/python
```

Use separate environments for the two published reference versions. The test
harness runs the reference interpreter in isolated mode and verifies its import
origin and installed distribution version. Install only the hash-pinned wheels:

```sh
python3 -m venv .venv-oracle-198
.venv-oracle-198/bin/python -m pip install --require-hashes --only-binary=:all: -r tools/oracle-1.9.8.txt
python3 tools/differential.py --python "$PWD/.venv-oracle-198/bin/python"

python3 -m venv .venv-oracle-196
.venv-oracle-196/bin/python -m pip install --require-hashes --only-binary=:all: -r tools/oracle-1.9.6.txt
python3 tools/differential.py --python "$PWD/.venv-oracle-196/bin/python" --version 1.9.6
```

After wheel installation the harness is offline. For an offline installation,
first download the pinned wheels to a local wheelhouse and add
`--no-index --find-links /path/to/wheelhouse` to the installation commands.

The [Python reader guide](docs/python-reader.md) covers local wheel builds,
isolated installation and verification commands. The [capture API
reference](docs/capture-api-ledger.md) lists supported behavior and exclusions.
The reader and writer guides describe streaming, timestamp, ownership and
resource-limit semantics. No performance, whole-library parity or package
resolver substitution is claimed.

## License

Original work is under the [BSD 3-Clause license](LICENSE). dpkt attribution and
its applicable upstream license are retained in [NOTICE](NOTICE) and
[licenses/dpkt.txt](licenses/dpkt.txt). The synthetic fixtures are original test
data.
