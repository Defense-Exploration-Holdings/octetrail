# Fuzz targets

libFuzzer targets for the parsers that read untrusted bytes. Each target feeds
arbitrary input to a reader or decoder and only requires that it returns `Ok`
or `Err` without panicking, overflowing or exhausting memory.

| Target | Covers |
| --- | --- |
| `pcap_reader` | classic pcap header and record iteration |
| `pcapng_reader` | PCAPNG block framing, options and interface clocks |
| `packet` | Ethernet II, IPv4, IPv6 extension headers, TCP and UDP |
| `dns` | DNS messages, including name compression |
| `http` | HTTP/1.x start lines, headers and body selection |
| `tls` | TLS record framing, handshake headers and ServerHello |
| `http2` | HTTP/2 frame boundaries |
| `diameter` | Diameter AVP walk |
| `dhcp` | DHCP options |
| `netflow` | NetFlow record split |
| `ieee80211` | 802.11 information elements and radiotap present words |
| `h225` | H.225.0 element walk |
| `asn1` | ASN.1 walk, including the depth and element limits |

The [Fuzz workflow](../.github/workflows/fuzz.yml) runs every target for 15
minutes each Monday and on demand, keeping the corpus in the Actions cache. A
crash fails the run and uploads the reproducing input as an artifact.

The crate is not part of the main workspace, so normal builds and wheels do not
need nightly Rust. To run a target:

```sh
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --locked
cd fuzz
cargo +nightly fuzz run -O packet -- -max_total_time=60
```

Crashing inputs are written to `fuzz/artifacts/<target>/`. Reproduce one with
`cargo +nightly fuzz run -O <target> <file>` and add it as a regression test
next to the parser before fixing it.
