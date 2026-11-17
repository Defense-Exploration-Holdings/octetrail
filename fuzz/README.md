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
