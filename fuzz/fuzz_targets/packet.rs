#![no_main]
//! Ethernet, IPv4/IPv6 and TCP/UDP decoding, starting at every layer.
use libfuzzer_sys::fuzz_target;
use octetrail::{ethernet, ipv4, ipv6, tcp, udp, vrrp};

fn transport(protocol: u8, data: &[u8]) {
    match protocol {
        6 => tcp_round_trip(data),
        17 => {
            let _ = udp::Datagram::parse(data, udp::Limits::default());
        }
        _ => {}
    }
}

// A parsed segment always packs back to the exact input, as in dpkt.
fn tcp_round_trip(data: &[u8]) {
    if let Ok(segment) = tcp::Segment::parse(data, tcp::Limits::default()) {
        assert_eq!(segment.to_bytes(tcp::Limits::default()).unwrap(), data);
    }
}

fn network(data: &[u8]) {
    if let Ok(mut packet) = ipv4::Packet::parse(data) {
        transport(packet.header.protocol, packet.data);
        let _ = packet.to_bytes();
    }
    if let Some((pseudo, rest)) = data.split_first_chunk::<12>() {
        let _ = ipv4::pseudo_checksum(pseudo, rest);
    }
    if let Ok(packet) = ipv6::Packet::parse(data) {
        if let Some(protocol) = packet.next {
            transport(protocol, &data[packet.rest.0..packet.rest.1]);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = ethernet::Frame::parse(data) {
        let payload = &data[frame.header + ethernet::HEADER_LEN..];
        match frame.kind {
            ethernet::Kind::Typed => {
                if let Ok(stack) = ethernet::Stack::parse(payload, frame.ethertype) {
                    network(&payload[stack.payload..]);
                }
            }
            ethernet::Kind::Llc { llc, .. } => {
                let _ = ethernet::Llc::parse(&data[llc.0..llc.1]);
            }
            _ => {}
        }
    }
    let _ = ethernet::crc32(data);
    if let Some((&count, rest)) = data.split_first() {
        let _ = vrrp::layout(count, rest);
    }
    network(data);
    tcp_round_trip(data);
    let _ = udp::Datagram::parse(data, udp::Limits::default());
});
