#![no_main]
//! Ethernet II, IPv4/IPv6 and TCP/UDP decoding, starting at every layer.
use libfuzzer_sys::fuzz_target;
use octetrail::{ethernet, ipv4, ipv6, tcp, udp};

fn transport(protocol: u8, data: &[u8]) {
    match protocol {
        6 => {
            let _ = tcp::Segment::parse(data, tcp::Limits::default());
        }
        17 => {
            let _ = udp::Datagram::parse(data, udp::Limits::default());
        }
        _ => {}
    }
}

fn network(data: &[u8]) {
    if let Ok(mut packet) = ipv4::Packet::parse(data) {
        transport(packet.header.protocol, packet.data);
        let _ = packet.to_bytes();
    }
    if let Ok(packet) = ipv6::Packet::parse(data, ipv6::Limits::default()) {
        transport(packet.protocol, packet.data);
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = ethernet::Frame::parse(data, ethernet::Limits::default()) {
        network(frame.data);
    }
    network(data);
    let _ = tcp::Segment::parse(data, tcp::Limits::default());
    let _ = udp::Datagram::parse(data, udp::Limits::default());
});
