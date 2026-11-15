//! Stream metadata and payload hex as JSON lines from a local offline capture.

use octetrail::{ByteOrder, Limits, Reader, Resolution};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let usage = "usage: pcap-read [--max-packet-bytes N] PATH";
    let first = args.next().ok_or(usage)?;
    let (limits, path) = if first == "--max-packet-bytes" {
        let value = args.next().ok_or(usage)?;
        let limit = value.to_str().ok_or(usage)?.parse()?;
        (
            Limits {
                max_packet_bytes: limit,
            },
            args.next().ok_or(usage)?,
        )
    } else {
        (Limits::default(), first)
    };
    if args.next().is_some() {
        return Err(usage.into());
    }
    let reader = Reader::new(BufReader::new(File::open(path)?), limits)?;
    let header = reader.header();
    let order = match header.byte_order {
        ByteOrder::Little => "little",
        ByteOrder::Big => "big",
    };
    let resolution = match header.resolution {
        Resolution::Microseconds => "microseconds",
        Resolution::Nanoseconds => "nanoseconds",
    };
    let mut out = BufWriter::new(io::stdout().lock());
    writeln!(
        out,
        "{{\"snaplen\":{},\"linktype\":{},\"byte_order\":\"{}\",\"resolution\":\"{}\"}}",
        header.snaplen, header.linktype, order, resolution
    )?;
    for packet in reader {
        let packet = packet?;
        write!(
            out,
            "{{\"seconds\":{},\"fraction\":{},\"original_len\":{},\"hex\":\"",
            packet.timestamp.seconds, packet.timestamp.fraction, packet.original_len
        )?;
        for byte in packet.data {
            write!(out, "{byte:02x}")?;
        }
        writeln!(out, "\"}}")?;
    }
    out.flush()?;
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pcap-read: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
