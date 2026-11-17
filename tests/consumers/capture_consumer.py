"""Project-authored offline consumer, unchanged across the three providers.

It intentionally imports dpkt by its normal capture names. The harness chooses
an isolated provider before loading this file; no provider-specific code belongs
here. This is not the upstream dpkt test suite.
"""

import hashlib
from pathlib import Path

import dpkt
import dpkt.pcap as classic
from dpkt import pcapng
from dpkt.pcapng import Reader as NgReader


def constants():
    assert dpkt.pcap is classic and dpkt.pcapng is pcapng and NgReader is pcapng.Reader
    return {
        "pcap": [
            classic.DLT_NULL,
            classic.DLT_EN10MB,
            classic.DLT_LINUX_SLL,
            classic.DLT_USER0,
            classic.PCAP_VERSION_MAJOR,
            classic.PCAP_VERSION_MINOR,
            classic.TCPDUMP_MAGIC,
            classic.TCPDUMP_MAGIC_NANO,
        ],
        "pcapng": [
            pcapng.DLT_NULL,
            pcapng.DLT_EN10MB,
            pcapng.DLT_LINUX_SLL,
            pcapng.PCAPNG_VERSION_MAJOR,
            pcapng.PCAPNG_VERSION_MINOR,
            pcapng.PCAPNG_BT_SHB,
            pcapng.PCAPNG_BT_IDB,
            pcapng.PCAPNG_BT_EPB,
        ],
    }


def run(case):
    module = classic if case["format"] == "pcap" else pcapng
    reader_type = module.Reader
    if case["operation"] == "error":
        try:
            with open(case["input"], "rb") as stream:
                list(reader_type(stream))
        except dpkt.NeedData as error:
            return {
                "error": type(error).__name__,
                "unpack_family": isinstance(error, dpkt.UnpackError),
                "root_family": isinstance(error, dpkt.Error),
            }
        raise AssertionError("expected incomplete input to raise NeedData")
    rows, digest = [], hashlib.sha256()
    with open(case["input"], "rb") as stream:
        reader = reader_type(stream)
        metadata = [
            reader.snaplen,
            reader.datalink(),
            reader.dloff,
            reader.filter,
            reader.name == stream.name,
            reader.fd == reader.fileno() == stream.fileno(),
        ]

        def collect(timestamp, data, label="offline"):
            assert label == "offline" and type(data) is bytes
            rows.append([str(timestamp), type(timestamp).__name__, len(data)])
            digest.update(data)

        if case["operation"] == "dispatch":
            dispatched = reader.dispatch(1, collect, "offline")
            assert type(dispatched) is int and dispatched == len(rows) <= 1
            assert reader.loop(collect, "offline") is None
            assert reader.readpkts() == []
        elif case["operation"] == "copy":
            options = {"snaplen": reader.snaplen, "linktype": reader.datalink()}
            if case["format"] == "pcap":
                options["nano"] = case["nano"]
            with open(case["output"], "xb") as output:
                writer = module.Writer(output, **options)
                for timestamp, data in reader:
                    collect(timestamp, data)
                    assert writer.writepkt_time(data, timestamp) is None
                writer.close()
        else:
            assert case["operation"] == "read"
            for timestamp, data in reader:
                collect(timestamp, data)
    result = {"metadata": metadata, "rows": rows, "payload_sha256": digest.hexdigest()}
    if case["operation"] == "dispatch":
        result["dispatch_count"] = dispatched
    if case["operation"] == "copy":
        result["output_hex"] = Path(case["output"]).read_bytes().hex()
    return result
