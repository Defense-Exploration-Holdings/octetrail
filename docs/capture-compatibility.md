# Explicit Python capture provider

Select the covered offline API explicitly:

```python
from octetrail import capture as packets

with open("synthetic.pcap", "rb") as source:
    reader = packets.pcap.Reader(source)
    with open("copy.pcap", "wb") as target:
        writer = packets.pcap.Writer(target, snaplen=reader.snaplen,
                                       linktype=reader.datalink())
        for timestamp, payload in reader:
            writer.writepkt_time(payload, timestamp)
        writer.close()
```

This example copies a microsecond classic capture. For classic nanoseconds,
select `nano=True` on the writer to preserve that resolution. Captured bytes are
copied as opaque data; no protocol decoder, live input or network sink is added.
The Reader borrows its input. Writer.close closes its supplied output. The
[reader](python-reader.md), [classic output](pcap-writer.md),
[PCAPNG reader](pcapng-reader.md) and [PCAPNG output](pcapng-writer.md) guides
remain the API and resource-limit references.

`capture` exports `pcap`, `pcapng`, `Error`, `UnpackError` and `NeedData` as the
same objects already supplied by OctetRail. The error hierarchy is
`NeedData -> UnpackError -> Error -> Exception`. The provider adds no fallback,
import hook or global alias. `import dpkt` still selects an independently
installed upstream package, or fails when it is absent. Class module names remain
`octetrail.pcap` and `octetrail.pcapng`; pickling, introspection, subclassing and
full error-message compatibility are outside the measured contract.

## Selected constants

These sixteen common exports are checked against both published baselines.
They are a small explicit subset of the versioned [API inventory](capture-api-ledger.md).

| Module | Names and values |
| --- | --- |
| pcap | DLT_NULL=0, DLT_EN10MB=1, DLT_LINUX_SLL=113, DLT_USER0=147 |
| pcap | PCAP_VERSION_MAJOR=2, PCAP_VERSION_MINOR=4 |
| pcap | TCPDUMP_MAGIC=0xa1b2c3d4, TCPDUMP_MAGIC_NANO=0xa1b23c4d |
| pcapng | DLT_NULL=0, DLT_EN10MB=1, DLT_LINUX_SLL=113 |
| pcapng | PCAPNG_VERSION_MAJOR=1, PCAPNG_VERSION_MINOR=0 |
| pcapng | PCAPNG_BT_SHB=0x0a0d0d0a, PCAPNG_BT_IDB=1, PCAPNG_BT_EPB=6 |

Full DLT/option/magic inventories, header/block classes, arbitrary packet objects
and protocol decoders remain absent. The measured [UniversalReader
factory](universal-reader.md) is a 1.9.8-only API and is excluded
from the common 1.9.6/1.9.8 consumer denominator. The known strict parsing rules,
per-interface clock differences and restricted custom-clock seconds output remain unchanged.

## Test-only namespace helper

The [namespace helper](../tools/capture_test_namespace.py) is disposable test
support outside the installed wheel. It maps only the root and two capture
modules, requires an isolated virtual environment and refuses to mask upstream
dpkt. It creates no distribution metadata. It is not a runtime shim or an
installation technique for downstream applications. The public tests and tools
run from this project root with the separate reference environments described
in the [README](../README.md).

## Distribution decision remains separate

The default distribution and import namespace remain `octetrail==0.1.0`. It
installs no `dpkt` package, startup hook, namespace alias, dependency or
Provides-Dist declaration. It cannot satisfy `dpkt==1.9.6`, `dpkt==1.9.8`, or any
other dpkt requirement. Both packages can coexist, with normal `import dpkt`
selecting upstream. `tools/capture_coexistence_probe.py` checks this in a fresh
environment containing both wheels, and checks that the temporary map refuses
that environment before loading upstream.

No opt-in import distribution or resolver substitution is supplied. A temporary
import alias cannot solve a dependency pin. Application compatibility requires
all accessed APIs and dependency metadata to be satisfied independently.
