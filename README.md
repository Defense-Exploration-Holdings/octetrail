# OctetRail

Fast packet parsing and pcap I/O for Python, written in Rust.

OctetRail started as a rewrite of [dpkt](https://github.com/kbandla/dpkt) and
keeps dpkt's API: module names, `Packet` classes, fields and exceptions.

Rust handles the parts where malformed input does damage: reading and writing
capture files, and loops over variable-length data such as DNS names, options
and extension headers. Those run with fixed size limits, so a crafted packet
cannot make them allocate or recurse without bound. The crate has no `unsafe`
code and its parsers are fuzzed. The packet classes themselves are Python.

Versions follow semantic versioning: breaking changes come only with a new
major version.

## Install

```sh
pip install octetrail
```

```python
from octetrail import ethernet, pcap

with pcap.open("capture.pcap") as reader:
    for timestamp, buf in reader:
        eth = ethernet.Ethernet(buf)
        print(timestamp, type(eth.data).__name__)
```

## Capture files

| Format | Read | Write | Not supported |
| --- | --- | --- | --- |
| pcap | yes | yes | Modified (Kuznetzov) pcap |
| PCAPNG | Enhanced Packet Blocks | One section, one interface | Simple and obsolete Packet Blocks |
| snoop | yes | yes | |

See [docs/pcapng-reader.md](docs/pcapng-reader.md) and
[docs/python-reader.md](docs/python-reader.md) for details.

## Protocols

| Layer | Modules |
| --- | --- |
| Link | [ethernet, llc, stp, ipx](docs/ethernet.md), [arp](docs/arp.md), [ppp, pppoe](docs/ppp.md), [sll, sll2, loopback](docs/sll-loopback.md), [ieee80211, radiotap](docs/ieee80211-radiotap.md), [cdp, dtp, edp](docs/cdp-dtp-edp.md), [aoe](docs/aoe.md) |
| Network | [ip](docs/ipv4.md), [ip6](docs/ipv6.md), [icmp, icmp6](docs/icmp.md), [igmp, vrrp](docs/igmp-vrrp.md), [gre, pim](docs/gre-pim.md), [ah, esp](docs/esp-ah.md), [ospf](docs/ospf-sctp.md) |
| Transport | [tcp](docs/tcp.md), [udp](docs/udp.md), [sctp](docs/ospf-sctp.md) |
| Application | [dns](docs/dns.md), [http](docs/http.md), [http2](docs/http2.md), [sip](docs/sip.md), [ssl](docs/tls.md), [dhcp](docs/dhcp.md), [bgp](docs/bgp.md), [mrt](docs/mrt.md), [netflow](docs/netflow.md), [diameter](docs/diameter.md), [radius, rtp, stun, tpkt](docs/radius-rtp-stun-tpkt.md), [ntp, rip, tftp, hsrp](docs/ntp-rip-tftp-hsrp.md), [netbios](docs/netbios.md), [rpc](docs/rpc.md), [h225](docs/h225.md), [asn1](docs/asn1.md), [telnet](docs/telnet.md), [gzip](docs/gzip.md) |
| Legacy | [aim](docs/aim.md), [qq](docs/qq.md), [sccp](docs/sccp.md), [pmap, rx, tns, yahoo, smb, rfb](docs/small-apps.md) |

Each page lists where the module behaves differently from dpkt. To write your
own header classes, see [docs/packet.md](docs/packet.md).

## Rust

The crate can be used as a git dependency. Its supported API is capture file
I/O. The protocol parsers are behind the `protocols` feature, which exists for
the Python bindings and can change at any time.

```rust
use octetrail::{Limits, Reader};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = Reader::new(File::open("capture.pcap")?, Limits::default())?;
    for packet in reader {
        println!("{} bytes", packet?.data.len());
    }
    Ok(())
}
```

## AI-Assisted Development

OctetRail is written with help from AI coding tools. Every change is reviewed
before it is merged, and protocol modules are tested against dpkt on dpkt's own
test vectors and on generated and mutated inputs. The less common protocols
have seen less real traffic than the core ones, so report anything that looks
wrong.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), and
[SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Sponsors

<a href="https://appliku.com/"><img src="https://raw.githubusercontent.com/Defense-Exploration-Holdings/octetrail/main/assets/sponsors/appliku.png" alt="Appliku" height="64"></a>
&nbsp;&nbsp;
<a href="https://github.com/speedpy/speedpy"><img src="https://raw.githubusercontent.com/Defense-Exploration-Holdings/octetrail/main/assets/sponsors/speedpy.png" alt="SpeedPy" height="64"></a>

[Appliku](https://appliku.com/) and [SpeedPy](https://github.com/speedpy/speedpy) support this project.

## License

Original work is under the [BSD 3-Clause license](LICENSE). dpkt attribution and
its applicable upstream license are retained in [NOTICE](NOTICE) and
[licenses/dpkt.txt](licenses/dpkt.txt). The synthetic fixtures are original test
data.
