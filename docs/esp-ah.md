# AH and ESP

`octetrail.ah` and `octetrail.esp` parse and pack IPsec Authentication Header
and Encapsulating Security Payload packets the way dpkt 1.9.8 does. Both are
fixed headers on the [`Packet`](packet.md) base, as in dpkt. IPv4 decodes
protocol 51 as AH and 50 as ESP, through the protocol table filled from the
`IP_PROTO_*` names. IPv6 reads both as [extension headers](ipv6.md) instead,
as dpkt does.

```python
from octetrail import ah, ip

packet = ah.AH(nxt=59, len=2, spi=0x100, seq=1, auth=b"icv!", data=b"rest")
parsed = ip.IP(bytes(ip.IP(p=51, data=packet)))
assert parsed.ah.auth == b"icv!" and parsed.ah.data == b"rest"
```

## AH

`AH` has `nxt`, `len`, `rsvd`, `spi` and `seq`, then `auth`, which is
`4 * len - 4` bytes long (RFC 4302), or empty when `len` is 0 or 1. The rest is
decoded with `IP.get_proto(nxt)` and also set as an attribute named after its
class, so an AH header can carry TCP, UDP, IPv4, IPv6, ESP or another AH. An
unknown `nxt`, or a payload that raises `UnpackError` or `NeedData`, leaves the
bytes. `auth` is cut to the bytes present.

Packing writes the header, `auth` and `data` as assigned. No checksum or length
is computed.

## ESP

`ESP` has `spi` and `seq`, and the encrypted rest in `data`.

## Errors

A header shorter than its fixed length raises `NeedData`. Inside IPv4 such a
payload stays bytes. As with IPv4 in IPv4, a chain of AH headers deeper than
the Python recursion limit raises [`NestingError`](nesting.md), both an
`UnpackError` and the `RecursionError` dpkt raises.

One difference from dpkt 1.9.8 is declared. When an AH header carries IPv6
whose next header is 44 after an extension header that is not a fragment
header, dpkt raises `AttributeError` out of `AH`, and out of the IPv4 or IPv6
packet that carries the AH. OctetRail raises
[`FragmentOffsetError`](ipv6.md#errors) for the inner packet, which is an
`UnpackError`, so `AH` keeps it as bytes, as `IP` and `ICMP6` do.

## Verification

`tools/esp_ah_differential.py` parses 26 packets, alone and inside IPv4 and
IPv6, including dpkt's AH test vectors, and builds and repacks packets from
keywords. OctetRail must equal dpkt 1.9.8 on every observation except the
declared fragment offset case:

```sh
python3 tools/esp_ah_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
