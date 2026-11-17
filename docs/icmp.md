# ICMP and ICMPv6

`octetrail.icmp` and `octetrail.icmp6` parse and pack ICMP and ICMPv6 messages
the way dpkt 1.9.8 does, with dpkt's classes and constants. The messages have
fixed headers only, so the [`Packet`](packet.md) base reads them, as in dpkt.
IPv6 decodes protocol 1 as ICMP and 58 as ICMPv6. IPv4 dispatch to ICMP comes
with IPv4 parity.

```python
from octetrail import icmp

echo = icmp.ICMP(type=8, data=icmp.ICMP.Echo(id=1, seq=2, data=b"ping"))
parsed = icmp.ICMP(bytes(echo))
assert parsed.echo.data == b"ping" and parsed.sum == echo.sum
```

## ICMP

`ICMP` has `type`, `code` and `sum`. The body is decoded by type: `Echo` for
0 and 8, `Unreach` for 3, `Quench` for 4, `Redirect` for 5 and `TimeExceed`
for 11, and set as an attribute named after its class (`echo`, `unreach` and
so on). The quote classes decode the rest as IPv4 into `ip`. A body that raises
`UnpackError` or `NeedData`, including a quote whose IPv4 header is cut short,
stays bytes. `ParamProbe` exists but, as in dpkt, type 12 is not decoded. A
`sum` of 0 is computed when packing.

## ICMPv6

`ICMP6` has `type`, `code` and `sum`, and decodes `Unreach` (1), `TooBig` (2),
`TimeExceed` (3), `ParamProb` (4) and `Echo` (128 and 129) the same way. The
error classes decode the rest as IPv6 into `ip6`. Other types, including
neighbor discovery, stay bytes. The checksum is computed by `IP6` when it packs
an ICMPv6 payload with a `sum` of 0.

## Errors

A header shorter than four bytes raises `NeedData`. There are no other parse
errors.

One difference from dpkt 1.9.8 is declared. When an ICMPv6 error quotes an
IPv6 packet whose next header is 44 and whose last extension header is not a
fragment header, dpkt raises `AttributeError` out of `ICMP6`. OctetRail raises
[`FragmentOffsetError`](ipv6.md#errors) for the quote, which is an
`UnpackError`, so `ICMP6` keeps the quote as bytes.

## Verification

`tools/icmp_differential.py` parses 21 messages, alone and inside IPv6,
including dpkt's unreachable vector, and builds and repacks messages from
keywords. OctetRail must equal dpkt 1.9.8 on every observation except the declared one:

```sh
python3 tools/icmp_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
