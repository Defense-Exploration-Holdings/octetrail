# Nested packets

dpkt decodes each payload with a nested call, so a packet whose headers nest
deeper than the Python recursion limit cannot be decoded. Chains of IPv4 in
IPv4, IPv6 in IPv4, IPv4 in IPv6, AH and GRE headers can do that. dpkt raises
`RecursionError` for them, and no payload decoder catches it, so it reaches the
caller.

OctetRail raises `octetrail.NestingError` instead, with Python's message. It is
both an `UnpackError` and a `RecursionError`, so code that catches either one
handles it, and code that catches `UnpackError` for every parse failure needs
no extra clause.

```python
from octetrail import NestingError, UnpackError, ip

layer = bytes.fromhex("450000000000000040040000") + bytes(8)
raw = b"x"
for _ in range(2000):
    raw = layer[:2] + (20 + len(raw)).to_bytes(2, "big") + layer[4:] + raw
try:
    ip.IP(raw)
except UnpackError as error:
    assert isinstance(error, NestingError) and isinstance(error, RecursionError)
```

The payload decoders of IPv4, IPv6, AH, GRE, ICMP, ICMPv6, Ethernet, LLC, PPP,
PPPoE, AoE, SLL and SLL2 keep a payload as bytes when it raises another
`UnpackError`, as dpkt does. They never do that for a `NestingError`: it passes
through every layer to the caller, as dpkt's `RecursionError` does. The depth
at which decoding fails depends on the recursion limit and the Python version,
as in dpkt.

IPv6 extension headers, including AH, are read in a loop and do not count
toward the limit.

The [ASN.1 decoder](asn1.md) raises the same class for elements nested more
than 512 levels deep; `asn1.NestingError` is `octetrail.NestingError`.

## Verification

The [fixture driver](../tools/nesting_differential.py) parses 40 chains at
depths that decode and depths past the recursion limit, alone and inside
Ethernet and PPPoE. It also checks which `except` clauses stop a chain that is
too deep. OctetRail must equal dpkt 1.9.8 on all 42 observations, except the
11 where dpkt raises `RecursionError` or lets it past an `UnpackError` clause:

```sh
python3 tools/nesting_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
