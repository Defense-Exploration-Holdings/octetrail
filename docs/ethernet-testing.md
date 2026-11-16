# Reproduce the Ethernet II comparisons

The Ethernet tests use offline synthetic frames, six-byte explicit MAC addresses,
unsigned two-byte network-order type fields and opaque `bytes` payloads. The
required API is `octetrail.ethernet.Ethernet([buffer], dst=..., src=..., type=...,
data=...)`, with mutable `dst`, `src`, `type`, `data`, `bytes(packet)` and
`len(packet)`. Keyword construction and positional-buffer parsing are exercised
separately. Combined buffer/keyword behavior is outside the required subset.

No packet library encodes the inputs. A reviewed [literal frame](../tests/fixtures/ethernet-ii.hex)
and a separate [struct-based fixture encoder](../tools/ethernet_cases.py) define
expected frames. Tests cross-check network byte order using byte arithmetic.
The corpus includes type values on both sides of the signed 16-bit boundary,
empty and 1500-byte payloads, field replacement, repeated serialization and
ordinary incomplete headers. It requires no Ethernet padding or FCS synthesis.
Unknown type values keep payloads opaque in both reference versions.

Run the independent fixture checks without installing OctetRail:

```sh
python3 -I -m unittest discover -s tests/python -p test_ethernet_fixtures.py -v
```

Create separate virtual environments for the references. Install each with its
hash-pinned requirements, for example:

```sh
python3 -m venv /tmp/oracle-196
python3 -m venv /tmp/oracle-198
/tmp/oracle-196/bin/pip install --require-hashes --only-binary=:all: -r tools/oracle-1.9.6.txt
/tmp/oracle-198/bin/pip install --require-hashes --only-binary=:all: -r tools/oracle-1.9.8.txt
python3 tools/ethernet_differential.py --oracle-196 /tmp/oracle-196/bin/python --oracle-198 /tmp/oracle-198/bin/python
```

Without `--python`, this validates both oracles against independent expectations
and explicitly reports OctetRail comparisons as pending. It does not count those
pending comparisons as passes. To test a separately installed OctetRail wheel in
a clean virtual environment without dpkt:

```sh
python3 tools/ethernet_differential.py --oracle-196 /tmp/oracle-196/bin/python --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
/tmp/octetrail-wheel/bin/python -I -m unittest discover -s tests/python -p 'test_ethernet*.py' -v
```

The probe checks distribution versions and module locations in isolated Python
processes. Missing implementations fail; they are never silently skipped or
replaced. Error class names and failure phases are compared, while exception
messages are outside the claim. Reference-only cases record dpkt's retained
mutable buffer types, ignored keyword fields with positional input, short MAC
padding, and deferred `PackError` on invalid type values. These are scope gaps,
not established differences in OctetRail, and do not run against OctetRail.

Nested IPv4/TCP/UDP composition, `unpack()` and `pack_hdr()` are covered
separately by the [composition tests](composition.md). Generic `pack()`, type
registries, constants, arbitrary packet attributes, buffer protocols, 802.3/LLC,
VLAN, MPLS, padding/FCS interpretation, and downstream applications are outside
these comparisons. Default construction is measured separately: dpkt exposes
empty address fields, serializes them as six zero bytes, and defaults to type
`0x0800`; reparsing those bytes exposes six-byte zero addresses. No IPv4 payload
decoding is implied by that default observation. Passing this bounded corpus
does not establish general Ethernet or dpkt equivalence.
