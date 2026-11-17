# Explicit offline DNS messages

`octetrail.dns.DNS(bytes)` decodes one message payload. It does not open sockets,
perform lookups, consume a TCP length prefix or change UDP/IP dispatch. Call it
explicitly on bytes returned by the existing offline APIs.

```python
from octetrail import dns

question = dns.DNS.Q(name="note.example", type=dns.DNS_A)
query = dns.DNS(id=17, qd=[question])
decoded = dns.DNS(bytes(query))
assert decoded.qd[0].name == "note.example"
```

The mutable message surface is `id`, `op`, `qd`, `an`, `ns`, `ar` and `data`.
Sections are independent lists of `DNS.Q` questions or `DNS.RR` records. Header
counts are derived from those lists. The covered bit accessors are `qr`,
`opcode`, `aa`, `tc`, `rd`, `ra`, `zero` and `rcode`; `ad` and `cd` are additional
flag conveniences. `pack_hdr()` is a twelve-byte header/count convenience outside
the measured dpkt equality surface; `bytes()` and `len()` use the complete
serialized message. Standalone Q/RR lengths and unpacking remain
unsupported because names depend on their message context.

Questions have `name`, `type` and `cls`. Records also expose `ttl`, original
`rlen`, and exact original `rdata`. The covered decoded fields are:

| Type | Decoded fields |
| --- | --- |
| A / AAAA | `ip` / `ip6` bytes, also retained in `rdata` |
| NS / CNAME / PTR | `nsname` / `cname` / `ptrname` |
| MX | integer `preference`, `mxname` |
| SOA | `mname`, `rname`, `serial`, `refresh`, `retry`, `expire`, `minimum` |
| TXT / HINFO | `text`, a mutable list of UTF-8 strings |
| SRV | `priority`, `weight`, `port`, `srvname` |
| NULL | opaque `rdata`; `null` is its ASCII hex bytes |
| OPT and unrecognized types | opaque `rdata`, without option/record interpretation |

Names are UTF-8 text without a trailing dot or embedded dot inside a wire label.
The empty string represents the root. There is no IDNA conversion. Text
construction accepts UTF-8 strings or bytes; binary non-UTF-8 names/text remain
outside this first slice. Address lengths must be exactly four or sixteen bytes.
HINFO requires two strings. Structural truncation raises `NeedData`, unsupported
name/RDATA layouts or encoding raise `UnpackError`, and packing invalid fields
raises `PackError`. Missing structured record fields fail rather than becoming
invented values. Numeric field widths are checked; opcode/rcode masking and
truthy single-bit setters follow the covered dpkt behavior.

## Compression, mutation and limits

Rust checks every field and name slice against the message/RDATA boundary.
Compressed names use backward references, with a maximum of 128 pointer hops per
name. Serialization rebuilds a deterministic compression dictionary, preserving
the covered ordinary wire outputs and using only representable 14-bit offsets.
Compression dictionary keys ignore ASCII case, as in dpkt; a repeated suffix
with different case can take the spelling of its first occurrence.
The name limit is 255 wire bytes, including the terminating root byte; labels
are at most 63 bytes. Message bytes are limited to 65535, total questions and
records to 1024 and charged work bytes to 4 MiB. The work-step budget is
1,243,135, derived from three bounded names per record, two charges per label,
128 pointer hops per name, a per-record charge and possible text bytes. Ordinary
larger compressed responses fit this budget. Before any count-based allocation
or record-count limit, the remaining bytes must fit at least five bytes per
question and eleven per record; otherwise parsing raises `NeedData`.
Parse budgets raise `dns.ParseLimitError`, a subclass of both `UnpackError` and
the existing `dns.LimitError`/ValueError family. Existing catch styles therefore
work. Serialization limits remain `dns.LimitError` and are not parse errors. These bounds are not total process-memory or wall-clock guarantees.

Known name-bearing and text records serialize from decoded fields, rebuilding
compression after mutations or layout changes. Their original `rdata` remains
available for inspection. Raw overrides for these records are unsupported and
raise `PackError`; supply structured fields instead. Unlike the references,
changing parsed `.cname` or `.text` takes effect without clearing `.rdata` first.
For A/AAAA, nonempty `rdata` takes precedence over `ip`/`ip6`, as in dpkt; clear
it to serialize a changed address alias. For example, after parsing an A
record, set `rr.ip = new_four_bytes` and `rr.rdata = b""` before `bytes(message)`.
For AAAA use `rr.ip6` with sixteen bytes and likewise clear `rdata`. Merely
editing either alias leaves the original captured address unchanged. This is
intentional reference-compatible precedence, unlike the structured CNAME/text
policy described above. Opaque NULL/OPT/unknown data is copied
exactly and is never interpreted or rebased. Any format-specific embedded offsets
inside an unknown record remain the caller's responsibility. The emitted RDATA
length is derived from actual bytes; the inspected `rlen` attribute is not updated.

Trailing unconsumed bytes are retained in `DNS.data` and serialized, unlike the
references, which discard them. Parsing fails as a whole on an incomplete
declared section; it does not silently return a partial list.

## Measured compatibility and exclusions

The [fixture driver](../tools/dns_differential.py) uses independently assembled
benign messages and both hash-pinned dpkt references. It checks 22 messages,
twelve constructors, header flag changes and two structured mutation sequences.
Seventeen fixture cases are equal for declared fields, exact serialized output
and length. Five explicit fixture differences cover two unknown RR types,
trailing bytes, re-encoding originally uncompressed name RDATA, and parsed MX
preference. Both pinned versions expose MX preference as a one-item tuple;
OctetRail uses an integer. The separate mutation sequences record the structured
field precedence difference described above. These outcomes are not normalized
into parity claims.

```sh
python3 tools/dns_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```

The driver requires both references and an installed candidate, runs isolated
optimized probes, and verifies versions/module origins with explicit failures.
Full exception messages, unusual name encodings, arbitrary Packet APIs,
standalone RR wire APIs, EDNS option semantics, DNSSEC interpretation, TCP framing,
stream reassembly and automatic transport dispatch are deferred. The exposed
fields cover common DNS record data, but no downstream application support,
dependency/import replacement, network service or broad DNS parity is claimed.
The [explicit HTTP subset](http.md) and [passive TLS subset](tls.md) are separate.

The review regression checks also compare a 768-record compressed NS response,
two A/AAAA edit sequences and minimum-size/count decisions against both pins.
The product retains its declared record cap while both references accept the
covered complete 1025-question message. This resource difference is explicit.
