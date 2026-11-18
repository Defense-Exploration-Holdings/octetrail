# DNS messages

`octetrail.dns` parses and packs DNS messages the way dpkt 1.9.8 does. `DNS`,
`DNS.Q` and `DNS.RR` are [`Packet`](packet.md) subclasses, as in dpkt, and names
are read and written in Rust. `dns.DNS(bytes)` decodes one message payload. It does
not open sockets, perform lookups, consume a TCP length prefix or change UDP/IP
dispatch, so call it on payload bytes you already have.

```python
from octetrail import dns

query = dns.DNS(id=17, qd=[dns.DNS.Q(name="note.example", type=dns.DNS_A)])
decoded = dns.DNS(bytes(query))
assert decoded.qd[0].name == "note.example"
```

## Messages

A message has `id`, `op`, `qd`, `an`, `ns`, `ar` and `data`. The four sections are
lists of `DNS.Q` questions and `DNS.RR` records, and the header counts are taken
from their lengths when packing. The flag accessors are `qr`, `opcode`, `aa`, `tc`,
`rd`, `ra`, `zero` and `rcode`, plus `ad` and `cd`, which dpkt does not have. A
new message has `op` set to `DNS_RD`. `len()` is the length of `bytes()`. As in
dpkt, `pack_hdr()` raises `PackError` because the sections are lists, and
`repr()` shows the fields that differ from their defaults.

Parsing stops after the declared sections. Any bytes after them are dropped and
`data` is empty. `data` is never packed. These rules are the same as dpkt.

## Subclasses

As in dpkt, `DNS.unpack` reads each question with `unpack_q(buf, off)` and each
record with `unpack_rr(buf, off)`, which creates `self.Q()` or `self.RR()` and
calls the record's `unpack_rdata(buf, off)`. `bytes()` calls `pack_q(buf, q)`,
`pack_rr(buf, rr)` and the record's `pack_rdata(off, label_ptrs)`. A subclass
can replace any of these, or set its own `Q` and `RR` classes, as dpkt's NetBIOS
name service does.

## Questions and records

Questions have `name`, `type` and `cls`. As in dpkt, a new question or record
has `name` set to `b""`, so set a string before packing it. Records add `ttl`, `rlen` (the declared
RDATA length) and `rdata`. `rdata` is the declared RDATA cut to the bytes that
are actually present, so it can be shorter than `rlen`. Each type also gets the
fields dpkt sets for it:

| Type | Fields |
| --- | --- |
| A / AAAA | `ip` / `ip6`, the same bytes as `rdata` |
| NS / CNAME / PTR | `nsname` / `cname` / `ptrname` |
| MX | `preference`, a one-item tuple as in dpkt, and `mxname` |
| SOA | `mname`, `rname`, `serial`, `refresh`, `retry`, `expire`, `minimum` |
| TXT / HINFO | `text`, a list of strings |
| SRV | `priority`, `weight`, `port`, `srvname` |
| NULL | `null`, the hex of `rdata` as ASCII bytes |
| OPT | none |

Other record types raise `UnpackError` ("RR type N is not supported"), as in dpkt.
Names in RDATA are read from the whole message, so a compressed name can end past
the declared RDATA. SOA numbers are read from the message right after the two
names. MX and SRV numbers come from `rdata`, which must hold them.

## Names

Names are UTF-8 strings with labels joined by dots. The empty string is the root.
A label that contains a dot byte is joined as it is. Compression pointers must
point before the start of the name being read, so every name ends. The labels of
one name may add up to at most 255 bytes, each label counted with its length
byte.

`dns.unpack_name(buf, off)` and `dns.pack_name(name, off, label_ptrs)` are the
module-level helpers dpkt has. `pack_name` splits the name on dots and writes
each label as it is, without checking it. It reuses an entry of `label_ptrs` (upper-cased
suffix bytes ending in a dot, mapped to offsets) when one matches. It also adds
the suffixes it writes below offset 0xc000. As in dpkt, a name that is not a
string raises `TypeError` and a label over 255 bytes raises `struct.error`.

## Errors

The error classes follow dpkt:

- `NeedData`: the message is shorter than twelve bytes, or a name runs past the
  end of the message.
- `UnpackError`:
  - a fixed-size field is cut short (a question's type and class, a record's
    ten fixed bytes, SOA numbers, or MX and SRV numbers inside `rdata`), with
    dpkt's "invalid DNS" message;
  - a pointer does not point backwards;
  - a name is too long;
  - a label uses a reserved length form;
  - the record type is unsupported.
- `ShortPointerError`: `unpack_name` reached a name that ends one byte into a
  compression pointer. dpkt raises `struct.error`; this class subclasses both
  `UnpackError` and `struct.error` and keeps dpkt's message.
- `TextDecodeError`: a name or TXT or HINFO string is not UTF-8. dpkt raises
  `UnicodeDecodeError`; this class subclasses both `UnpackError` and
  `UnicodeDecodeError` and keeps dpkt's message.
- `ParseLimitError`: a subclass of `UnpackError` and of `dns.LimitError`. It is
  raised when parsing takes more than 16,777,216 name steps or decodes more than
  64 MiB of names and text. Pointers must point backwards, but a crafted message
  can still chain thousands of them, and this budget bounds that work. dpkt has
  no such limit.

## Packing

`bytes()` packs as dpkt's `DNS.__bytes__` does. It writes the header, then each
question and record owner name, compressed against the names before it, then
the resource data:

- A nonempty `rdata` is copied as it is, for every type. A parsed record
  therefore packs its original RDATA bytes. That includes any compression
  pointers inside them, even if the names before them changed. To pack a
  changed `cname`, `text`, `ip` or other field, set `rdata = b""` first.
- With empty `rdata`, the typed fields are packed: `ip` or `ip6`, the names
  (compressed), the numbers, or the text strings, which must be bytes. OPT
  packs no data. NULL and unknown types raise `PackError`. A missing field
  raises `AttributeError`, as in dpkt.
- `rdlen` is the length of the data written. `rlen` is not used.

As in dpkt, integer fields out of range, text over 255 bytes, RDATA over 65535
bytes and a parsed MX `preference` tuple raise `struct.error`, and text strings
that are not bytes raise `TypeError`.

## Measured compatibility

The private parity harness decodes dpkt-built messages and mutations of them with
both libraries and compares the outcome class, the header fields and the packed
bytes. Its seed messages cover every record type above, in all three sections.
The [fixture driver](../tools/dns_differential.py) checks 22 hand-assembled
messages, twelve constructors, header flag changes and raw RDATA precedence
against dpkt 1.9.6 and 1.9.8. It also compares 43 observations with dpkt 1.9.8
as they are, including `repr()`, error classes and messages and a subclass that
replaces `Q`, `RR` and `unpack_rdata`; the two `TextDecodeError` cases are the
declared differences. dpkt's own DNS tests also pass against OctetRail.

```sh
python3 tools/dns_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```

TCP framing, EDNS option parsing, DNSSEC records
and transport dispatch are not provided, and dpkt does not provide them either.
