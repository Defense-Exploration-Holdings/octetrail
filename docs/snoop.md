# Snoop

`octetrail.snoop` reads and writes snoop capture files (RFC 1761) the way dpkt
1.9.8 does. `FileHdr` and `PktHdr` use the [`Packet`](packet.md) base, as in
dpkt. The module has dpkt's `Reader`, `Writer`, `FileReader` and `FileWriter`
classes, the `SNOOP_*` and `SDL_*` constants and the `dltoff` table.

```python
import io

from octetrail import snoop

out = io.BytesIO()
snoop.Writer(out).writepkt(b"frame", ts=1.5)
reader = snoop.Reader(io.BytesIO(out.getvalue()))
assert reader.datalink() == snoop.SDL_ETHER
assert reader.readpkts() == [(1.5, b"frame")]
```

## Reading

`Reader` checks the magic and looks up the link type in `dltoff`, which, as in
dpkt, knows only Ethernet. Iterating yields `(timestamp, bytes)` pairs, with
the timestamp as a float in seconds. Each record keeps its first `incl_len`
bytes. The version and the original length are not checked. As in dpkt, a
record length below 24 reads the rest of the file into that record.

`readpkts()`, `dispatch()`, `loop()`, `datalink()`, `fileno()` and the `name`,
`filter` and `dloff` attributes behave as in dpkt. `setfilter()` raises
`NotImplementedError`.

A record body is read in pieces of at most 1 MiB, so a record length larger
than the file does not make the reader allocate memory for it. The bytes
returned are the same as dpkt's.

## Writing

`Writer` writes the file header, then one record per packet, padded to a
multiple of four bytes. Timestamps are split into seconds and rounded
microseconds as in dpkt, so a fraction that rounds up to a full second is
written as 1000000 microseconds. A subclass can set `precision_multiplier`.
`writepkt()` uses the current time when no timestamp is given, and
`writepkts()` takes `(timestamp, bytes)` pairs.

## Errors

- A file header shorter than 16 bytes and a record header cut short raise
  `NeedData`.
- A file without the snoop magic raises `snoop.HeaderError`, which is both an
  `UnpackError` and a `ValueError`, with dpkt's message. dpkt raises
  `ValueError`.
- A link type that is not in `dltoff` raises `snoop.LinktypeError`, which is
  both an `UnpackError` and a `KeyError` holding the link type. dpkt raises
  `KeyError`.
- A timestamp or field outside an unsigned 32-bit value raises
  `struct.error` when writing a record and `PackError` when packing a header,
  as in dpkt.

## Verification

The [fixture driver](../tools/snoop_differential.py) reads 24 files, parses and
builds both headers, writes packets with edge-case timestamps and exercises the
reader methods. OctetRail must equal dpkt 1.9.8 on all 64 observations except
the declared magic and link type errors:

```sh
python3 tools/snoop_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
