# Gzip

`octetrail.gzip` parses and packs gzip member headers (RFC 1952) the way dpkt
1.9.8 does. `Gzip` and `GzipExtra` use the [`Packet`](packet.md) base, as in
dpkt. The module has dpkt's method, flag and OS constants.

```python
from octetrail import gzip

packet = gzip.Gzip(filename="hello.txt", data=b"payload")
parsed = gzip.Gzip(bytes(packet))
assert parsed.flags == gzip.GZIP_FNAME
assert parsed.filename == "hello.txt"
```

## Fields

`Gzip` has `magic`, `method`, `flags`, `mtime`, `xflags` and `os`. After
parsing, `extra` is a `GzipExtra` with `id` and `len`, `filename` is a `str`,
`comment` is bytes, and each is `None` when its flag is not set. `data` holds
the bytes after the optional fields, which is the compressed stream and its
trailer. Neither the magic nor the method is checked, as in dpkt.

The encryption header and the header CRC are skipped when their flags are set,
and are not kept.

## Packing

`bytes()` packs the header, then `extra`, `filename` and `comment` when they
are set, and sets their flags. The encryption header and the header CRC are
not packed back, as in dpkt.

`compress()` replaces `data` with a raw deflate stream and `decompress()`
returns the inflated payload. As in dpkt, `compress()` keeps only the output of
the final flush, and `decompress()` has no size limit, so call it only on
trusted data.

## Errors

- A header shorter than 10 bytes raises `NeedData`.
- A cut-off extra field, a file name or comment with no NUL byte, and a short
  encryption header or header CRC raise `NeedData` with dpkt's messages.
- A file name that is not UTF-8 raises `gzip.FilenameDecodeError`, which is
  both an `UnpackError` and a `UnicodeDecodeError` with dpkt's message. dpkt
  raises `UnicodeDecodeError` there.

## Verification

The [fixture driver](../tools/gzip_differential.py) parses 20 headers,
including dpkt's test vector, and builds, repacks, compresses and decompresses
members. OctetRail must equal dpkt 1.9.8 on all 30 observations except the
declared file name error:

```sh
python3 tools/gzip_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
