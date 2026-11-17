# SIP messages

`octetrail.sip` parses and packs SIP requests and responses the way dpkt 1.9.8
does. As in dpkt, `sip.Request` and `sip.Response` are the
[HTTP classes](http.md) with SIP's methods, protocol name and defaults, so
parsing, packing and errors follow the HTTP module.

```python
from octetrail import sip

r = sip.Request(b"BYE sip:bob@biloxi.example SIP/2.0\r\nCall-ID: a84b\r\n\r\n")
assert (r.method, r.version, r.headers["call-id"]) == ("BYE", "2.0", "a84b")
```

## Fields

- `Request`: `method`, `uri`, `version`, `headers`, `body` and `data`. The
  method must be one of ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY,
  OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE or UPDATE, and the
  version word must start with `SIP`.
- `Response`: `version`, `status`, `reason`, `headers`, `body` and `data`. The
  status line must start with `SIP`.

A new request is `INVITE sip:user@example.com SIP/2.0` and a new response is
`SIP/2.0 200 OK`. Both start with empty To, From, Call-ID, CSeq and Contact
headers. As in dpkt, that default header dict is one object shared by every
new message, so changing it on one message changes it on the others. Pass
`headers=` to give a message its own.

Header names are lower-cased when parsed, and compact forms such as `v` or `i`
are kept as they are. The body follows Content-Length, Transfer-Encoding and
Content-Type as in HTTP.

## Measured compatibility

The [fixture driver](../tools/sip_differential.py) parses 19 requests and
responses and checks defaults, keywords, repacking and the shared default
headers. OctetRail must equal dpkt 1.9.8 on all 31 observations, with no
declared differences:

```sh
python3 tools/sip_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
