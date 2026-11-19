# RPC

`octetrail.rpc` parses and packs ONC RPC (RFC 5531) messages the way dpkt
1.9.8 does. RPC has only fixed headers, so the classes use the
[`Packet`](packet.md) base, as in dpkt. The module has dpkt's constants and its
XDR list helpers.

```python
from octetrail import rpc

call = rpc.RPC(xid=1, dir=rpc.CALL, data=rpc.RPC.Call(prog=100000, vers=2, proc=4))
assert rpc.RPC(bytes(call)).call.prog == 100000
```

## Classes

- `RPC` has `xid` and `dir`. A call is read into `call` and a reply into
  `reply`, and either one is also `data`. Any other `dir` leaves the bytes.
- `RPC.Call` has `rpcvers`, `prog`, `vers` and `proc`, then `cred` and `verf`
  (`RPC.Auth` objects).
- `RPC.Auth` has `flavor`, and its body in `data`, read by its length.
- `RPC.Reply` has `stat`. An accepted reply is read into `accept`
  (`RPC.Reply.Accept`, with `verf`, `stat`, and `low` and `high` for a program
  mismatch). A denied reply is read into `reject` (`RPC.Reply.Reject`, with
  `low` and `high` for an RPC mismatch, or `why` for an authentication error).

`unpack_xdrlist(cls, buf)` reads XDR optional-data lists of `cls` objects and
`pack_xdrlist(*items)` packs them.

## Packing

- A `Call` packs its header, `cred`, `verf` and then `data`. dpkt also packs
  `data` before the credentials, so a parsed call does not round-trip there.
- `Auth` pads its body to a multiple of four bytes, as XDR requires, and
  `len()` counts the padding. dpkt does neither.
- `unpack_xdrlist` continues from each item's `data`, so it suits classes whose
  `data` is the rest of the buffer. `RPC.Auth` is not one of them.
- `RPC.Reply.Accept()` has no `verf` until one is set, so it does not pack.

## Errors

Through the constructors, a header shorter than it needs raises `NeedData` and
a short length, mismatch or reason field raises `UnpackError`, as the `Packet`
base does for dpkt. Calling `unpack()` directly raises `struct.error` on the
same input, as in dpkt. `unpack_xdrlist` raises `UnpackError` on a word other
than 0 or 1.

## Verification

The [fixture driver](../tools/rpc_differential.py) parses 18 calls and
replies, and builds, packs and reads XDR lists from keywords. OctetRail must
equal dpkt 1.9.8 on all 36 observations, with no declared differences:

```sh
python3 tools/rpc_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
