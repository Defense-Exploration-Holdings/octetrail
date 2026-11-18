# BGP

`octetrail.bgp` parses and packs BGP-4 messages the way dpkt 1.9.8 does. Every
message, attribute and route class uses the [`Packet`](packet.md) base, with
dpkt's names, fields, nesting and constants.

```python
from octetrail import bgp

raw = bytes.fromhex("ffffffffffffffffffffffffffffffff001304")
packet = bgp.BGP(raw)
assert packet.type == bgp.KEEPALIVE
assert bytes(packet) == raw
```

## Classes

`BGP` reads the 19-byte header, cuts `data` to the header's length and parses
it by type into `BGP.Open`, `BGP.Update`, `BGP.Notification`, `BGP.Keepalive`
or `BGP.RouteRefresh`. The parsed message is also kept under its type's name,
such as `packet.update`.

- `BGP.Open` has a list of `BGP.Open.Parameter`, each holding a
  `Capability` or an `Authentication` where dpkt has one.
- `BGP.Update` has `withdrawn` and `announced` route lists and a list of
  `BGP.Update.Attribute`. Each attribute has the `optional`, `transitive`,
  `partial` and `extended_length` flag properties, and its value is parsed into
  the class for its type, such as `Origin`, `ASPath`, `Communities`,
  `ClusterList`, `MPReachNLRI` or `MPUnreachNLRI`.
- `RouteIPV4`, `RouteIPV6`, `ExtendedRouteIPV4`, `RouteEVPN` and
  `RouteGeneric` are the route classes. `MPReachNLRI` and `MPUnreachNLRI` pick
  one by address family, as dpkt does.

Behavior that dpkt has and that is kept as it is:

- Announced IPv4 routes are read as `ExtendedRouteIPV4`, with a path ID,
  whenever the bytes left are a multiple of 9.
- An `ASPath` reads 4-byte AS numbers only when it is exactly 6 bytes long,
  one segment with one AS.
- `BGP.marker` defaults to the text `"\xff" * 16`.

## Errors

Short and inconsistent input raises the errors dpkt raises, with dpkt's
messages. One differs: an EVPN route that ends before its MAC or IP address
length byte raises `bgp.EVPNIndexError`, where dpkt raises `IndexError`. It is
both an `UnpackError` and an `IndexError`, with the same message, so code that
catches either one handles it.

dpkt slices the rest of the buffer once per route, attribute, segment and
community, so long lists take quadratic time. OctetRail gives each element only
the bytes it can use and walks the rest by offset, so the same lists parse in
linear time with the same result.

## Verification

The [fixture driver](../tools/bgp_differential.py) parses 2,551 inputs: dpkt's
BGP test vectors, every prefix of them, byte edits of them and parts of
messages read with each class. It also builds, edits and packs messages.
OctetRail must equal dpkt 1.9.8 on all 2,558 observations, except the 285 where
dpkt raises the EVPN `IndexError`:

```sh
python3 tools/bgp_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
