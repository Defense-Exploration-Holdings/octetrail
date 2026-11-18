# IEEE 802.11 and radiotap

`octetrail.ieee80211` and `octetrail.radiotap` parse and pack 802.11 frames and
radiotap headers the way dpkt 1.9.8 does. The classes use the
[`Packet`](packet.md) base, as in dpkt. The information element walk and the
radiotap present words are read in Rust.

```python
from octetrail import ieee80211, radiotap

probe = bytes([0x40, 0, 0, 0]) + bytes(18) + b"\x10\x00" + b"\x00\x04note"
frame = ieee80211.IEEE80211(probe + bytes(4))
assert frame.ssid.info == b"note"
packet = radiotap.Radiotap(b"\x00\x00\x08\x00\x00\x00\x00\x00" + probe + bytes(4))
assert packet.data.ssid.info == b"note"
```

## IEEE 802.11

`IEEE80211` has `framectl` and `duration`, with `version`, `type`, `subtype`,
`to_ds`, `from_ds`, `more_frag`, `retry`, `pwr_mgt`, `more_data`, `wep` and
`order` as bit properties of `framectl`. `IEEE80211(buf, fcs=True)` cuts the
last 4 bytes into `fcs` before decoding.

- Management frames set `mgmt` and decode beacons, probe responses,
  association, reassociation, disassociation, authentication, deauthentication
  and action frames under dpkt's attribute names. Probe requests are read as
  information elements only, and ATIM frames are not decoded further.
  Capability frames get a `capability` object.
- Control frames decode RTS, CTS, ACK, block ack, block ack request and CF-End.
- Data frames pick `Data`, `DataFromDS`, `DataToDS` or `DataInterDS` from the
  DS bits, and QoS data sets `qos_data`.
- Information elements go into `ies` in wire order and onto an attribute per
  element, such as `ssid`, `rate`, `ds` or `tim`, or `ie_<id>` for other ids.
  As in dpkt, the walk stops when 4 or fewer bytes are left.

A type and subtype dpkt does not decode raises `UnpackError` with dpkt's
message. The module also has dpkt's constants and its `ntole` helper.

## Radiotap

`Radiotap` has `version`, `pad`, `length` and `present_flags`, with a
`*_present` property for each field bit. The present word is followed by more
words while bit 31 is set. Each present field is decoded with dpkt's alignment
into an attribute such as `tsft`, `flags`, `rate` or `channel`, and into
`fields`. The bytes after `length` decode as `IEEE80211`, with the FCS cut when
the flags field says so.

When the present words run past the end of the buffer, OctetRail raises
`radiotap.PresentFlagsError`, which is both an `UnpackError` and an
`IndexError` with dpkt's message. dpkt raises `IndexError` there.

## Verification

The [fixture driver](../tools/ieee80211_radiotap_differential.py) parses 75
frames, including dpkt's own test vectors with and without an FCS, and builds
frames from keywords. OctetRail must equal dpkt 1.9.8 on all 91 observations
except the two declared present word errors:

```sh
python3 tools/ieee80211_radiotap_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
