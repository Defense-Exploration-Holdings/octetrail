# QQ

`octetrail.qq` parses and packs QQ instant messenger headers the way dpkt
1.9.8 does. `QQBasicPacket`, `QQ3Packet` and `QQ5Packet` use the
[`Packet`](packet.md) base, as in dpkt. The module has dpkt's command and
family constants and its `command_str` table from command number to name.

```python
from octetrail import qq

header = qq.QQBasicPacket(command=qq.QQ_CMD_SEND_IM, sequence=1, qqNum=7, data=b"hi")
assert qq.QQBasicPacket(bytes(header)).command == qq.QQ_CMD_SEND_IM
assert qq.command_str[qq.QQ_CMD_SEND_IM] == "QQ_CMD_SEND_IM"
```

## Fields

- `QQBasicPacket`: `header_type`, `source`, `command`, `sequence` and
  `qqNum`, 11 bytes.
- `QQ3Packet`: `header_type`, `command`, `sequence`, `unknown1` to
  `unknown13` and `source`, 46 bytes.
- `QQ5Packet`: `header_type`, `source`, `unknown`, `command`, `sequence` and
  `qqNum`, 13 bytes.

`data` holds the bytes after the header. Nothing is decoded further, and the
header type is not checked, as in dpkt.

## Errors

A buffer shorter than the header raises `NeedData`. There are no declared
differences.

## Verification

The [fixture driver](../tools/qq_differential.py) parses 8 headers, builds
them from keywords and reads the constants and the command table. OctetRail
must equal dpkt 1.9.8 on all 13 observations:

```sh
python3 tools/qq_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```
