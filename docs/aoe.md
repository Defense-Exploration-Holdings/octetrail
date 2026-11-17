# ATA over Ethernet

`octetrail.aoe`, `octetrail.aoeata` and `octetrail.aoecfg` parse and pack ATA
over Ethernet the way dpkt 1.9.8 does. The classes are [`Packet`](packet.md)
subclasses, as in dpkt, and [Ethernet](ethernet.md) decodes type 0x88A2 as
`AOE`.

```python
from octetrail import aoe, aoecfg, ethernet

frame = ethernet.Ethernet(
    src=b"\x02" * 6, dst=b"\xff" * 6, type=ethernet.ETH_TYPE_AOE,
    data=aoe.AOE(cmd=aoe.AOE_CMD_CFG, data=aoecfg.AOECFG(bufcnt=16)),
)
assert ethernet.Ethernet(bytes(frame)).aoe.aoecfg.bufcnt == 16
```

## AOE

`AOE` has `ver` and `fl` as bit fields of the first byte, then `err`, `maj`,
`min`, `cmd` and `tag`. Parsing decodes `data` with `AOE.get_cmd(cmd)` and sets
the attribute named after the class, `aoeata` or `aoecfg`. As in dpkt, an
unknown command or a body that does not parse stays bytes. `AOE.set_cmd` adds
a class. The table is filled from the `AOE_CMD_*` names when the package is
imported.

## Commands

`AOEATA` has `aflags`, `errfeat`, `scnt`, `cmdstat`, the six bytes `lba0` to
`lba5` and `res`. `AOECFG` has `bufcnt`, `fwver`, `scnt`, `aoeccmd` and `cslen`;
the configuration string is `data`.

## Errors

A header shorter than its fixed length raises `NeedData`. A bit field value
that does not fit raises `ValueError`, as in dpkt. There are no declared
differences.

## Verification

`tools/aoe_differential.py` parses 14 messages and Ethernet frames, including
dpkt's ATA vector, and builds and packs each class, comparing 24 observations
with dpkt 1.9.8. dpkt's own AoE tests also pass against OctetRail.

```sh
python3 tools/aoe_differential.py --oracle-196 /tmp/oracle-196/bin/python \
  --oracle-198 /tmp/oracle-198/bin/python --python /tmp/octetrail-wheel/bin/python
```
