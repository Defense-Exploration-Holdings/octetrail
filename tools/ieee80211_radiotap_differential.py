"""IEEE 802.11 and radiotap frames run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same frames, including dpkt's own test vectors, with
and without a frame check sequence, builds them from keywords and packs them
again. OctetRail must match dpkt
1.9.8 on every observation except the declared ones; the keys where 1.9.6
differs are listed.
"""

import argparse
import importlib
import importlib.metadata
import importlib.util
import json
import re
import subprocess
import sys

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 runs only the probes, which read no TOML.

    class tomllib:
        @staticmethod
        def loads(_text):
            raise SystemExit("reading pyproject.toml needs Python 3.11 or later")


from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "composition_fixture", Path(__file__).with_name("composition_differential.py")
)
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)

# dpkt's test vectors, by module, test and position.
DPKT = {
    "ieee80211.802211_ack.0": "d40000000012f0b61ca4ffffffff",
    "ieee80211.80211_beacon.0": (
        "80000000ffffffffffff0026cb186a300026cb186a30a0d0770932038f000000"
        "6600310400044341454e010882848b0c12961824030101050400010000070655"
        "5320010b1a0b0500006e00002a01022d1a6e181bffff00000000000000000000"
        "000000000000000000000030140100000fac040100000fac040100000fac0128"
        "0032043048606c36035163033d16010005000000000000000000000000000000"
        "00000000851e05008f000f00ff0359006373652d333931320000000000000000"
        "000000369606004096001400dd180050f2020101800003a4000027a400004243"
        "5e0062322f00dd06004096010104dd050040960305dd050040960b09dd080040"
        "961301003401dd050040961405"
    ),
    "ieee80211.80211_data.0": (
        "080920000026cb173d91001644b0aec60002b3d6263c807eaaaa030000000800"
        "450000280727400080061d398dd4373d3ff5d169c05f01bbb2d6ef23382b4f08"
        "50104204ac170000"
    ),
    "ieee80211.80211_data.1": (
        "aaaa030000000800450000280727400080061d398dd4373d3ff5d169c05f01bbb2d6ef23382b4f0850104204"
    ),
    "ieee80211.80211_data_qos.0": (
        "88013a010026cb1744f00023dfc9c0930026cb1744f0207b0000aaaa03000000"
        "888e010000740202007419800000006a16030100650100006103014b4ca77e27"
        "616f027b3c7239e37bd74359917faa224751b6889f8590875ad11320e0070000"
        "68bda413b0d5827ec7fbe7ccab6e5d5a5150d445c5a16553adb5885b001a002f"
        "000500040035000a000900030008003300390016001500140100ffffffff"
    ),
    "ieee80211.80211_data_qos.1": (
        "aaaa03000000888e010000740202007419800000006a16030100650100006103"
        "014b4ca77e27616f027b3c7239e37bd74359917faa224751b6889f8590875ad1"
        "1320e007000068bda413b0d5827ec7fbe7ccab6e5d5a5150d445c5a16553adb5"
        "885b001a002f000500040035000a000900030008003300390016001500140100"
    ),
    "ieee80211.bug.0": "88412c000026cb1744f0001e52971411001f6de81800d00700006f00002000000000",
    "ieee80211.data_ds.0": "08030000010b850000000026cb187350010b8500000000890026cb187350",
    "ieee80211.data_ds.1": "884150010026cb1748c100242ce7fe8affffffffffff80a00000091a002000000000",
    "ieee80211.data_ds.2": "08020201000244ac2770001f33397544001f3339754490a4",
    "ieee80211.compressed_block_ack.0": "9400000034c059d63f62b4750e4683c1055080ee0300000000000000a2e49845",
    "ieee80211.action_block_ack_request.0": (
        "d0003a01002314365230b4750e4683c1b4750e4683c1701403000d0210000040290650339e"
    ),
    "ieee80211.action_block_ack_response.0": (
        "d0003c00b4750e4683c1002314365230b4750e4683c1d06803010d0000021088139fc00b75"
    ),
    "ieee80211.action_block_ack_delete.0": "d0002c0000c14106130d6cb2aeaede806cb2aeaede80a052030200080100745d0ac6",
    "ieee80211.ieee80211_unpack.0": "400000000000000000000000000000000000000000000000",
    "ieee80211.ieee80211_unpack.1": "900000000000000000000000000000000000000000000000",
    "ieee80211.ieee80211_unpack.2": "0c000000",
    "ieee80211.blockack_unpack.0": "00000000000000000000000000000000",
    "ieee80211.action_unpack.0": "0100",
    "ieee80211.beacon_unpack.0": "b971fa455202000064001104",
    "radiotap.radiotap_1.0": "000000186e48000000026c09a000a8810200000000000000",
    "radiotap.radiotap_2.0": (
        "000030002f4000a0200800a0200800a020080000000000000884bdac28000000"
        "10028509a000a5000000a1009f01a102"
    ),
    "radiotap.radiotap_2.1": "2f4000a0200800a0200800a020080000",
    "radiotap.fcs.0": "00001a002f480000348f710900000000100c8509c000cc010000",
    "radiotap.radiotap_3.0": (
        "00002000670804008484662500000000220cd6a001000000400100003c142411"
        "08020000ffffffffffff06037f07a0160019e3d35352008eaaaa030000000806"
        "00010800060400010019e3d35352a9fef7000000000000004f673238"
    ),
    "radiotap.radiotap_properties.0": "000000180000000000000000000000000000000000000000",
    "radiotap.radiotap_unpack_fcs.0": (
        "000018006e48000011026c09a000a8810200000000000000d40000000012f0b61ca4ffffffff"
    ),
}

MAC = bytes(range(1, 7))


def mgmt(subtype, body):
    return bytes([subtype << 4, 0, 0, 0]) + MAC * 3 + b"\x10\x00" + body


def radiotap(present, fields, frame=b""):
    header_len = 4 + len(present) + len(fields)
    return bytes([0, 0]) + header_len.to_bytes(2, "little") + present + fields + frame


ACK = b"\xd4\x00\x00\x00" + MAC


def cases():
    """(target, hex) by name."""
    found = {
        "probe_req": ("ieee", mgmt(4, b"\x00\x04note\x01\x02\x82\x84\xdd\x01x\x00\x00\x00\x00")),
        "probe_req_tail_four": ("ieee", mgmt(4, b"\x00\x01a\xde\xad\xbe\xef")),
        "probe_req_ie_cut": ("ieee", mgmt(4, b"\x00\x09abcde")),
        "probe_req_tim_short": ("ieee", mgmt(4, b"\x05\x01\x00\x00\x00\x00\x00")),
        "probe_req_known_ies": (
            "ieee",
            mgmt(
                4,
                b"\x02\x05\x00\x10\x01\x02\x03\x03\x01\x06\x04\x06\x01\x02\x00\x03\x00\x04"
                b"\x05\x05\x00\x01\x00\x00\xff\x06\x02\x00\x01\x2d\x01\x00\x00\x00\x00\x00",
            ),
        ),
        "atim": ("ieee", mgmt(9, b"rest")),
        "auth": ("ieee", mgmt(11, b"\x00\x00\x01\x00\x00\x00\x00\x00\xdd\x00")),
        "action_unknown": ("ieee", mgmt(13, b"\x07\x00")),
        "mgmt_unknown_subtype": ("ieee", mgmt(6, b"")),
        "ctl_ps_poll": ("ieee", b"\xa4\x00\x00\x00" + MAC * 2),
        "ack": ("ieee", ACK),
        "ack_short": ("ieee", ACK[:7]),
        "data_null": ("ieee", b"\x48\x01\x00\x00" + MAC * 3 + b"\x00\x00"),
        "data_inter_ds": ("ieee", b"\x08\x03\x00\x00" + MAC * 3 + b"\x00\x00" + MAC + b"payload"),
        "header_only": ("ieee", b"\x00\x00\x00\x00"),
        "empty": ("ieee", b""),
        "fcs_frame": ("ieee_fcs", ACK + b"\x01\x02\x03\x04"),
        "fcs_short": ("ieee_fcs", b"\xd4\x00\x00\x00\x01\x02"),
        "rt_ack": ("radiotap", radiotap(b"\x00\x00\x00\x00", b"", ACK)),
        "rt_fields": (
            "radiotap",
            radiotap(
                b"\x2f\x40\x00\x00",
                bytes(4)
                + (1).to_bytes(8, "little")
                + b"\x10\x02"
                + b"\x6c\x09\xa0\x00\xd8\x00\x00",
                ACK + b"\x00\x00\x00\x00",
            ),
        ),
        # The same fields at their aligned offsets: TSFT needs no padding
        # after the 8-byte header, and RxFlags needs one byte.
        "rt_fields_aligned": (
            "radiotap",
            radiotap(
                b"\x2f\x40\x00\x00",
                (1).to_bytes(8, "little") + b"\x10\x02" + b"\x6c\x09\xa0\x00\xd8\x00\x00\x00",
                ACK + b"\x00\x00\x00\x00",
            ),
        ),
        "rt_ext": (
            "radiotap",
            radiotap(b"\x02\x00\x00\x80\x00\x00\x00\x00", b"\x00", ACK),
        ),
        "rt_ext_short": ("radiotap", bytes([0, 0, 12, 0]) + b"\x00\x00\x00\x80\x00\x00"),
        "rt_present_short": ("radiotap", bytes([0, 0, 8, 0, 0, 0])),
        "rt_no_frame": ("radiotap", radiotap(b"\x04\x00\x00\x00", b"\x02")),
        "rt_bad_frame": ("radiotap", radiotap(b"\x00\x00\x00\x00", b"", b"\x00\x60\x00\x00")),
        "rt_chanplus": (
            "radiotap",
            radiotap(b"\x00\x00\x04\x00", b"\x00\x00\x00\x00\x01\x00\x00\x00\x6c\x09\x01\x14", ACK),
        ),
        "rt_header_short": ("radiotap", b"\x00\x00\x08"),
    }
    for name, wire in DPKT.items():
        raw = bytes.fromhex(wire)
        found["dpkt." + name] = ("radiotap" if name.startswith("radiotap") else "ieee", raw)
        if name.startswith("ieee80211"):
            found["dpkt_fcs." + name] = ("ieee_fcs", raw)
    return {k: (t, v.hex()) for k, (t, v) in found.items()}


def as_json(v):
    if isinstance(v, (bytes, bytearray)):
        return {"hex": bytes(v).hex()}
    if isinstance(v, (int, str, bool, type(None))):
        return v
    if isinstance(v, (list, tuple)):
        return [as_json(x) for x in v]
    if isinstance(v, dict):
        return {str(k): as_json(x) for k, x in v.items()}
    return {"repr": repr(v)}


def attempt(action):
    try:
        return as_json(action())
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}


def shape(value, depth=0):
    if depth > 6:
        return repr(value)
    if hasattr(value, "__hdr__"):
        return snapshot(value, depth + 1)
    if isinstance(value, list):
        return [shape(v, depth + 1) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return {type(value).__name__: bytes(value).hex()}
    if isinstance(value, (int, str, type(None))):
        return value
    if hasattr(value, "__dict__"):
        return {
            "object": type(value).__name__,
            **{k: shape(v, depth + 1) for k, v in sorted(vars(value).items())},
        }
    return repr(value)


def plain_repr(value):
    """repr() with the module path and address of plain objects removed."""
    return re.sub(r"<[\w.]+\.(\w+) object at 0x[0-9a-f]+>", r"<\1>", repr(value))


def snapshot(packet, depth=0):
    found = {"class": type(packet).__name__, "repr": attempt(lambda: plain_repr(packet))}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {k: shape(v, depth) for k, v in sorted(vars(packet).items()) if k[0] != "_"}
    return found


def parse(package, target, raw):
    if target == "radiotap":
        return package.radiotap.Radiotap(raw)
    if target == "ieee_fcs":
        return package.ieee80211.IEEE80211(raw, fcs=True)
    return package.ieee80211.IEEE80211(raw)


def constructed(package):
    W, R = package.ieee80211, package.radiotap

    def bits():
        frame = W.IEEE80211(framectl=0)
        found = []
        for name, value in (
            ("type", 2),
            ("subtype", 8),
            ("to_ds", 1),
            ("from_ds", 1),
            ("wep", 1),
            ("order", 1),
            ("retry", 1),
        ):
            setattr(frame, name, value)
            found.append([name, frame.framectl, getattr(frame, name)])
        return found

    def rt_bits():
        rt = R.Radiotap(bytes.fromhex(DPKT["radiotap.radiotap_1.0"]))
        found = [rt.present_flags.hex()]
        for name in (
            "tsft_present",
            "flags_present",
            "rate_present",
            "channel_present",
            "chanplus_present",
            "rx_flags_present",
        ):
            setattr(rt, name, 1)
            found.append([name, getattr(rt, name), rt.present_flags.hex()])
            setattr(rt, name, 0)
            found.append(rt.present_flags.hex())
        return found

    def flags_fcs():
        f = R.Radiotap.Flags(val=0x01)
        f.fcs = 1
        found = [f.val, f.fcs]
        f.fcs = 0
        return found + [f.val, f.fcs]

    def block_ack_bits():
        b = W.IEEE80211.BlockAck(ctl=0)
        found = []
        for name, value in (("compressed", 1), ("ack_policy", 1), ("multi_tid", 1), ("tid", 9)):
            setattr(b, name, value)
            found.append([name, b.ctl, getattr(b, name)])
        return found

    return {
        "default_frame": attempt(lambda: snapshot(W.IEEE80211())),
        "default_radiotap": attempt(lambda: [repr(R.Radiotap()), bytes(R.Radiotap()).hex()]),
        "default_ie": attempt(lambda: snapshot(W.IEEE80211.IE())),
        "default_mgmt": attempt(lambda: snapshot(W.IEEE80211.MGMT_Frame())),
        "frame_bits": attempt(bits),
        "radiotap_bits": attempt(rt_bits),
        "flags_fcs": attempt(flags_fcs),
        "block_ack_bits": attempt(block_ack_bits),
        "capability": attempt(lambda: shape(W.IEEE80211.Capability(0xFFFF))),
        "fragment_numbers": attempt(
            lambda: [
                (d.fragment_number, d.sequence_number)
                for d in (W.IEEE80211.Data(frag_seq=v) for v in (0x0000, 0x1234, 0xFFFF))
            ]
        ),
        "ntole": attempt(
            lambda: [W.IEEE80211(bytes.fromhex(DPKT["ieee80211.80211_beacon.0"])).beacon.interval]
        ),
        "bytearray": attempt(
            lambda: snapshot(W.IEEE80211(bytearray(bytes.fromhex(cases()["probe_req"][1]))))
        ),
        "rt_bytearray": attempt(
            lambda: snapshot(R.Radiotap(bytearray(bytes.fromhex(cases()["rt_fields"][1]))))
        ),
        "rt_error_classes": attempt(
            lambda: sorted(
                c.__name__
                for c in type(
                    _raised(lambda: R.Radiotap(bytes.fromhex(cases()["rt_ext_short"][1])))
                ).__mro__
                if c.__module__ == "builtins"
            )
        ),
        "constants": attempt(
            lambda: sorted(
                (k, getattr(W, k)) for k in dir(W) if k.isupper() and isinstance(getattr(W, k), int)
            )
        ),
        "constant_lists": attempt(lambda: [W.FRAMES_WITH_CAPABILITY, W.FCS_LENGTH]),
    }


def _raised(action):
    try:
        action()
    except Exception as error:  # noqa: BLE001 - the error is the observation.
        return error
    return None


def exercise(package):
    return {
        "cases": {
            name: attempt(lambda t=t, h=h: snapshot(parse(package, t, bytes.fromhex(h))))
            for name, (t, h) in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for member in ("ieee80211", "radiotap"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified IEEE 802.11 or radiotap module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. Radiotap bytes
# that end before a present word's extension bit raise IndexError in dpkt;
# OctetRail raises radiotap.PresentFlagsError, which is both an UnpackError and
# an IndexError, with the same message.
_PRESENT = {"error": "PresentFlagsError", "message": "bytearray index out of range"}
DECLARED = {
    "cases.rt_ext_short": _PRESENT,
    "cases.rt_present_short": _PRESENT,
}


def flatten(report):
    return {
        section + "." + key: found
        for section, entries in report.items()
        for key, found in entries.items()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--module", choices=("dpkt", "octetrail"))
    parser.add_argument("--version")
    parser.add_argument("--oracle-196")
    parser.add_argument("--oracle-198")
    parser.add_argument("--python", action="append", default=[])
    args = parser.parse_args()
    if args.probe:
        print(json.dumps(exercise(provenance(args.module, args.version))))
        return
    C.require(
        args.oracle_196 and args.oracle_198 and args.python,
        "both pins and an installed provider are required",
    )
    version = tomllib.loads((C.ROOT / "pyproject.toml").read_text())["project"]["version"]
    providers = [
        (args.oracle_196, "dpkt", "1.9.6"),
        (args.oracle_198, "dpkt", "1.9.8"),
        *((p, "octetrail", version) for p in args.python),
    ]
    reports = []
    for python, module, v in providers:
        result = subprocess.run(
            [python, "-B", "-I", "-O", __file__, "--probe", "--module", module, "--version", v],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        reports.append(flatten(json.loads(result.stdout)))
    reference = reports[1]
    for (_, module, v), report in zip(providers[2:], reports[2:], strict=True):
        wrong = sorted(k for k in reference if report.get(k) != DECLARED.get(k, reference[k]))
        C.require(
            not wrong, "IEEE 802.11 or radiotap mismatch " + module + v + ": " + ", ".join(wrong)
        )
    print(
        json.dumps(
            {
                "cases": len(cases()),
                "observations": len(reference),
                "providers": len(providers),
                "dpkt_196_differs_on": sorted(
                    k for k in reference if reports[0].get(k) != reference[k]
                ),
                "declared_differences": sorted(DECLARED),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
