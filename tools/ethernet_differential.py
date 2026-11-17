"""Ethernet, LLC, IPX and STP frames run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same Ethernet II, 802.1Q, MPLS, ISL, IEEE 802.3 LLC
and Novell frames, including dpkt's own test vectors, builds frames from
keywords and packs them again. OctetRail must match dpkt 1.9.8 on every
observation except the declared ones; the keys where 1.9.6 differs are listed.
Payloads are IPv6 or bytes, since IPv4 parity is a separate module.
"""

import argparse
import importlib
import importlib.metadata
import importlib.util
import json
import struct
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

# dpkt's test_isl_eth_llc_stp, test_eth_2mpls_ecw_eth_llc_stp and
# test_eth_8023_llc_trailer vectors.
ISL_STP = (
    "01000c0000030002fd2cb8970000aaaa03000000029b000000000180c20000000002fd2cb8980026"
    "424203000000000080000002fd2cb8830000000080000002fd2cb88380260000140002000f000000"
    "00000000000041c675d6"
)
MPLS_ECW_STP = (
    "cc010d5c0010cc000d5c00108847000120fe000101ff000000000180c2000000cc040d5cf0000026"
    "42420300000000008000cc040d5c0000000000008000cc040d5c000080010000140002000f000000"
    "000000000000"
)
LLC_TRAILER = (
    "0180c2000000780cf0b4d8910027424203000002023c00012c3311f239c1000000028001780cf0b4"
    "d8bc80aa0100140002000f0000000000000000004db981205c1e5fba3aa547fa018e5203"
)

DST = bytes.fromhex("02aabbccddee")
SRC = bytes.fromhex("021122334455")
ISL = b"\x01\x00\x0c\x00\x00\x03" + SRC + b"\x00\x26" + bytes(range(1, 13))


def header(kind, dst=DST, src=SRC):
    return dst + src + struct.pack(">H", kind)


def ip6(body=b"note", nxt=59):
    return struct.pack(">IHBB16s16s", 0x60000000, len(body), nxt, 64, bytes(16), bytes(16)) + body


def tag(vid, kind, pri=0):
    return struct.pack(">HH", (pri << 13) | vid, kind)


def label(value, bottom, ttl=64):
    return struct.pack(">I", (value << 12) | (bottom << 8) | ttl)


def stp_body():
    return bytes(2) + b"\x00\x00\x00" + bytes(8) + bytes(4) + bytes(8) + b"\x80\x01" + bytes(8)


def cases():
    """Hex frames by name."""
    llc_stp = b"\x42\x42\x03" + stp_body()
    snap = b"\xaa\xaa\x03\x00\x00\x00\x86\xdd" + ip6()
    found = {
        "ii_opaque": header(0x88B5) + b"octetrail",
        "ii_ip6": header(0x86DD) + ip6(),
        "ii_short": header(0x88B5)[:13],
        "empty": b"",
        "vlan_ip6": header(0x8100) + tag(5, 0x86DD, 3) + ip6(),
        "vlan_opaque": header(0x8100) + tag(5, 0x88B5) + b"note",
        "vlan_short": header(0x8100) + b"\x00\x05",
        "qinq_ip6": header(0x88A8) + tag(7, 0x8100) + tag(9, 0x86DD) + ip6(),
        "qinq_three_tags": header(0x9100) + tag(1, 0x8100) + tag(2, 0x8100) + tag(3, 0x86DD),
        "vlan_type_zero": header(0x8100) + tag(5, 0) + b"note",
        "mpls_ip6": header(0x8847) + label(16, 0) + label(17, 1) + ip6(),
        "mpls_opaque_short": header(0x8848) + label(16, 1) + b"\x99note",
        "mpls_teb": header(0x8847) + label(16, 1) + header(0x86DD) + ip6(),
        "mpls_ecw_teb": header(0x8847) + label(16, 1) + bytes(4) + header(0x88B5) + b"x",
        "mpls_no_bottom": header(0x8847) + label(16, 0) + label(17, 0),
        "mpls_nothing_after": header(0x8847) + label(16, 1),
        "mpls_dpkt_ecw_stp": bytes.fromhex(MPLS_ECW_STP),
        "isl_dpkt_stp": bytes.fromhex(ISL_STP),
        "isl_twice": ISL + ISL + header(0x86DD) + ip6(),
        "isl_short_tag": ISL[:20],
        "isl_short_inner": ISL + bytes(5),
        "novell_ipx": header(40) + b"\xff\xff" + struct.pack(">HBB", 31, 0, 17) + bytes(26) + b"x",
        "novell_short": header(40) + b"\xff\xff\x00\x1e",
        "unknown_type": header(0) + b"note",
        "llc_stp": header(len(llc_stp)) + llc_stp,
        "llc_stp_short": header(10) + b"\x42\x42\x03" + bytes(7),
        "llc_snap_ip6": header(len(snap)) + snap,
        "llc_snap_unknown": header(13) + b"\xaa\xaa\x03\x00\x00\x0c\x20\x00hello",
        "llc_snap_short": header(6) + b"\xaa\xaa\x03\x00\x00\x00",
        "llc_ipx": header(33)
        + b"\xe0\xe0\x03"
        + struct.pack(">HHBB", 0xFFFF, 30, 0, 0)
        + bytes(24),
        "llc_ipx_short": header(5) + b"\x10\x10\x03\x00\x00",
        "llc_ip_short": header(4) + b"\x06\x06\x03\x45",
        "llc_header_short": header(2) + b"\x01\x02",
        "llc_other_sap": header(7) + b"\xf0\xf0\x03note",
        "llc_padding_fcs": header(7) + b"\xf0\xf0\x03note" + bytes(39) + b"\x12\x34\x56\x78",
        "llc_padding_fcs_trailer": header(7) + b"\xf0\xf0\x03note" + bytes(39) + bytes(4) + b"tr",
        "llc_nonzero_padding": header(7) + b"\xf0\xf0\x03note" + b"\x01" * 39 + bytes(4),
        "llc_fcs_only": header(50) + b"\xf0\xf0\x03" + bytes(47) + b"\xde\xad\xbe\xef",
        "llc_short_tail": header(7) + b"\xf0\xf0\x03note" + b"\x01\x02",
        "llc_length_past_end": header(1500) + b"\xf0\xf0\x03note",
        "llc_dpkt_trailer": bytes.fromhex(LLC_TRAILER),
    }
    return {k: v.hex() for k, v in found.items()}


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


def snapshot(packet):
    found = {"class": type(packet).__name__, "repr": repr(packet)}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {k: repr(v) for k, v in sorted(vars(packet).items()) if k[0] != "_"}
    data = getattr(packet, "data", None)
    if data is not None and not isinstance(data, (bytes, str)):
        found["data"] = snapshot(data)
    return found


def constructed(package):
    eth, llc, stp, ipx, ip6m = (
        package.ethernet,
        package.llc,
        package.stp,
        package.ipx,
        package.ip6,
    )
    r = {}
    for name, cls in (
        ("ethernet", eth.Ethernet),
        ("vlan", eth.VLANtag8021Q),
        ("isl", eth.VLANtagISL),
        ("mpls", eth.MPLSlabel),
        ("llc", llc.LLC),
        ("stp", stp.STP),
        ("ipx", ipx.IPX),
    ):
        r["default_" + name] = attempt(lambda cls=cls: snapshot(cls()))
    r["keyword_ip6"] = attempt(lambda: snapshot(eth.Ethernet(dst=DST, src=SRC, data=ip6m.IP6())))
    r["keyword_bytes_decoded"] = attempt(lambda: snapshot(eth.Ethernet(type=0x86DD, data=ip6())))
    r["keyword_vlan_not_walked"] = attempt(
        lambda: snapshot(eth.Ethernet(type=0x8100, data=tag(5, 0x86DD) + ip6()))
    )
    r["keyword_llc_stp"] = attempt(
        lambda: snapshot(
            eth.Ethernet(dst=DST, src=SRC, data=llc.LLC(dsap=0x42, ssap=0x42, data=stp.STP()))
        )
    )

    def computed_fcs():
        frame = eth.Ethernet(data=llc.LLC(dsap=0xF0, ssap=0xF0, data=b"note"))
        frame.fcs = 0
        frame.padding = bytes(39)
        return snapshot(frame)

    r["computed_fcs"] = attempt(computed_fcs)

    def computed_isl_fcs():
        frame = eth.Ethernet(bytes.fromhex(ISL_STP))
        frame.fcs = None
        return snapshot(frame)

    r["computed_isl_fcs"] = attempt(computed_isl_fcs)
    r["snap_type_from_data"] = attempt(lambda: snapshot(llc.LLC(data=ip6m.IP6())))

    def vlan_types():
        frame = eth.Ethernet(bytes.fromhex(cases()["qinq_ip6"]))
        frame.type = 0x1234
        frame.data = b"raw"
        return snapshot(frame)

    r["vlan_types_repacked"] = attempt(vlan_types)

    def three_tags():
        frame = eth.Ethernet(bytes.fromhex(cases()["vlan_ip6"]))
        frame.vlan_tags += [eth.VLANtag8021Q(), eth.VLANtag8021Q()]
        return bytes(frame)

    r["three_tags"] = attempt(three_tags)

    def mpls_relabel():
        frame = eth.Ethernet(bytes.fromhex(cases()["mpls_ip6"]))
        frame.mpls_labels.append(eth.MPLSlabel(val=99))
        frame.type = 0x0800
        return snapshot(frame)

    r["mpls_relabel"] = attempt(mpls_relabel)
    r["type_table"] = attempt(
        lambda: [
            eth.Ethernet.get_type(0x86DD).__name__,
            eth.Ethernet.get_type(0x8137).__name__,
            eth.Ethernet.get_type(0x6558).__name__,
            eth.Ethernet.get_type_rev(eth.Ethernet),
        ]
    )
    r["bit_fields"] = attempt(
        lambda: [
            eth.VLANtag8021Q(b"\xff\xff\x08\x00").as_tuple(),
            eth.MPLSlabel(b"\xff\xff\xff\xff").as_tuple(),
            repr(eth.VLANtagISL(ISL)),
        ]
    )
    r["stp_timers"] = attempt(
        lambda: (lambda s: [s.age, s.max_age, s.hello, s.fd])(stp.STP(bytes(range(35))))
    )
    r["mac_to_str"] = attempt(lambda: eth.mac_to_str(DST))
    r["constants"] = [
        eth.ETH_MTU,
        eth.ETH_MIN,
        eth.ETH_TYPE_PROFINET,
        sorted(eth._ETH_TYPES_QINQ),
        ipx.IPX_HDR_LEN,
    ]
    return r


def exercise(package):
    eth = package.ethernet
    return {
        "cases": {
            name: attempt(lambda h=h: snapshot(eth.Ethernet(bytes.fromhex(h))))
            for name, h in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for member in ("ethernet", "llc", "stp", "ipx"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified Ethernet module origin",
        )
    for member in ("llc", "stp", "ipx"):
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose: parse errors stay
# UnpackError. An MPLS stack with nothing after it raises MPLSIndexError, an
# UnpackError and IndexError, where dpkt raises IndexError.
DECLARED = {
    "cases.mpls_nothing_after": {"error": "MPLSIndexError", "message": "index out of range"},
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
        C.require(not wrong, "Ethernet mismatch " + module + v + ": " + ", ".join(wrong))
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
