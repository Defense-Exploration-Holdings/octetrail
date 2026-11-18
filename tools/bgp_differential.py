"""BGP messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same messages and parts of messages, including dpkt's
test vectors, every prefix of them and byte edits of them, builds messages
from keywords and packs them again. OctetRail must match dpkt 1.9.8 on every
observation except the declared ones; the keys where 1.9.6 differs are listed.
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


# dpkt's BGP test vectors, and the two from its regression tests.
VECTORS = {
    "bgp1": "ffffffffffffffffffffffffffffffff001304",
    "bgp2": (
        "ffffffffffffffffffffffffffffffff006302000000484001010040020a010201f401f40201febb"
        "400304c0a8000f40050400000064400600c00706febac0a8000ac0080cfebf000103160004015400"
        "fa800904c0a8000f800a04c0a800fa16c0a804"
    ),
    "bgp3": (
        "ffffffffffffffffffffffffffffffff007902000000624001010040020040050400000064c01008"
        "0002012c0000012cc080240000fde940010100400204020115b34005040000002c80090416050505"
        "800a0416050505900e001e0001800c00000000000000000c0404040060187701000001f4000001f4"
        "85"
    ),
    "bgp4": (
        "ffffffffffffffffffffffffffffffff002d010400ed005ac66e837d1002060104000100010202800002020200"
    ),
    "bgp5": (
        "ffffffffffffffffffffffffffffffff006002000000494001010040020040050400000064c01010"
        "030c000000000008000203e800000002900e00240019460401010102000119000101010102000205"
        "000003e8000004000000000002000002"
    ),
    "bgp6": (
        "ffffffffffffffffffffffffffffffff006f02000000584001010040020040050400000064c01010"
        "030c000000000008000203e800000002900e00330019460401010102000228000101010102000205"
        "000003e800000400000000000230ccaa029cd82920c0b40102000002000000"
    ),
    "bgp7": (
        "ffffffffffffffffffffffffffffffff005802000000414001010040020040050400000064c01010"
        "030c000000000008000203e800000002900e001c0019460401010102000311000101010102000200"
        "00000220c0b40102"
    ),
    "bgp8": (
        "ffffffffffffffffffffffffffffffff005f02000000484001010040020040050400000064c01010"
        "030c000000000008000203e800000002900e00230019460401010102000418000101010102000205"
        "000003e8000004000020c0b40102"
    ),
    "bgp9": (
        "ffffffffffffffffffffffffffffffff007b02000000644001010040020040050400000064c01010"
        "030c000000000008000203e800000002900e003f0019460401010102000234000101010102000205"
        "000003e800000400000000000230ccaa029cd82980c0b40102c0b40102c0b40102c0b40102000002"
        "000000"
    ),
    "mp_nlri_next_hop": (
        "ffffffffffffffffffffffffffffffff006c0200000055400101004002040201fde9800404000000"
        "00800e400002012020010db8000000000000000000000001fe80000000000000c0010bfffe7e0000"
        "004020010db8000100024020010db8000100014020010db800010000"
    ),
    "add_path_as_path": (
        "ffffffffffffffffffffffffffffffff005902000000304001010040020602010000fbff4003040a"
        "000e018004040000000040050400000064800a040a0022048009040a000f01000000012005050505"
        "0000000120c0a80105"
    ),
}

# Parts of messages, parsed with one class each: (class, hex).
PARTS = {
    "open_params": ("Open", "04fde900b4c0a8010110020601040001000102020200"),
    "open_auth": ("Open", "04fde900b4c0a801010a01080102030405060708"),
    "open_param_cut": ("Open", "04fde900b4c0a8010108020601"),
    "open_short": ("Open", "04fde9"),
    "param_cap": ("Param", "0206010400010001"),
    "param_auth": ("Param", "0103aabbcc"),
    "param_other": ("Param", "0702abcd"),
    "param_empty": ("Param", ""),
    "capability": ("Cap", "41040000fde9"),
    "capability_cut": ("Cap", "4110ab"),
    "authentication": ("Auth", "01aabb"),
    "update_empty": ("Update", "00000000"),
    "update_short": ("Update", "00"),
    "update_withdrawn_cut": ("Update", "0008180a00"),
    "update_attr_cut": ("Update", "00000010400101"),
    "update_ext_attr": ("Update", "0000000890080004000100020000"),
    "update_nlri_9": ("Update", "00000000180a0000000000012005050505"),
    "attr_origin": ("Attr", "40010100"),
    "attr_ext": ("Attr", "500100010002"),
    "attr_flags": ("Attr", "f0010001aa"),
    "attr_short": ("Attr", "40"),
    "attr_len_cut": ("Attr", "5002"),
    "attr_unknown": ("Attr", "c0ff03abcdef"),
    "attr_next_hop": ("Attr", "4003040a000001"),
    "attr_med": ("Attr", "80040400000064"),
    "attr_local_pref": ("Attr", "40050400000064"),
    "attr_atomic": ("Attr", "400600"),
    "attr_aggregator": ("Attr", "c00706fde90a000001"),
    "attr_aggregator4": ("Attr", "c0070800010000fde90a00"),
    "attr_originator": ("Attr", "8009040a000e01"),
    "attr_cluster": ("Attr", "800a080a0022040a002205"),
    "attr_communities": ("Attr", "c0080cffffff01ffffff0200010002"),
    "attr_mp_unreach_v6": ("Attr", "800f080002012020010db8"),
    "as_path_2": ("ASPath", "02020001fde9"),
    "as_path_4": ("ASPath", "0202000000010000fde9"),
    "as_path_set": ("ASPath", "0101fde90203000100020003"),
    "as_path_odd": ("ASPath", "0203000100020003"),
    "as_path_cut": ("ASPath", "0205fde9"),
    "as_path_empty": ("ASPath", ""),
    "segment": ("ASPathSeg", "0201fde9"),
    "segment4": ("ASPathSeg4", "02020000fde90001"),
    "segment4_cut": ("ASPathSeg4", "02020000fde9ab"),
    "communities_reserved": ("Comm", "ffffff01ffffff02ffffff03"),
    "communities_odd": ("Comm", "00010002ab"),
    "cluster_odd": ("Cluster", "0a0000010a"),
    "aggregator_short": ("Aggr", "fde9"),
    "mp_reach_v4": ("MPReach", "00010104c0a8010100180a0000"),
    "mp_reach_v6_two_hops": (
        "MPReach",
        "0002012020010db8000000000000000000000001fe80000000000000c0010bfffe7e0000004020010db800010002",
    ),
    "mp_reach_snpa": ("MPReach", "000001000104123400"),
    "mp_reach_snpa_cut": ("MPReach", "0000010002041234"),
    "mp_reach_evpn": (
        "MPReach",
        "00194604010101010002211111111111111111222222222222222222223333333300000000666600",
    ),
    "mp_unreach_v4": ("MPUnreach", "000101180a0000100a01"),
    "mp_unreach_generic": ("MPUnreach", "04d2010833"),
    "snpa": ("SNPA", "041234"),
    "snpa_odd": ("SNPA", "031234"),
    "snpa_cut": ("SNPA", "ff12"),
    "notification": ("Notif", "112233"),
    "notification_data": ("Notif", "0602aabbcc"),
    "keepalive": ("Keep", "11"),
    "route_refresh": ("RR", "11112233"),
    "route_refresh_short": ("RR", "1111"),
    "route_v4": ("R4", "0811"),
    "route_v4_full": ("R4", "200a000001"),
    "route_v4_long": ("R4", "ff0102030405"),
    "route_v4_empty": ("R4", ""),
    "route_v6": ("R6", "402001db8000000001"),
    "route_v6_long": ("R6", "ff" + "11" * 33),
    "route_extended": ("XR4", "000000012005050505"),
    "route_extended_short": ("XR4", "00000001"),
    "route_generic": ("RG", "0833"),
    "route_generic_long": ("RG", "ff" + "22" * 33),
    "evpn_mac_ip": (
        "EVPN",
        "022511111111111111112222222222222222222233333333300102030405062001020304666666",
    ),
    "evpn_ip6": (
        "EVPN",
        "023111111111111111112222222222222222222233333333000080" + "20010db8" + "00" * 12 + "6666",
    ),
    "evpn_test": ("EVPN", "021a111111111111111122222222222222222222333333330000006666"),
    "evpn_ad": ("EVPN", "0119111111111111111122222222222222222222333333336666"),
    "evpn_imet": ("EVPN", "030d11111111111111113333333320c0a80101"),
    "evpn_es": ("EVPN", "041711111111111111112222222222222222222220c0a80101"),
    "evpn_other": ("EVPN", "0503aabbcc"),
    "evpn_mac_cut": ("EVPN", "021611111111111111112222222222222222222233333333"),
    "evpn_ip_cut": ("EVPN", "02171111111111111111222222222222222222223333333300"),
    "evpn_empty": ("EVPN", ""),
}

CLASSES = {
    "Open": ("Open",),
    "Param": ("Open", "Parameter"),
    "Cap": ("Open", "Parameter", "Capability"),
    "Auth": ("Open", "Parameter", "Authentication"),
    "Update": ("Update",),
    "Attr": ("Update", "Attribute"),
    "ASPath": ("Update", "Attribute", "ASPath"),
    "ASPathSeg": ("Update", "Attribute", "ASPath", "ASPathSegment"),
    "ASPathSeg4": ("Update", "Attribute", "ASPath", "ASPathSegment4"),
    "Comm": ("Update", "Attribute", "Communities"),
    "Cluster": ("Update", "Attribute", "ClusterList"),
    "Aggr": ("Update", "Attribute", "Aggregator"),
    "MPReach": ("Update", "Attribute", "MPReachNLRI"),
    "MPUnreach": ("Update", "Attribute", "MPUnreachNLRI"),
    "SNPA": ("Update", "Attribute", "MPReachNLRI", "SNPA"),
    "Notif": ("Notification",),
    "Keep": ("Keepalive",),
    "RR": ("RouteRefresh",),
}
ROUTES = {
    "R4": "RouteIPV4",
    "R6": "RouteIPV6",
    "XR4": "ExtendedRouteIPV4",
    "RG": "RouteGeneric",
    "EVPN": "RouteEVPN",
}


def edits(raw):
    """Byte edits past the 19-byte header: a few fixed values at a stride."""
    found = {}
    for at in range(19, len(raw), 5):
        for value in (0x00, 0xFF, 0x10, (at * 37) & 0xFF):
            changed = bytearray(raw)
            changed[at] = value
            found["%04d_%02x" % (at, value)] = bytes(changed)
    return found


def cases():
    """(class, hex) by name."""
    found = {}
    for name, value in VECTORS.items():
        raw = bytes.fromhex(value)
        found[name] = ("BGP", value)
        for n in range(len(raw)):
            found["%s_prefix_%03d" % (name, n)] = ("BGP", raw[:n].hex())
        for key, changed in edits(raw).items():
            found["%s_edit_%s" % (name, key)] = ("BGP", changed.hex())
    for name, (kind, value) in PARTS.items():
        found["part_" + name] = (kind, value)
        raw = bytes.fromhex(value)
        for n in range(len(raw)):
            found["part_%s_prefix_%03d" % (name, n)] = (kind, raw[:n].hex())
    return found


def resolve(module, kind):
    if kind == "BGP":
        return module.BGP
    if kind in ROUTES:
        return getattr(module, ROUTES[kind])
    found = module.BGP
    for part in CLASSES[kind]:
        found = getattr(found, part)
    return found


def as_json(v):
    if isinstance(v, (bytes, bytearray)):
        return {"hex": bytes(v).hex()}
    if isinstance(v, (int, str, bool, type(None))):
        return v
    if isinstance(v, (list, tuple)):
        return [as_json(x) for x in v]
    if isinstance(v, dict):
        return {str(k): as_json(x) for k, x in v.items()}
    if hasattr(v, "__hdr__"):
        return snapshot(v)
    return {"repr": repr(v)}


def attempt(action):
    try:
        return as_json(action())
    except struct.error as error:
        # struct messages differ between Python versions, so only the class is kept.
        return {"error": type(error).__name__}
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}


FLAGS = ("optional", "transitive", "partial", "extended_length")


def snapshot(packet):
    found = {"class": type(packet).__name__, "repr": attempt(lambda: repr(packet))}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {k: as_json(v) for k, v in sorted(vars(packet).items()) if k[0] != "_"}
    for name in FLAGS:
        if hasattr(type(packet), name):
            found["fields"][name] = attempt(lambda n=name: getattr(packet, n))
    return found


def constructed(package):
    b = package.bgp
    vectors = {k: bytes.fromhex(v) for k, v in VECTORS.items()}

    def defaults():
        names = ["BGP", *CLASSES, *ROUTES]
        return {n: attempt(lambda n=n: snapshot(resolve(b, n)())) for n in names}

    def flags():
        found = []
        attribute = b.BGP.Update.Attribute(bytes.fromhex("40010100"))
        for name in FLAGS:
            for value in (1, 0, 3):
                setattr(attribute, name, value)
                found.append([name, value, attribute.flags, bytes(attribute).hex()])
        return found

    def edited():
        packet = b.BGP(vectors["bgp4"])
        update = packet.update
        update.attributes[0].origin.type = b.ORIGIN_INCOMPLETE
        update.announced.append(b.RouteIPV4(bytes.fromhex("180a0102")))
        update.withdrawn.append(b.RouteIPV4(bytes.fromhex("100a01")))
        return [bytes(packet).hex(), len(packet), len(update)]

    def built():
        found = []
        for make in (
            lambda: b.BGP(type=b.KEEPALIVE, data=b.BGP.Keepalive()),
            lambda: b.BGP(type=b.NOTIFICATION, data=b.BGP.Notification(code=6, subcode=2)),
            lambda: b.BGP(len=23, type=b.ROUTE_REFRESH, data=b.BGP.RouteRefresh(afi=1, safi=1)),
            lambda: b.BGP.Open(asn=65001, identifier=1, param_len=0),
            lambda: b.BGP.Update.Attribute(type=b.ORIGIN, data=b.BGP.Update.Attribute.Origin()),
            lambda: b.BGP.Update.Attribute.ASPath.ASPathSegment(type=2, len=1, data=b""),
            lambda: b.RouteIPV4(len=24, prefix=b"\x0a\x00\x01\x00"),
            lambda: b.RouteIPV6(len=32, prefix=bytes(16)),
            lambda: b.ExtendedRouteIPV4(path_id=7, len=8, prefix=b"\x0a\x00\x00\x00"),
            lambda: b.RouteEVPN(type=3, len=0, data=b""),
        ):
            found.append(attempt(lambda m=make: snapshot(m())))
        return found

    return {
        "defaults": attempt(defaults),
        "flags": attempt(flags),
        "edited": attempt(edited),
        "built": attempt(built),
        "repack": {k: attempt(lambda v=v: bytes(b.BGP(v)).hex()) for k, v in vectors.items()},
        "bytearray": attempt(lambda: snapshot(b.BGP(bytearray(vectors["bgp3"])))),
        "constants": attempt(
            lambda: sorted(
                (k, getattr(b, k))
                for k in dir(b)
                if k.isupper() and k[0] != "_" and isinstance(getattr(b, k), int)
            )
        ),
    }


def exercise(package):
    return {
        "cases": {
            name: attempt(lambda k=kind, w=w: snapshot(resolve(package.bgp, k)(bytes.fromhex(w))))
            for name, (kind, w) in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".bgp").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/bgp.py")).resolve(),
        "unverified bgp module origin",
    )
    package.bgp = importlib.import_module(module + ".bgp")
    return package


# dpkt reads an EVPN route's MAC and IP address length bytes with buf[0],
# which raises IndexError when the route ends first. These are the only
# IndexErrors dpkt's BGP module raises. OctetRail raises bgp.EVPNIndexError,
# which is both an UnpackError and an IndexError, with the same message.
INDEX_ERROR = '"error": "IndexError"'


def declared(found):
    """OctetRail's expected observation where it differs from dpkt on purpose."""
    text = json.dumps(found)
    if INDEX_ERROR not in text:
        return None
    return json.loads(text.replace(INDEX_ERROR, '"error": "EVPNIndexError"'))


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
        expected = {k: declared(found) or found for k, found in reference.items()}
        wrong = sorted(k for k in reference if report.get(k) != expected[k])
        C.require(not wrong, "bgp mismatch " + module + v + ": " + ", ".join(wrong))
    print(
        json.dumps(
            {
                "cases": len(cases()),
                "observations": len(reference),
                "providers": len(providers),
                "dpkt_196_differs_on": sorted(
                    k for k in reference if reports[0].get(k) != reference[k]
                ),
                "declared_differences": len([f for f in reference.values() if declared(f)]),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
