"""CDP, DTP and EDP packets run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same packets, alone and inside Ethernet LLC/SNAP
frames, including dpkt's own test vectors, builds them from keywords and packs
them again. OctetRail must match dpkt 1.9.8 on every observation except the
declared ones; the keys where 1.9.6 differs are listed.
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

# dpkt's test vectors: a CDP packet, an Ethernet LLC/SNAP frame with eight
# CDP entries, a DTP packet and an EDP packet that is mostly zeros.
CDP_DPKT = "02b4df9300010009636973636f00020011000000010101cc0004c0a80167"
ETH_CDP_DPKT = (
    "01000cccccccc402326b00000154aaaa0300000c200002b42c42000100065232000500ff"
    "436973636f20494f5320536f6674776172652c203337303020536f667477617265202843"
    "333734352d414456454e54455250524953454b395f534e412d4d292c2056657273696f6e"
    "2031322e3428323564292c2052454c4541534520534f4654574152452028666331290a54"
    "6563686e6963616c20537570706f72743a20687474703a2f2f7777772e636973636f2e63"
    "6f6d2f74656368737570706f72740a436f707972696768742028632920313938362d3230"
    "313020627920436973636f2053797374656d732c20496e632e0a436f6d70696c65642057"
    "65642031382d4175672d31302030383a31382062792070726f645f72656c5f7465616d00"
    "06000e436973636f203337343500020011000000010101cc00040a000002000300134661"
    "737445746865726e6574302f30000400080000002900090004000b000500"
)
DTP_DPKT = "04000100021234"
EDP_DPKT = (
    "0100013c9e76001b00000800272d90ed990200240000000000000000000000000f020207000000000000000000000000000000009901010445584f532d32"
    + "00" * 250
    + "99000004"
)


def tlv(kind, length, value=b""):
    return struct.pack(">HH", kind, length) + value


def cdp(entries=b"", version=2, ttl=180, checksum=0):
    return struct.pack(">BBH", version, ttl, checksum) + entries


def snap(kind, body, oui=b"\x00\x00\x0c"):
    payload = b"\xaa\xaa\x03" + oui + struct.pack(">H", kind) + body
    return b"\x01\x00\x0c\xcc\xcc\xcc" + b"\x02" * 6 + struct.pack(">H", len(payload)) + payload


def cases():
    """(target, hex) by name."""
    found = {
        "cdp_dpkt": ("cdp", bytes.fromhex(CDP_DPKT)),
        "cdp_header_only": ("cdp", cdp()),
        "cdp_two_entries": ("cdp", cdp(tlv(1, 9, b"cisco") + tlv(3, 7, b"Fa0"))),
        "cdp_zero_length": ("cdp", cdp(tlv(1, 9, b"cisco") + tlv(6, 0, b"rest of it"))),
        "cdp_length_two_last": ("cdp", cdp(tlv(5, 2))),
        "cdp_length_two_more": ("cdp", cdp(tlv(5, 2, b"abcdef"))),
        "cdp_length_beyond": ("cdp", cdp(tlv(5, 60, b"short"))),
        "cdp_address_entry": (
            "cdp",
            cdp(tlv(2, 17, b"\x00\x00\x00\x01\x01\x01\xcc\x00\x04\x0a\x00\x00\x01")),
        ),
        "cdp_address_zero_length": ("cdp", cdp(tlv(2, 0, b"\x00\x00\x00\x02tail"))),
        "cdp_address_short": ("cdp", cdp(tlv(2, 8, b"\x00\x00"))),
        "cdp_address_length_small": ("cdp", cdp(tlv(2, 5, b"\x00\x00\x00\x01xyz"))),
        "cdp_entry_short": ("cdp", cdp(tlv(1, 5, b"a") + b"\x00\x03")),
        "cdp_short": ("cdp", b"\x02\xb4\x00"),
        "cdp_empty": ("cdp", b""),
        "dtp_dpkt": ("dtp", bytes.fromhex(DTP_DPKT)),
        "dtp_entries": (
            "dtp",
            b"\x01" + tlv(1, 4, b"VTP1") + tlv(4, 6, b"\x00\x11\x22\x33\x44\x55"),
        ),
        "dtp_value_cut": ("dtp", b"\x01" + tlv(2, 9, b"ab")),
        "dtp_entry_short": ("dtp", b"\x01" + tlv(1, 1, b"x") + b"\x00\x02"),
        "dtp_version_only": ("dtp", b"\x01"),
        "dtp_empty": ("dtp", b""),
        "edp_dpkt": ("edp", bytes.fromhex(EDP_DPKT)),
        "edp_short": ("edp", b"\x01\x00\x01"),
        "eth_cdp_dpkt": ("eth", bytes.fromhex(ETH_CDP_DPKT)),
        "eth_cdp_short_entry": ("eth", snap(0x2000, cdp(tlv(1, 5, b"a") + b"\x00"))),
        "eth_dtp": ("eth", snap(0x2004, b"\x01" + tlv(1, 4, b"VTP1"))),
        "eth_dtp_short_entry": ("eth", snap(0x2004, b"\x01\x00\x01")),
        "eth_edp": ("eth", snap(0x00BB, bytes.fromhex(EDP_DPKT)[:40], oui=b"\x00\xe0\x2b")),
    }
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


def snapshot(packet):
    found = {"class": type(packet).__name__, "repr": repr(packet)}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {k: repr(v) for k, v in sorted(vars(packet).items()) if k[0] != "_"}
    found["attr_data"] = attempt(lambda: repr(packet.data))
    data = getattr(packet, "data", None)
    if data is not None and not isinstance(data, (bytes, bytearray, str, list)):
        found["data"] = snapshot(data)
    return found


def constructed(package):
    cdp_m, dtp_m, edp_m, eth_m = package.cdp, package.dtp, package.edp, package.ethernet
    CDP = cdp_m.CDP

    def built_like_dpkt():
        address = CDP.TLV_Addresses(data=CDP.Address(data=b"\xc0\xa8\x01\x67"))
        name = CDP.TLV(type=cdp_m.CDP_DEVID, data=b"cisco")
        packet = CDP(data=name.pack() + address.pack())
        return [bytes(packet).hex(), packet.sum, repr(name), repr(address)]

    def entries():
        no_len = CDP.TLV(bytes.fromhex("00000000abcd"))
        with_len = CDP.TLV(bytes.fromhex("00000006abcdef"))
        short_len = CDP.TLV(bytes.fromhex("00000002abcdef"))
        found = [no_len.data_len(), bytes(no_len).hex(), no_len.len]
        found += [with_len.data_len(), bytes(with_len).hex()]
        found += [short_len.data_len(), repr(short_len.data), bytes(short_len).hex()]
        return found

    def address():
        entry = CDP.Address(bytes.fromhex("0011223333") + b"x" * 4)
        return [entry.data_len(), repr(entry), len(entry), bytes(entry).hex()]

    def dtp_built():
        packet = dtp_m.DTP(v=3, data=[(1, b"VTP1"), (4, b"")])
        return [bytes(packet).hex(), len(packet), repr(packet)]

    def tables():
        return [
            attempt(lambda t=t: eth_m.Ethernet.get_type(t).__name__)
            for t in (0x2000, 0x2004, 0x00BB)
        ]

    return {
        "default_cdp": attempt(lambda: snapshot(CDP())),
        "default_dtp": attempt(lambda: snapshot(dtp_m.DTP())),
        "default_edp": attempt(lambda: snapshot(edp_m.EDP())),
        "cdp_sum_kept": attempt(lambda: bytes(CDP(sum=0x1234, data=b"x")).hex()),
        "cdp_bytearray": attempt(lambda: snapshot(CDP(bytearray(cdp(tlv(1, 5, b"a")))))),
        "built_like_dpkt": attempt(built_like_dpkt),
        "entries": attempt(entries),
        "address": attempt(address),
        "address_entry_short": attempt(
            lambda: snapshot(CDP.TLV_Addresses(b"\x00\x02\x00\x00\x00"))
        ),
        "entry_too_long": attempt(lambda: bytes(CDP.TLV(data=b"x" * 70000))),
        "dtp_built": attempt(dtp_built),
        "dtp_bytearray": attempt(lambda: dtp_m.DTP(bytearray(b"\x01" + tlv(1, 2, b"ab"))).data),
        "edp_sum_kept": attempt(lambda: bytes(edp_m.EDP(sum=0x1234, mac=b"\x02" * 6)).hex()),
        "ethernet_types": attempt(tables),
        "constants": attempt(
            lambda: (
                [
                    getattr(cdp_m, n)
                    for n in sorted(dir(cdp_m))
                    if n.startswith("CDP_") and isinstance(getattr(cdp_m, n), int)
                ]
                + [dtp_m.TRUNK_NAME, dtp_m.MAC_ADDR]
            )
        ),
        "tlv_types": attempt(lambda: {k: v.__name__ for k, v in CDP.tlv_types.items()}),
    }


def exercise(package):
    targets = {
        "cdp": package.cdp.CDP,
        "dtp": package.dtp.DTP,
        "edp": package.edp.EDP,
        "eth": package.ethernet.Ethernet,
    }
    return {
        "cases": {
            name: attempt(lambda t=t, h=h: snapshot(targets[t](bytes.fromhex(h))))
            for name, (t, h) in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for member in ("cdp", "dtp", "edp", "ethernet"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified CDP, DTP or EDP module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose.
# OctetRail fixes dpkt here (DTP packs its version byte). These keys are not compared;
# tests/python checks the fixed results.
FIXED = {
    "cases.dtp_dpkt",
    "cases.dtp_entries",
    "cases.dtp_value_cut",
    "cases.dtp_version_only",
    "cases.eth_dtp",
    "constructed.default_dtp",
    "constructed.dtp_built",
}

DECLARED = {}


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
        wrong = sorted(
            k
            for k in reference
            if k not in FIXED and report.get(k) != DECLARED.get(k, reference[k])
        )
        C.require(not wrong, "CDP, DTP or EDP mismatch " + module + v + ": " + ", ".join(wrong))
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
                "fixed_dpkt_bugs": sorted(FIXED),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
