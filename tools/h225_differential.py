"""H.225.0 call signaling run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same messages, including prefixes of dpkt's SETUP
test vector, builds messages and information elements from keywords and packs
them again. OctetRail must match dpkt 1.9.8 on every observation; the keys
where 1.9.6 differs are listed.
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


# dpkt's SETUP test vector.
DPKT_SETUP = (
    "030004110802542b0504038893a5280e4a6f6e204f6265726865696465007e03f00520b8060008914a000401"
    "400c004a006f006e0020004f0062006500720068006500690064006522c00900003d06656b69676100001432"
    "2e302e3220284f50414c2076322e322e322900000001401500740063007000240068003300320033002e0076"
    "006f0078006700720061007400690061002e006f00720067004287232c06b8006a8b1d0cb706db119eca0010"
    "a4896d6a00c51d800407000a00017a753011005e881d0cb706db119eca0010a4896d6a822b0e304000000604"
    "01004c100900003d0f53706565782062733420576964653680111c00010098a02641138a0098a02641138b26"
    "0000640c100900003d0f537065657820627334205769646536800b0d00010098a02641138b002a4000000604"
    "01004c100900003d09694c42432d31336b3380111c00010098a02641138a0098a02641138b200000650c1009"
    "00003d09694c42432d31336b33800b0d00010098a02641138b0020400000060401004e0c0300830080111c00"
    "010098a02641138a0098a02641138b160000660e0c03008300800b0d00010098a02641138b004b4000000604"
    "01004c10b500534c2a020000000000400100004001020008000000000031000100401f000059060000410000"
    "0002004001000080111c00010098a02641138a0098a02641138b410000670c10b500534c2a02000000000040"
    "0100004001020008000000000031000100401f00005906000041000000020040010000800b0d00010098a026"
    "41138b0032400000060401004c100900003d11537065657820627334204e6172726f773380111c00010098a0"
    "2641138a0098a02641138b280000680c100900003d11537065657820627334204e6172726f7733800b0d0001"
    "0098a02641138b001d400000060401004c601d80111c00010098a02641138a0098a02641138b130000690c60"
    "1d800b0d00010098a02641138b001d400000060401004c201d80111c00010098a02641138a0098a02641138b"
    "1300006a0c201d800b0d00010098a02641138b00010001000100010081030280f80270010600088175000b80"
    "138001f4000100000100000100000cc0010001800b80000020200900003d0f53706565782062733420576964"
    "653680000120200900003d09694c42432d31336b3380000224180300e6008000032020b500534c2a02000000"
    "0000400100004001020008000000000031000100401f00005906000041000000020040010000800004202009"
    "00003d11537065657820627334204e6172726f773380000520c0ef8000062040ef80000708e0035100800100"
    "80000808d003510080010080000983015080000a83011080000b830140008001030600000001000200030004"
    "00050006010007000800000901000a000b0701003280a6ff4c02800180"
)


def message(body, ref=b"\x00\x01", msg_type=5, proto=8, v=3, rsvd=0, length=None):
    payload = bytes([proto, len(ref)]) + ref + bytes([msg_type]) + body
    length = 4 + len(payload) if length is None else length
    return bytes([v, rsvd]) + length.to_bytes(2, "big") + payload


def cases():
    """Hex by name."""
    setup = bytes.fromhex(DPKT_SETUP)
    found = {
        "dpkt_setup": setup,
        "tpkt_version0": bytes.fromhex("00000000"),
        "tpkt_rsvd": bytes.fromhex("03ff0000"),
        "tpkt_len": bytes.fromhex("0300ffff"),
        "tpkt_short": bytes.fromhex("0300"),
        "tpkt_len_small": message(b"\x80", length=0),
        "tpkt_only": bytes.fromhex("03000004"),
        "header_only": bytes.fromhex("030000060802"),
        "no_type": message(b"")[:-1],
        "ref_long": message(b"", ref=b"")[:4] + b"\x08\x09\x00\x01",
        "ref_empty": message(b"\x80", ref=b""),
        "no_elements": message(b""),
        "single_octet": message(b"\xa1\xa0\x90"),
        "one_byte_length": message(b"\x04\x03\x88\x93\xa5"),
        "length_past_end": message(b"\x28\x0eJon"),
        "length_cut": message(b"\xa1\x28"),
        "uuie": message(b"\x7e\x00\x03abc"),
        "uuie_cut": message(b"\x7e\x00"),
        "uuie_past_end": message(b"\x7e\xff\xffab"),
        "zero_length": message(b"\x28\x00\x6c\x00"),
        "proto_other": message(b"\x80", proto=0x09),
        "mixed": message(b"\x04\x03\x88\x93\xa5\xa1\x7e\x00\x02hi\x28\x01x\x80"),
        "many_single": message(b"\xa1" * 300),
    }
    for n in list(range(4, 64)) + [100, 500, 1000, 1040]:
        found["setup_prefix_%04d" % n] = setup[:n]
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
    except struct.error as error:
        # struct messages differ between Python versions, so only the class is kept.
        return {"error": type(error).__name__}
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}


def snapshot(packet):
    found = {"class": type(packet).__name__, "repr": repr(packet)}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {
        k: snapshot(v) if hasattr(v, "__hdr__") else repr(v)
        for k, v in sorted(vars(packet).items())
        if k[0] != "_"
    }
    for name in ("tpkt", "ref_val", "type", "len"):
        if hasattr(packet, name) and name not in found["fields"]:
            value = getattr(packet, name)
            found["fields"][name] = snapshot(value) if hasattr(value, "__hdr__") else repr(value)
    data = getattr(packet, "data", None)
    if isinstance(data, list):
        found["data"] = [snapshot(ie) for ie in data]
    else:
        found["data"] = repr(data)
    return found


def constructed(package):
    h = package.h225
    raw = bytes.fromhex(cases()["mixed"])

    def edited():
        packet = h.H225(raw)
        packet.type = h.CONNECT
        packet.data[0].data = b"\x01"
        packet.data.append(h.H225.IE(type=h.DISPLAY, len=2, data=b"ok"))
        return [bytes(packet).hex(), len(packet)]

    def elements():
        found = []
        for keywords in (
            {},
            {"type": 0x80},
            {"type": h.DISPLAY, "len": 3, "data": b"abc"},
            {"type": h.USER_TO_USER, "len": 2, "data": b"hi"},
            {"type": h.USER_TO_USER, "len": 70000, "data": b""},
            {"type": h.DISPLAY, "len": 300, "data": b""},
        ):
            found.append(attempt(lambda k=keywords: snapshot(h.H225.IE(**k))))
        return found

    return {
        "default": attempt(lambda: snapshot(h.H225())),
        "keywords": attempt(lambda: snapshot(h.H225(proto=9, ref_len=1))),
        "elements": attempt(elements),
        "ie_parse": [
            attempt(lambda b=b: snapshot(h.H225.IE(b)))
            for b in (b"\x80", b"\x28\x02ab", b"\x28", b"\x7e\x00", b"\x7e\x00\x01xyz", b"")
        ],
        "edited": attempt(edited),
        "repack": attempt(lambda: bytes(h.H225(bytes.fromhex(DPKT_SETUP))).hex()),
        "bytearray": attempt(lambda: snapshot(h.H225(bytearray(raw)))),
        "constants": attempt(
            lambda: sorted(
                (k, getattr(h, k)) for k in dir(h) if k.isupper() and isinstance(getattr(h, k), int)
            )
        ),
    }


def exercise(package):
    return {
        "cases": {
            name: attempt(lambda w=w: snapshot(package.h225.H225(bytes.fromhex(w))))
            for name, w in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".h225").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/h225.py")).resolve(),
        "unverified h225 module origin",
    )
    package.h225 = importlib.import_module(module + ".h225")
    return package


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
        wrong = sorted(k for k in reference if report.get(k) != DECLARED.get(k, reference[k]))
        C.require(not wrong, "h225 mismatch " + module + v + ": " + ", ".join(wrong))
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
