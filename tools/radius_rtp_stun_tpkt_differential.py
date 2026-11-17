"""RADIUS, RTP, STUN and TPKT messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same messages, including dpkt's own test vectors,
builds them from keywords and packs them again. OctetRail must match dpkt
1.9.8 on every observation except the declared ones; the keys where 1.9.6
differs are listed.
"""

import argparse
import importlib
import importlib.metadata
import importlib.util
import json
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

# dpkt's test vectors.
STUN_RESPONSE = "0101000c2112a442534f70436969354a6663317a000100080001112233445566"
STUN_PADDED = (
    "000100542112a4423559536e427170567761394f00060017704c795a48523a47"
    "774c334148426f7675624c7643716e00802a0008188b104c697bf65b00250000"
    "002400046e001eff00080014602bc7fc0d1063aac5381ccb96a97308739a960c"
    "80280004d162ea65"
)
RTP_DPKT = (
    "80084d01000100e0343ffa3453535356535d5657d5d6d1dedfd3d9dadfdcdfd8"
    "ddd4ddd9d1d6dcdadeddc7c1dfdfdadbddddc4d95557d45044445b444f4c4740"
    "4c47595b585d56565356d5d55455d6d6d4d1d1d0d1d5ddd655d4d6d1d4d6d7d7"
    "d5d4d0d7d1d4d2dcd6dcdfdcddd2dedcd0dddcd0d6d6d655545557575650505c"
    "5c525d5d5f5e5d5e5250525654575555d4d755d555555555555457545555d5d5"
    "d7d6d7d1d1d3d2d3d2d2d3d3"
)
RADIUS_HEADER = "01341234" + "0123456789abcdef" * 2


def stun(kind, attrs, xid=b"\x21\x12\xa4\x42" + bytes(range(12))):
    body = b""
    for t, v in attrs:
        body += t.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v
        body += bytes(-len(v) % 4)
    return kind.to_bytes(2, "big") + len(body).to_bytes(2, "big") + xid + body


def rtp(first=0x80, pt=8, csrc=b"", payload=b"audio"):
    return bytes([first, pt]) + bytes.fromhex("4d01000100e0343ffa34") + csrc + payload


def cases():
    """(target, hex) by name."""
    radius = bytes.fromhex(RADIUS_HEADER)
    found = {
        "radius_dpkt": ("radius", radius + b"\x01\x06user"),
        "radius_two": ("radius", radius + b"\x01\x06user\x02\x0apassword"),
        "radius_zero_length": ("radius", radius + b"\x01\x06user\x00\x00tail"),
        "radius_length_one": ("radius", radius + b"\x05\x01abc"),
        "radius_long_length": ("radius", radius + b"\x01\x06user\x1a\xffvendor"),
        "radius_odd_tail": ("radius", radius + b"\x01\x06user\x02"),
        "radius_one_byte": ("radius", radius + b"\x01"),
        "radius_header_only": ("radius", radius),
        "radius_short": ("radius", radius[:19]),
        "radius_attrs_dpkt": ("radius_attrs", b"\x01\x06user\x00\x00"),
        "radius_attrs_two": ("radius_attrs", b"\x01\x06user\x02\x0apassword"),
        "radius_attrs_odd": ("radius_attrs", b"\x01\x03a\x05"),
        "radius_attrs_empty": ("radius_attrs", b""),
        "rtp_dpkt": ("rtp", bytes.fromhex(RTP_DPKT)),
        "rtp_csrc": ("rtp", rtp(first=0x82, csrc=bytes(range(8)))),
        "rtp_csrc_cut": ("rtp", rtp(first=0x8F, csrc=b"\x01\x02\x03", payload=b"")),
        "rtp_marker": ("rtp", rtp(first=0xB0, pt=0xE0)),
        "rtp_header_only": ("rtp", rtp(payload=b"")),
        "rtp_short": ("rtp", rtp()[:11]),
        "stun_dpkt_response": ("stun", bytes.fromhex(STUN_RESPONSE)),
        "stun_dpkt_padded": ("stun", bytes.fromhex(STUN_PADDED)),
        "stun_built": (
            "stun",
            stun(0x0111, [(0x0009, b"\x00\x00\x04\x01bad"), (0x000A, b"\x00\x01")]),
        ),
        "stun_short": ("stun", bytes.fromhex(STUN_RESPONSE)[:19]),
        "stun_attrs_dpkt": ("stun_attrs", bytes.fromhex(STUN_RESPONSE)[20:]),
        "stun_attrs_padded": ("stun_attrs", bytes.fromhex(STUN_PADDED)[20:]),
        "stun_attrs_value_cut": ("stun_attrs", b"\x00\x06\x00\x10short"),
        "stun_attrs_header_cut": ("stun_attrs", b"\x00\x01\x00\x00\x00\x02"),
        "stun_attrs_empty": ("stun_attrs", b""),
        "stun_tlv": ("stun_tlv", b"\x00\x06\x00\x03abc\x00rest"),
        "stun_tlv_short": ("stun_tlv", b"\x00\x06"),
        "tpkt_cotp": ("tpkt", b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x01\x00"),
        "tpkt_short": ("tpkt", b"\x03\x00\x00"),
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
    if not hasattr(packet, "__hdr__"):
        return {"value": as_json(packet)}
    found = {"class": type(packet).__name__, "repr": repr(packet)}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {k: repr(v) for k, v in sorted(vars(packet).items()) if k[0] != "_"}
    found["attrs"] = {
        name: attempt(lambda name=name: repr(getattr(packet, name)))
        for name in ("data", "attrs", "csrc", "version", "p", "x", "cc", "m", "pt")
        if hasattr(type(packet), name) or name in ("data",)
    }
    return found


def constructed(package):
    radius_m, rtp_m, stun_m, tpkt_m = package.radius, package.rtp, package.stun, package.tpkt

    def rtp_bits():
        found = []
        packet = rtp_m.RTP()
        for name in ("version", "p", "x", "cc", "m", "pt"):
            found.append(getattr(packet, name))
            setattr(packet, name, 1)
            found.append([getattr(packet, name), packet._type])
        packet.csrc = b"\x00\x00\x00\x07"
        packet.data = b"payload"
        found += [bytes(packet).hex(), len(packet)]
        return found

    def radius_built():
        packet = radius_m.RADIUS(code=radius_m.RADIUS_ACCESS_REQUEST, id=7, auth=b"a" * 16)
        packet.data = b"\x01\x06user"
        return [bytes(packet).hex(), len(packet), repr(packet.attrs)]

    def bytearray_attrs():
        return [
            repr(radius_m.parse_attrs(bytearray(b"\x01\x06user"))),
            repr(stun_m.parse_attrs(bytearray(bytes.fromhex(STUN_RESPONSE)[20:]))),
            repr(rtp_m.RTP(bytearray(rtp(first=0x81, csrc=b"abcd"))).csrc),
            repr(radius_m.RADIUS(bytearray(bytes.fromhex(RADIUS_HEADER) + b"\x01\x04ab")).attrs),
        ]

    def error_classes(action):
        error = _raised(action)
        return [c.__name__ for c in type(error).__mro__ if c.__module__ in ("builtins", "struct")]

    return {
        "default_radius": attempt(lambda: snapshot(radius_m.RADIUS())),
        "default_rtp": attempt(lambda: snapshot(rtp_m.RTP())),
        "default_stun": attempt(lambda: snapshot(stun_m.STUN())),
        "default_tpkt": attempt(lambda: snapshot(tpkt_m.TPKT())),
        "rtp_bits": attempt(rtp_bits),
        "radius_built": attempt(radius_built),
        "stun_built": attempt(
            lambda: snapshot(stun_m.STUN(type=1, xid=b"\x21\x12\xa4\x42" + bytes(12)))
        ),
        "tpkt_built": attempt(lambda: snapshot(tpkt_m.TPKT(len=11, data=b"cotp"))),
        "bytearray_attrs": attempt(bytearray_attrs),
        "radius_bytearray_odd": attempt(lambda: radius_m.parse_attrs(bytearray(b"\x01\x03a\x05"))),
        "radius_error_classes": attempt(
            lambda: error_classes(lambda: radius_m.parse_attrs(b"\x01"))
        ),
        "stun_error_classes": attempt(lambda: error_classes(lambda: stun_m.parse_attrs(b"\x01"))),
        "radius_attr_default": attempt(lambda: radius_m.RADIUS.attrs),
        "rtp_csrc_default": attempt(lambda: rtp_m.RTP.csrc),
        "constants": attempt(
            lambda: [
                radius_m.RADIUS_ACCESS_CHALLENGE,
                radius_m.RADIUS_VENDOR_SPECIFIC,
                radius_m.RADIUS_LOGIN_LAT_PORT,
                rtp_m.VERSION,
                rtp_m._CC_MASK,
                rtp_m._PT_SHIFT,
                stun_m.SHARED_SECRET_ERROR_RESPONSE == 274,
                stun_m.REFLECTED_FROM,
                stun_m.MESSAGE_INTEGRITY,
            ]
        ),
    }


def _raised(action):
    try:
        action()
    except Exception as error:  # noqa: BLE001 - the error is the observation.
        return error
    return None


def exercise(package):
    targets = {
        "radius": package.radius.RADIUS,
        "radius_attrs": package.radius.parse_attrs,
        "rtp": package.rtp.RTP,
        "stun": package.stun.STUN,
        "stun_attrs": package.stun.parse_attrs,
        "stun_tlv": package.stun.tlv,
        "tpkt": package.tpkt.TPKT,
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
    for member in ("radius", "rtp", "stun", "tpkt"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified RADIUS, RTP, STUN or TPKT module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. One byte left at
# the end of the RADIUS attributes raises IndexError in dpkt, and a cut-off STUN
# attribute header raises struct.error. OctetRail raises ShortAttributeError,
# which is also an UnpackError, with dpkt's message.
_RADIUS = {"error": "ShortAttributeError", "message": "index out of range"}
_STUN = {"error": "ShortAttributeError", "message": "unpack requires a buffer of 4 bytes"}
DECLARED = {
    "cases.radius_attrs_odd": _RADIUS,
    "cases.radius_odd_tail": _RADIUS,
    "cases.radius_one_byte": _RADIUS,
    "cases.stun_attrs_header_cut": _STUN,
    "cases.stun_tlv_short": _STUN,
    "constructed.radius_bytearray_odd": {
        "error": "ShortAttributeError",
        "message": "bytearray index out of range",
    },
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
            not wrong, "RADIUS, RTP, STUN or TPKT mismatch " + module + v + ": " + ", ".join(wrong)
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
