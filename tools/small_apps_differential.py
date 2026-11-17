"""Portmap, Rx, TNS, Yahoo Messenger, SMB and RFB messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

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

SMB_DPKT = "ff534d42a0000000000803c80000000000000000000000000008fa7a00085302"
TNS_DPKT = "00230000010000000134012c000008007fff4f98000000010001002200000000010158"
YHOO = (
    b"YMSG\x00\x0b\x00\x00" + (20).to_bytes(4, "little") + bytes(20) + b"nick".ljust(36, b"\0") * 2
)


def cases():
    """(target, hex) by name."""
    found = {
        "pmap_mapping": ("pmap.Pmap", bytes.fromhex("000186a000000002000000110000006f")),
        "pmap_short": ("pmap.Pmap", bytes(15)),
        "rx_data": (
            "rx.Rx",
            bytes.fromhex("12345678000000010000000200000003000000040104000200000000") + b"x",
        ),
        "rx_short": ("rx.Rx", bytes(27)),
        "tns_dpkt": ("tns.TNS", bytes.fromhex(TNS_DPKT)),
        "tns_with_tail": ("tns.TNS", bytes.fromhex(TNS_DPKT) + b"tail"),
        "tns_cut": ("tns.TNS", bytes.fromhex(TNS_DPKT)[:-10]),
        "tns_length_below_header": ("tns.TNS", b"\x00\x04\x00\x00\x01\x00\x00\x00rest"),
        "tns_short": ("tns.TNS", bytes(7)),
        "yhoo": ("yahoo.YHOO", YHOO + b"payload"),
        "yhoo_short": ("yahoo.YHOO", YHOO[:100]),
        "ymsg": ("yahoo.YMSG", b"YMSG\x00\x0b\x00\x00\x00\x05\x00\x01" + bytes(8) + b"hello"),
        "ymsg_short": ("yahoo.YMSG", b"YMSG"),
        "smb_dpkt": ("smb.SMB", bytes.fromhex(SMB_DPKT)),
        "smb_with_body": ("smb.SMB", bytes.fromhex(SMB_DPKT) + b"\x00\x00\x00"),
        "smb_short": ("smb.SMB", bytes.fromhex(SMB_DPKT)[:31]),
        "rfb_type": ("rfb.RFB", b"\x03\x01\x00\x00\x00\x00\x04\x00\x03\x00"),
        "rfb_empty": ("rfb.RFB", b""),
        "rfb_pixel_format": ("rfb.SetPixelFormat", bytes(3) + bytes(range(16))),
        "rfb_encodings": ("rfb.SetEncodings", b"\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x07"),
        "rfb_update_request": (
            "rfb.FramebufferUpdateRequest",
            b"\x01\x00\x00\x00\x00\x04\x00\x03\x00",
        ),
        "rfb_key": ("rfb.KeyEvent", b"\x01\x00\x00\x00\x00\xff\x0d"),
        "rfb_pointer": ("rfb.PointerEvent", b"\x01\x00\x10\x00\x20"),
        "rfb_update": ("rfb.FramebufferUpdate", b"\x00\x00\x01rect"),
        "rfb_colours": ("rfb.SetColourMapEntries", b"\x00\x00\x00\x00\x02rgb"),
        "rfb_cut_text": ("rfb.CutText", b"\x00\x00\x00\x00\x00\x00\x05hello"),
        "rfb_cut_text_short": ("rfb.CutText", b"\x00\x00\x00\x00"),
    }
    return {k: (t, v.hex()) for k, (t, v) in found.items()}


TARGETS = sorted({target for target, _ in cases().values()})


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
    found["attrs"] = {
        name: attempt(lambda name=name: repr(getattr(packet, name)))
        for name in ("data", "msg", "pid")
    }
    return found


def target(package, name):
    module, cls = name.split(".")
    return getattr(getattr(package, module), cls)


def constructed(package):
    smb_m = package.smb

    def smb_pid():
        packet = smb_m.SMB()
        packet.pid = 528416
        packet.uid = 2048
        parsed = smb_m.SMB(bytes.fromhex(SMB_DPKT))
        return [bytes(packet).hex(), packet.pid, parsed.pid, packet._pidhi, packet._pidlo]

    def tns_repacked():
        packet = package.tns.TNS(bytes.fromhex(TNS_DPKT) + b"tail")
        return [bytes(packet).hex(), len(packet), packet.msg.hex()]

    found = {
        "default_" + name: attempt(lambda name=name: snapshot(target(package, name)()))
        for name in TARGETS
    }
    found.update(
        {
            "smb_pid": attempt(smb_pid),
            "tns_repacked": attempt(tns_repacked),
            "yhoo_built": attempt(
                lambda: snapshot(
                    package.yahoo.YHOO(version=b"YMSG", nick1=b"a", nick2=b"b", service=6)
                )
            ),
            "rx_built": attempt(lambda: snapshot(package.rx.Rx(type=package.rx.ACK, data=b"x"))),
            "constants": attempt(
                lambda: [
                    package.pmap.PMAP_PROG,
                    package.pmap.PMAP_PROCDUMP,
                    package.rx.JUMBO_PACKET,
                    package.rx.SEC_RXKAD_ENC,
                    smb_m.SMB_FLAGS2_UNICODE,
                    smb_m.SMB_FLAGS_REPLY,
                    package.rfb.CLIENT_CUT_TEXT,
                    package.rfb.SERVER_CUT_TEXT,
                ]
            ),
        }
    )
    return found


def exercise(package):
    return {
        "cases": {
            name: attempt(lambda t=t, h=h: snapshot(target(package, t)(bytes.fromhex(h))))
            for name, (t, h) in cases().items()
        },
        "constructed": constructed(package),
    }


def _raised(action):
    try:
        action()
    except Exception as error:  # noqa: BLE001 - the error is the observation.
        return error
    return None


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for member in ("pmap", "rx", "tns", "yahoo", "smb", "rfb"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified Portmap, Rx, TNS, Yahoo, SMB or RFB module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# OctetRail matches 1.9.8 on every observation.
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
        C.require(
            not wrong,
            "Portmap, Rx, TNS, Yahoo, SMB or RFB mismatch " + module + v + ": " + ", ".join(wrong),
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
