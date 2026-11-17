"""NTP, RIP, TFTP and HSRP messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

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
NTP_DPKT = (
    "240204ef0000008400003327c1020402c890ec1122ae07e5c890f9d9c07e8ccd"
    "c890f9d9dac5b078c890f9d9dac68a93"
)
RIP_AUTH = "ffff00020123456789abcdef0123456789abcdef"
RIP_RTE = "0002000001020300ffffff000000000000000001"


def rip(entries, cmd=2, version=2):
    return bytes([cmd, version, 0, 0]) + b"".join(bytes.fromhex(e) for e in entries)


def hsrp(state=0x10, auth=b"cisco\0\0\0", vip=b"\x0a\x00\x00\x01"):
    return bytes([0, 0, state, 3, 10, 100, 1, 0]) + auth + vip


def cases():
    """(target, hex) by name."""
    found = {
        "ntp_dpkt": ("ntp", bytes.fromhex(NTP_DPKT)),
        "ntp_with_extension": ("ntp", bytes.fromhex(NTP_DPKT) + b"\x00\x01\x00\x08ext!"),
        "ntp_client": ("ntp", b"\xe3" + bytes(47)),
        "ntp_short": ("ntp", bytes.fromhex(NTP_DPKT)[:47]),
        "rip_response": ("rip", rip([RIP_RTE, RIP_RTE])),
        "rip_auth_first": ("rip", rip([RIP_AUTH, RIP_RTE])),
        "rip_two_auth": ("rip", rip([RIP_AUTH, RIP_RTE, RIP_AUTH.replace("01", "ff")])),
        "rip_header_only": ("rip", rip([], cmd=1)),
        "rip_entry_cut": ("rip", rip([RIP_RTE]) + b"\x00\x02\x00"),
        "rip_short": ("rip", b"\x02\x02"),
        "tftp_rrq": ("tftp", b"\x00\x01rfc1350.txt\x00octet\x00"),
        "tftp_wrq_extra": ("tftp", b"\x00\x02name\x00netascii\x00blksize\x00512\x00"),
        "tftp_rrq_one_nul": ("tftp", b"\x00\x01name\x00"),
        "tftp_rrq_no_nul": ("tftp", b"\x00\x01name"),
        "tftp_rrq_empty": ("tftp", b"\x00\x01"),
        "tftp_data": ("tftp", b"\x00\x03\x00\x01\n\nNetwork Working Group"),
        "tftp_ack": ("tftp", b"\x00\x04\x00\x07"),
        "tftp_data_short": ("tftp", b"\x00\x03\x00"),
        "tftp_err": ("tftp", b"\x00\x05\x00\x07no such user\x00trailing"),
        "tftp_err_no_nul": ("tftp", b"\x00\x05\x00\x01missing"),
        "tftp_err_short": ("tftp", b"\x00\x05"),
        "tftp_other": ("tftp", b"\x00\x06\xab\xcd\xef"),
        "tftp_short": ("tftp", b"\x00"),
        "hsrp_active": ("hsrp", hsrp()),
        "hsrp_with_tail": ("hsrp", hsrp(state=8) + b"tail"),
        "hsrp_short": ("hsrp", hsrp()[:19]),
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
    found["attrs"] = {
        name: attempt(lambda name=name: repr(getattr(packet, name)))
        for name in ("data", "auth", "rtes", "filename", "mode", "block", "errcode", "errmsg")
    }
    return found


def constructed(package):
    ntp_m, rip_m, tftp_m, hsrp_m = package.ntp, package.rip, package.tftp, package.hsrp

    def ntp_bits():
        message = ntp_m.NTP(bytes.fromhex(NTP_DPKT))
        found = [message.li, message.v, message.mode]
        message.li, message.v, message.mode = 3, 3, ntp_m.CLIENT
        found += [message.flags, bytes(message).hex()]
        return found

    def rip_built():
        message = rip_m.RIP(cmd=2)
        message.rtes = [rip_m.RTE(addr=0x0A000000, subnet=0xFF000000)]
        message.auth = rip_m.Auth(auth=b"secret")
        return [bytes(message).hex(), len(message), repr(message)]

    def tftp_built():
        found = []
        for keywords in (
            dict(opcode=1, filename=b"f", mode=b"octet"),
            dict(opcode=3, block=9, data=b"chunk"),
            dict(opcode=4, block=10),
            dict(opcode=5, errcode=1, errmsg=b"not found"),
            dict(opcode=9, data=b"x"),
        ):
            packet = tftp_m.TFTP(**keywords)
            found.append([bytes(packet).hex(), len(packet)])
        return found

    return {
        "default_ntp": attempt(lambda: snapshot(ntp_m.NTP())),
        "default_rip": attempt(lambda: snapshot(rip_m.RIP())),
        "default_rte": attempt(lambda: snapshot(rip_m.RTE())),
        "default_auth": attempt(lambda: snapshot(rip_m.Auth())),
        "default_tftp": attempt(lambda: snapshot(tftp_m.TFTP())),
        "default_hsrp": attempt(lambda: snapshot(hsrp_m.HSRP())),
        "ntp_bits": attempt(ntp_bits),
        "ntp_built": attempt(
            lambda: bytes(
                ntp_m.NTP(
                    v=4,
                    mode=3,
                    id=b"\0" * 4,
                    update_time=b"\0" * 8,
                    originate_time=b"\0" * 8,
                    receive_time=b"\0" * 8,
                    transmit_time=b"\1" * 8,
                )
            ).hex()
        ),
        "rip_built": attempt(rip_built),
        "rip_bytearray": attempt(
            lambda: [repr(r.data) for r in rip_m.RIP(bytearray(rip([RIP_RTE]))).rtes]
        ),
        "tftp_built": attempt(tftp_built),
        "tftp_missing_field": attempt(lambda: bytes(tftp_m.TFTP(opcode=3))),
        "tftp_request_error_classes": attempt(
            lambda: [
                c.__name__
                for c in type(_raised(lambda: tftp_m.TFTP(b"\x00\x01name"))).__mro__
                if c.__module__ == "builtins"
            ]
        ),
        "hsrp_built": attempt(
            lambda: snapshot(hsrp_m.HSRP(state=hsrp_m.ACTIVE, vip=b"\x0a\0\0\1"))
        ),
        "constants": attempt(
            lambda: [
                ntp_m.SERVER,
                ntp_m.PRIVATE == 7,
                ntp_m.ALARM_CONDITION,
                rip_m.REQUEST,
                rip_m.RESPONSE,
                tftp_m.OP_ERR,
                tftp_m.ENOUSER,
                hsrp_m.RESIGN,
                hsrp_m.ACTIVE,
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
        "ntp": package.ntp.NTP,
        "rip": package.rip.RIP,
        "tftp": package.tftp.TFTP,
        "hsrp": package.hsrp.HSRP,
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
    for member in ("ntp", "rip", "tftp", "hsrp"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified NTP, RIP, TFTP or HSRP module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. A read or write
# request without a NUL after the file name raises IndexError in dpkt; OctetRail
# raises tftp.RequestError, which is both an UnpackError and an IndexError.
_REQUEST_ERROR = {"error": "RequestError", "message": "list index out of range"}
DECLARED = {
    "cases.tftp_rrq_empty": _REQUEST_ERROR,
    "cases.tftp_rrq_no_nul": _REQUEST_ERROR,
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
            not wrong, "NTP, RIP, TFTP or HSRP mismatch " + module + v + ": " + ", ".join(wrong)
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
