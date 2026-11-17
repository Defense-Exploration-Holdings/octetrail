"""NetBIOS messages and name helpers run by dpkt 1.9.6, 1.9.8 and OctetRail.

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

NAME = "EOGFHEECEJEPFDCACACACACACACACAAA"  # "NETBIOS" padded, service 0x00


def encoded(name=NAME):
    return bytes([len(name)]) + name.encode() + b"\0"


def ns(counts, body, op=0x8500, id_=0x1234):
    return struct.pack("!6H", id_, op, *counts) + body


def rr(kind, rdata, owner=b"\xc0\x0c", ttl=300):
    return owner + struct.pack("!HHIH", kind, 1, ttl, len(rdata)) + rdata


NBSTAT = b"\x02" + b"ABCDEFGHIJKLMNO\x2f\x01\x02" + b"PQRSTUVWXYZABCD\x43\x03\x04" + bytes(6)


def cases():
    """(target, hex) by name."""
    question = encoded() + b"\x00\x20\x00\x01"
    found = {
        "ns_query": ("ns", ns([1, 0, 0, 0], question, op=0x0110)),
        "ns_positive": ("ns", ns([1, 1, 0, 0], question + rr(0x20, b"\x60\x00\x0a\x00\x00\x01"))),
        "ns_a_record": ("ns", ns([1, 1, 0, 0], question + rr(1, b"\x0a\x00\x00\x02"))),
        "ns_nbstat": ("ns", ns([1, 1, 0, 0], question + rr(0x21, NBSTAT))),
        "ns_nbstat_no_names": ("ns", ns([1, 1, 0, 0], question + rr(0x21, b"\x00"))),
        "ns_nbstat_cut": ("ns", ns([1, 1, 0, 0], question + rr(0x21, NBSTAT[:25]))),
        "ns_nbstat_empty": ("ns", ns([1, 1, 0, 0], question + rr(0x21, b""))),
        "ns_other_type": ("ns", ns([0, 1, 0, 0], rr(0x63, b"opaque", owner=encoded()))),
        "ns_null_record": ("ns", ns([0, 0, 0, 1], rr(0x0A, b"\x01\x02", owner=encoded()))),
        "ns_name_cut": ("ns", ns([1, 0, 0, 0], encoded()[:10])),
        "ns_short": ("ns", b"\x12\x34\x85\x00"),
        "session_message": ("session", b"\x00\x00\x00\x04\xffSMB"),
        "session_request": ("session", b"\x81\x00\x00\x44" + encoded() * 2),
        "session_short": ("session", b"\x85\x00"),
        "datagram_direct": (
            "datagram",
            b"\x11\x02\x80\x01\x0a\x00\x00\x01\x00\x8a\x00\x05\x00\x00" + b"hello",
        ),
        "datagram_short": ("datagram", b"\x11\x02\x80\x01\x0a\x00"),
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
    records = [r for section in ("an", "ns", "ar") for r in getattr(packet, section, [])]
    found["records"] = [
        {
            "class": type(r).__name__,
            "repr": repr(r),
            "ip": attempt(lambda r=r: r.ip),
            "nodenames": attempt(lambda r=r: r.nodenames),
        }
        for r in records
    ]
    found["questions"] = [type(q).__name__ for q in getattr(packet, "qd", [])]
    return found


def constructed(package):
    nb = package.netbios

    def built_query():
        message = nb.NS(
            id=7, op=0x0110, qd=[nb.NS.Q(name=nb.encode_name("WORKGROUP"), type=nb.NS_NB)]
        )
        return [bytes(message).hex(), repr(message)]

    def built_answer():
        message = nb.NS(
            id=7,
            qd=[nb.NS.Q(name=NAME, type=nb.NS_NB)],
            an=[nb.NS.RR(name=NAME, type=nb.NS_NB, rdata=b"\x60\x00\x0a\x00\x00\x01")],
        )
        return [bytes(message).hex(), len(message)]

    def unpack_rdata_direct():
        record = nb.NS.RR(type=nb.NS_NBSTAT, rdata=NBSTAT)
        record.unpack_rdata(b"", 0)
        other = nb.NS.RR(type=nb.NS_A, rdata=b"\x01\x02\x03\x04")
        other.unpack_rdata(b"", 0)
        return [record.nodenames, other.ip]

    return {
        "encode": attempt(
            lambda: [nb.encode_name(n) for n in ("The NetBIOS name", "FRED            ", "*", "")]
        ),
        "encode_long": attempt(lambda: nb.encode_name("A" * 20)),
        "decode": attempt(
            lambda: [
                nb.decode_name(n)
                for n in (
                    "FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF",
                    "FEGHGFCAEOGFHEECEJEPFDCAHEGBGNGF",
                    "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB",
                    "",
                )
            ]
        ),
        "decode_lowercase": attempt(lambda: nb.decode_name("a" * 32)),
        "decode_below_a": attempt(lambda: nb.decode_name("0" * 32)),
        "service_names": attempt(
            lambda: [
                nb.node_to_service_name(t)
                for t in (
                    ("ISS", 0x00, 0x0800),
                    ("IS~X", 0x00, 0x0000),
                    ("ISS", 0xFF, 0x0800),
                    ("__MSBROWSE__", 0x01, nb.NS_NAME_G),
                    ("Forte_$ND800ZA", 0x20, 0),
                    ("SERVER", 0x20, 0),
                )
            ]
        ),
        "default_ns": attempt(lambda: snapshot(nb.NS())),
        "default_session": attempt(lambda: snapshot(nb.Session())),
        "default_datagram": attempt(lambda: snapshot(nb.Datagram())),
        "rr_len": attempt(lambda: len(nb.NS.RR())),
        "built_query": attempt(built_query),
        "built_answer": attempt(built_answer),
        "unpack_rdata_direct": attempt(unpack_rdata_direct),
        "nbstat_error_classes": attempt(
            lambda: [
                c.__name__
                for c in type(
                    _raised(lambda: nb.NS(bytes.fromhex(cases()["ns_nbstat_empty"][1])))
                ).__mro__
                if c.__module__ == "builtins"
            ]
        ),
        "class_tree": attempt(
            lambda: [
                issubclass(nb.NS, package.dns.DNS),
                issubclass(nb.NS.RR, package.dns.DNS.RR),
                issubclass(nb.NS.Q, package.dns.DNS.Q),
            ]
        ),
        "constants": attempt(
            lambda: [
                nb.NS_NBSTAT,
                nb.NS_NAME_PRM,
                nb.SSN_KEEPALIVE == 5,
                nb.DGRAM_NEGATIVE,
                len(nb.nbstat_svcs),
                nb.nbstat_svcs[(0x20, 1)],
            ]
        ),
    }


def exercise(package):
    targets = {
        "ns": package.netbios.NS,
        "session": package.netbios.Session,
        "datagram": package.netbios.Datagram,
    }
    return {
        "cases": {
            name: attempt(lambda t=t, h=h: snapshot(targets[t](bytes.fromhex(h))))
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
    for member in ("netbios", "dns"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified NetBIOS or DNS module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. A NODE STATUS
# record with empty resource data raises IndexError in dpkt; OctetRail raises
# netbios.NodeStatusError, which is both an UnpackError and an IndexError.
DECLARED = {
    "cases.ns_nbstat_empty": {"error": "NodeStatusError", "message": "index out of range"},
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
        C.require(not wrong, "NetBIOS mismatch " + module + v + ": " + ", ".join(wrong))
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
