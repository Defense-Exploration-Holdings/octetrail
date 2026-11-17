"""ICMP and ICMPv6 messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same messages, alone and inside IPv6, including
dpkt's own test vectors, builds them from keywords and packs them again.
OctetRail must match dpkt 1.9.8 on every observation except the declared ones;
the keys where 1.9.6 differs are listed. ICMP quotes of IPv4 headers are
compared by bytes only, since IPv4 parity is a separate module.
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

# dpkt's test_icmp vector: a port unreachable quoting an IPv4 TCP header.
UNREACH_DPKT = (
    "030a6b190000000045000028941f0000e30699b4232b2400de8e8442abd100500035e12920d9"
    "000000229bf0e204656b"
)
ECHO_DATA = b"ABCDEFGHIJKLMNOPQRSTUVWABCDEFGHI"
# A time exceeded message quoting IPv6 whose next header is 44 after an AH header.
FRAGMENT_AFTER_AH = (
    "03218f54407964ce60000000001e2c40267dfba003257d76a397ad2d06dd272b093c18d34a5fda962e"
    "c0c9ec8a3655cc3351fb18cd83f2f91e5e0caa8cdbbf30f84e247e08df87dd91adc1dfcd49"
)


def ip6(nxt, body):
    return struct.pack(">IHBB16s16s", 0x60000000, len(body), nxt, 64, bytes(16), bytes(16)) + body


def cases():
    """(target, hex) by name."""
    inner6 = ip6(59, b"note")
    found = {
        "icmp_echo": ("icmp", b"\x08\x00\x00\x00\x00\x01\x00\x02ping"),
        "icmp_echo_reply": ("icmp", b"\x00\x00\x53\x87\x00\x01\x03\xd6" + ECHO_DATA),
        "icmp_unreach_short_quote": ("icmp", b"\x03\x01\x00\x00\x00\x00\x05\xdc\x45\x00"),
        "icmp_redirect_short": ("icmp", b"\x05\x00\x00\x00\x0a\x00"),
        "icmp_time_exceed_empty": ("icmp", b"\x0b\x00\x00\x00\x00\x00\x00\x00"),
        "icmp_param_short": ("icmp", b"\x0c\x00\x00\x00\x01"),
        "icmp_unknown_type": ("icmp", b"\x01\x00\x00\x00abcd"),
        "icmp_short": ("icmp", b"\x08\x00\x00"),
        "icmp6_echo": ("icmp6", b"\x80\x00\x00\x00\x00\x07\x00\x01ping"),
        "icmp6_echo_short": ("icmp6", b"\x81\x00\x00\x00\x00"),
        "icmp6_unreach": ("icmp6", b"\x01\x04\x00\x00\x00\x00\x00\x00" + inner6),
        "icmp6_too_big": ("icmp6", b"\x02\x00\x00\x00\x00\x00\x05\x00" + inner6),
        "icmp6_time_exceed_cut": ("icmp6", b"\x03\x00\x00\x00\x00\x00\x00\x00" + inner6[:20]),
        "icmp6_param_prob": ("icmp6", b"\x04\x00\x00\x00\x00\x00\x00\x28" + inner6),
        "icmp6_neighbor_solicit": ("icmp6", b"\x87\x00\x00\x00" + bytes(20)),
        "icmp6_short": ("icmp6", b"\x80"),
        "ip6_icmp6_echo": ("ip6", ip6(58, b"\x80\x00\x00\x00\x00\x07\x00\x01ping")),
        "ip6_icmp6_error": ("ip6", ip6(58, b"\x01\x00\x00\x00\x00\x00\x00\x00" + inner6)),
        "ip6_icmp_echo": ("ip6", ip6(1, b"\x08\x00\x00\x00\x00\x01\x00\x02ping")),
        "ip6_icmp6_short": ("ip6", ip6(58, b"\x80\x00")),
        "icmp6_quote_fragment_after_ah": ("icmp6", bytes.fromhex(FRAGMENT_AFTER_AH)),
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
    data = getattr(packet, "data", None)
    if data is not None and not isinstance(data, (bytes, str)):
        found["data"] = snapshot(data)
    return found


def constructed(package):
    icmp, icmp6, ip6m = package.icmp, package.icmp6, package.ip6

    def quote(raw):
        message = icmp.ICMP(raw)
        return [
            bytes(message).hex(),
            len(message),
            type(message.data).__name__,
            type(message.data.data).__name__,
            sorted(vars(message)),
        ]

    r = {
        "default_icmp": attempt(lambda: snapshot(icmp.ICMP())),
        "default_icmp6": attempt(lambda: snapshot(icmp6.ICMP6())),
        "echo_given_sum": attempt(
            lambda: snapshot(
                icmp.ICMP(type=0, sum=0x5387, data=icmp.ICMP.Echo(id=1, seq=0x03D6, data=ECHO_DATA))
            )
        ),
        "echo_computed_sum": attempt(
            lambda: snapshot(
                icmp.ICMP(type=0, data=icmp.ICMP.Echo(id=1, seq=0x03D6, data=ECHO_DATA))
            )
        ),
        "dpkt_unreach_quote": attempt(lambda: quote(bytes.fromhex(UNREACH_DPKT))),
        "nested_defaults": attempt(
            lambda: [
                repr(cls())
                for cls in (
                    icmp.ICMP.Echo,
                    icmp.ICMP.Quote,
                    icmp.ICMP.Unreach,
                    icmp.ICMP.Redirect,
                    icmp.ICMP.ParamProbe,
                    icmp6.ICMP6.Error,
                    icmp6.ICMP6.TooBig,
                    icmp6.ICMP6.ParamProb,
                    icmp6.ICMP6.Echo,
                )
            ]
        ),
        "ip6_icmp6_checksum": attempt(
            lambda: snapshot(
                ip6m.IP6(nxt=58, data=icmp6.ICMP6(type=128, data=icmp6.ICMP6.Echo(id=7)))
            )
        ),
        "type_tables": attempt(
            lambda: [
                sorted((k, v.__name__) for k, v in icmp.ICMP._typesw.items()),
                sorted((k, v.__name__) for k, v in icmp6.ICMP6._typesw.items()),
                ip6m.IP6.get_proto(1).__name__,
                ip6m.IP6.get_proto(58).__name__,
            ]
        ),
        "constants": attempt(
            lambda: [
                icmp.ICMP_UNREACH_PORT,
                icmp.ICMP_TSTAMPREPLY,
                icmp6.ND_REDIRECT,
                icmp6.ICMP6_MAXTYPE,
                icmp6.MLD_LISTENER_DONE,
            ]
        ),
    }
    return r


def exercise(package):
    targets = {"icmp": package.icmp.ICMP, "icmp6": package.icmp6.ICMP6, "ip6": package.ip6.IP6}
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
    for member in ("icmp", "icmp6", "ip6"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified ICMP module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. dpkt raises
# AttributeError out of ICMP6 when a quoted IPv6 header has next header 44 after
# a header that is not a fragment header. OctetRail raises FragmentOffsetError,
# an UnpackError, inside the quote, so ICMP6 keeps the quote as bytes, as
# Ethernet and IP6 keep such a payload.
DECLARED = {
    "cases.icmp6_quote_fragment_after_ah": {
        "class": "ICMP6",
        "repr": "ICMP6(type=3, code=33, sum=36692, data=%r)" % bytes.fromhex(FRAGMENT_AFTER_AH)[4:],
        "len": 78,
        "bytes": FRAGMENT_AFTER_AH,
        "fields": {},
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
        C.require(not wrong, "ICMP mismatch " + module + v + ": " + ", ".join(wrong))
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
