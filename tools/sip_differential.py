"""SIP requests and responses run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same messages, builds them from keywords and packs
them again. OctetRail must match dpkt
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

INVITE = (
    b"INVITE sip:bob@biloxi.example SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP pc33.atlanta.example;branch=z9hG4bK776asdhds\r\n"
    b"Via: SIP/2.0/UDP bigbox3.site3.atlanta.example\r\n"
    b"Max-Forwards: 70\r\n"
    b"To: Bob <sip:bob@biloxi.example>\r\n"
    b"From: Alice <sip:alice@atlanta.example>;tag=1928301774\r\n"
    b"Call-ID: a84b4c76e66710@pc33.atlanta.example\r\n"
    b"CSeq: 314159 INVITE\r\n"
    b"Contact: <sip:alice@pc33.atlanta.example>\r\n"
    b"Content-Type: application/sdp\r\n"
    b"Content-Length: 14\r\n\r\n"
    b"v=0\r\no=alice\r\n"
)
OK = (
    b"SIP/2.0 200 OK\r\n"
    b"To: Bob <sip:bob@biloxi.example>;tag=a6c85cf\r\n"
    b"CSeq: 314159 INVITE\r\n"
    b"Content-Length: 4\r\n\r\n"
    b"v=0\nNEXT"
)


def cases():
    """(target, hex) by name."""
    found = {
        "invite": ("Request", INVITE),
        "invite_tail": ("Request", INVITE + b"BYE"),
        "register": ("Request", b"REGISTER sip:registrar.example SIP/2.0\r\nTo: a\r\n\r\n"),
        "options_no_version": ("Request", b"OPTIONS sip:x\r\n\r\n"),
        "ack_extra_words": ("Request", b"ACK sip:x SIP/2.0 more words\r\n\r\n"),
        "compact_headers": ("Request", b"BYE sip:x SIP/2.0\r\nv: a\r\ni: b\r\nl: 0\r\n\r\n"),
        "http_method": ("Request", b"GET / SIP/2.0\r\n\r\n"),
        "http_version": ("Request", b"INVITE sip:x HTTP/1.1\r\n\r\n"),
        "lower_method": ("Request", b"invite sip:x SIP/2.0\r\n\r\n"),
        "short_body": ("Request", INVITE[:-2]),
        "bad_header": ("Request", b"INVITE sip:x SIP/2.0\r\nbad name: x\r\n\r\n"),
        "empty": ("Request", b""),
        "ok": ("Response", OK),
        "ringing": ("Response", b"SIP/2.0 180 Ringing\r\nContent-Length: 4\r\n\r\nnote"),
        "no_reason": ("Response", b"SIP/2.0 486\r\n\r\n"),
        "http_response": ("Response", b"HTTP/1.1 200 OK\r\n\r\n"),
        "bad_status": ("Response", b"SIP/2.0 OK fine\r\n\r\n"),
        "chunked_response": (
            "Response",
            b"SIP/2.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n",
        ),
        "response_short": ("Response", b"SIP/2.0\r\n"),
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
    found = {"class": type(packet).__name__}
    # OrderedDict's repr changed in Python 3.12.
    found["repr"] = repr(packet).replace(repr(packet.headers), "HEADERS")
    found["headers"] = list(packet.headers.items())
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["str"] = attempt(lambda: str(packet))
    found["fields"] = {
        k: repr(v) for k, v in sorted(vars(packet).items()) if k[0] != "_" and k != "headers"
    }
    return found


def constructed(package):
    sip = package.sip

    def shared_defaults():
        # dpkt's default header dict is one object shared by every new message.
        first, second = sip.Request(), sip.Request()
        first.headers["X-Note"] = "set"
        found = [second.headers is first.headers, bytes(second).hex()]
        del first.headers["X-Note"]
        return found

    def repacked():
        message = sip.Request(INVITE)
        message.method, message.uri = "BYE", "sip:bob@biloxi.example"
        message.headers["cseq"] = "314160 BYE"
        message.body = b""
        message.headers["content-length"] = "0"
        return [bytes(message).hex(), len(message), str(message)]

    return {
        "default_request": attempt(lambda: snapshot(sip.Request())),
        "default_response": attempt(lambda: snapshot(sip.Response())),
        "shared_defaults": attempt(shared_defaults),
        "keywords": attempt(
            lambda: snapshot(sip.Request(method="REGISTER", uri="sip:r", body=b"b", data=b"d"))
        ),
        "response_keywords": attempt(
            lambda: snapshot(sip.Response(status="404", reason="Not Found", headers={}))
        ),
        "repacked": attempt(repacked),
        "bytearray": attempt(lambda: snapshot(sip.Request(bytearray(INVITE)))),
        "unpack_again": attempt(lambda: snapshot(_unpacked(sip.Request(), INVITE))),
        "mro": [c.__name__ for c in sip.Request.__mro__ if c.__name__ != "Temp"],
        "response_mro": [c.__name__ for c in sip.Response.__mro__ if c.__name__ != "Temp"],
        "http_unchanged": attempt(
            lambda: snapshot(package.http.Request(b"GET / HTTP/1.1\r\n\r\n"))
        ),
        "http_rejects_sip": attempt(lambda: package.http.Request(INVITE)),
    }


def _unpacked(message, buf):
    message.unpack(buf)
    return message


def exercise(package):
    return {
        "cases": {
            name: attempt(lambda t=t, h=h: snapshot(getattr(package.sip, t)(bytes.fromhex(h))))
            for name, (t, h) in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for member in ("http", "sip"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified HTTP or SIP module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. There are none.
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
        C.require(not wrong, "SIP mismatch " + module + v + ": " + ", ".join(wrong))
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
