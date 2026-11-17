"""Independent HTTP fixtures decoded by dpkt 1.9.6, 1.9.8 and OctetRail, which must agree."""

import argparse
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


def fixture(name, kind, start, headers=(), body=b"", tail=b"", source=None):
    fields = dict(
        zip(
            ("method", "uri", "version") if kind == "Request" else ("version", "status", "reason"),
            start,
            strict=True,
        )
    )
    first = (
        f"{start[0]} {start[1]} HTTP/{start[2]}"
        if kind == "Request"
        else f"HTTP/{start[0]} {start[1]} {start[2]}"
    )
    canonical = (
        first.encode()
        + b"\r\n"
        + b"".join(f"{k}: {v}\r\n".encode() for k, v in headers)
        + b"\r\n"
        + body
    )
    expected = {
        "fields": fields,
        "headers": dict(headers),
        "body": body.hex(),
        "data": tail.hex(),
        "wire": canonical.hex(),
        "length": len(canonical.decode("utf8", "ignore")),
    }
    return {
        "id": name,
        "kind": kind,
        "wire": (source if source is not None else canonical + tail).hex(),
        "expected": expected,
        "category": "equal",
    }


def cases():
    rows = [
        fixture(
            "get",
            "Request",
            ("GET", "/note?q=1", "1.1"),
            [("host", "example.test"), ("user-agent", "offline-note/1")],
            source=b"GET /note?q=1 HTTP/1.1\r\nHost: example.test\r\nUser-Agent: offline-note/1\r\n\r\n",
        ),
        fixture("post", "Request", ("POST", "/note", "1.1"), [("content-length", "4")], b"note"),
        fixture(
            "binary", "Request", ("PUT", "/note", "1.0"), [("content-length", "2")], b"\x00\xff"
        ),
        fixture(
            "utf8-body", "Response", ("1.1", "200", "OK"), [("content-length", "2")], "é".encode()
        ),
        fixture(
            "eof-type", "Response", ("1.0", "200", "OK"), [("content-type", "text/plain")], b"note"
        ),
        fixture("unframed-tail", "Response", ("1.0", "200", "OK"), tail=b"note"),
        fixture(
            "length-tail",
            "Request",
            ("POST", "/note", "1.1"),
            [("content-length", "4")],
            b"note",
            b"NEXT",
        ),
        fixture(
            "not-found", "Response", ("1.1", "404", "Not Found"), [("content-length", "4")], b"note"
        ),
        fixture("empty-reason", "Response", ("1.1", "200", ""), source=b"HTTP/1.1 200\r\n\r\n"),
        fixture(
            "spacing",
            "Response",
            ("1.1", "200", "All Good"),
            source=b"HTTP/1.1   200   All Good\r\n\r\n",
        ),
        fixture("head-request", "Request", ("HEAD", "/note", "1.1")),
        fixture("connect", "Request", ("CONNECT", "example.test:443", "1.1")),
        fixture(
            "duplicate",
            "Request",
            ("GET", "/", "1.1"),
            [("x-note", ["first", "second"])],
            source=b"GET / HTTP/1.1\r\nX-Note: first\r\nX-Note: second\r\n\r\n",
        ),
    ]
    for status in ("100", "204", "304"):
        rows.append(
            fixture(
                "no-body-" + status,
                "Response",
                ("1.1", status, "Note"),
                [("content-length", "4")],
                tail=b"note",
            )
        )
    rows.append(
        {
            "id": "short-body",
            "kind": "Request",
            "wire": b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nno".hex(),
            "expected": {"error": "NeedData"},
            "category": "equal",
        }
    )
    rows.append(
        {
            "id": "unlisted-method",
            "kind": "Request",
            "wire": b"PATCH /note HTTP/1.1\r\n\r\n".hex(),
            "expected": {"error": "UnpackError"},
            "category": "equal",
        }
    )
    for name, wire, kind in (
        ("http09", b"GET /note\r\n\r\n", "Request"),
        ("lf-only", b"GET / HTTP/1.1\nHost: example.test\n\n", "Request"),
        ("unfinished-head", b"GET / HTTP/1.1\r\nHost: example.test\r\n", "Request"),
        (
            "chunked",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nnote\r\n0\r\n\r\n",
            "Response",
        ),
    ):
        rows.append({"id": name, "wire": wire.hex(), "kind": kind, "category": name})
    return rows


def expected(case, module):
    """What dpkt 1.9.8 reports for a fixture; OctetRail must match it exactly."""
    if case["category"] == "equal":
        return case["expected"]
    if case["id"] == "http09":
        return fixture("", "Request", ("GET", "/note", "0.9"))["expected"]
    if case["id"] in ("lf-only", "unfinished-head"):
        return fixture("", "Request", ("GET", "/", "1.1"), [("host", "example.test")])["expected"]
    return fixture(
        "", "Response", ("1.1", "200", "OK"), [("transfer-encoding", "chunked")], b"note"
    )["expected"]


def snapshot(message):
    names = (
        ("method", "uri", "version")
        if hasattr(message, "method")
        else ("version", "status", "reason")
    )
    return {
        "fields": {key: getattr(message, key) for key in names},
        "headers": message.headers,
        "body": message.body.hex(),
        "data": message.data.hex(),
        "wire": bytes(message).hex(),
        "length": len(message),
    }


def review_checks(package, provider):
    H = package.http
    for name in ("X-Note", "note_token"):
        message = H.Request(headers={name: "ordinary value"})
        C.require(
            message.pack_hdr() == name + ": ordinary value\r\n", "ordinary header token rendering"
        )
    raw = b"GET /note HTTP/1.1\r\nContent-Type: application/octet-stream\r\n\r\n" + bytes(1 << 21)
    C.require(len(H.Request(raw).body) == 1 << 21, "large body parses whole")
    return {"large_body_bytes": 1 << 21}


def attempt(action):
    try:
        found = action()
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}
    if isinstance(found, (bytes, bytearray)):
        return {"hex": bytes(found).hex()}
    return found


def observations(package):
    """Class shape, subclass hooks and error text, compared with dpkt 1.9.8."""
    H = package.http

    class Sip(H.Request):
        _Request__methods = dict.fromkeys(("INVITE", "ACK"))
        _Request__proto = "SIP"

    class SipReply(H.Response):
        _Response__proto = "SIP"

    invite = b"INVITE sip:a@b SIP/2.0\r\nTo: a\r\nContent-Length: 2\r\n\r\nhi"
    reply = b"SIP/2.0 180 Ringing\r\nTo: a\r\n\r\n"
    request = b"GET /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabcde"

    def shape(message):
        return {
            # OrderedDict's repr changed in Python 3.12.
            "repr": repr(message).replace(repr(message.headers), "HEADERS"),
            "str": str(message),
            "bytes": bytes(message).hex(),
            "len": len(message),
            "vars": sorted(vars(message)),
            "pack_hdr": message.pack_hdr(),
        }

    found = {
        # dpkt's Packet has a "Temp" base left by its Python 2 metaclass shim.
        "mro": [c.__name__ for c in H.Request.__mro__ if c.__name__ != "Temp"],
        "response_mro": [c.__name__ for c in H.Response.__mro__ if c.__name__ != "Temp"],
        "hdr": attempt(lambda: [H.Message.__hdr__, H.Request.__hdr__, H.Response.__hdr__]),
        "request": attempt(lambda: shape(H.Request(request))),
        "response": attempt(lambda: shape(H.Response(b"HTTP/1.1 204 No\r\nA: b\r\n\r\nzz"))),
        "message": attempt(lambda: shape(H.Message(b"Host: a\r\n\r\nbody"))),
        "default_request": attempt(lambda: shape(H.Request())),
        "default_response": attempt(lambda: shape(H.Response())),
        "keywords": attempt(lambda: shape(H.Request(uri="/k", body=b"b", data=b"d"))),
        "sip_request": attempt(lambda: shape(Sip(invite))),
        "sip_reply": attempt(lambda: shape(SipReply(reply))),
        "sip_rejects_http": attempt(lambda: Sip(request)),
        "http_rejects_sip": attempt(lambda: H.Request(invite)),
        "bad_request_line": attempt(lambda: H.Request(b"GET\r\n\r\n")),
        "bad_method": attempt(lambda: H.Request(b"BREW / HTTP/1.1\r\n\r\n")),
        "bad_version": attempt(lambda: H.Request(b"GET / FTP/1.0\r\n\r\n")),
        "bad_response": attempt(lambda: H.Response(b"HTTP/1.1\r\n\r\n")),
        "bad_status_proto": attempt(lambda: H.Response(b"FTP/1.1 200 OK\r\n\r\n")),
        "short_body": attempt(lambda: H.Request(request[:-3])),
        "negative_length": attempt(
            lambda: H.Request(b"GET / HTTP/1.1\r\nContent-Length: -2\r\n\r\nab")
        ),
        "bad_length": attempt(lambda: H.Request(b"GET / HTTP/1.1\r\nContent-Length: x\r\n\r\n")),
        "largest_length": attempt(
            lambda: H.Request(b"GET / HTTP/1.1\r\nContent-Length: 9223372036854775807\r\n\r\n")
        ),
        "huge_length": attempt(
            lambda: H.Request(b"GET / HTTP/1.1\r\nContent-Length: 9223372036854775808\r\n\r\n")
        ),
        "huge_negative_length": attempt(
            lambda: H.Request(b"GET / HTTP/1.1\r\nContent-Length: -9223372036854775809\r\n\r\n")
        ),
        "largest_chunk": attempt(
            lambda: H.Response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"7fffffffffffffff\r\nab\r\n0\r\n\r\n"
            )
        ),
        "huge_chunk": attempt(
            lambda: H.Response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"8000000000000000\r\nab\r\n0\r\n\r\n"
            )
        ),
        "huge_negative_chunk": attempt(
            lambda: H.Response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"-8000000000000001\r\nab\r\n0\r\n\r\n"
            )
        ),
        "two_lengths": kind(
            lambda: H.Request(b"GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nab")
        ),
        "two_encodings": attempt(
            lambda: H.Request(
                b"GET / HTTP/1.1\r\nTransfer-Encoding: a\r\nTransfer-Encoding: b\r\n\r\n"
            )
        ),
        "bad_header": attempt(
            lambda: H.Request(b"GET / HTTP/1.1\r\nbad name: it's\t\x01\\\r\n\r\n")
        ),
        "bad_header_quotes": attempt(lambda: H.Request(b"GET / HTTP/1.1\r\na b: \"'\r\n\r\n")),
        "missing_chunk": attempt(
            lambda: H.Response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n")
        ),
        "bad_chunk": attempt(
            lambda: H.Response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")
        ),
        "short_chunks": attempt(
            lambda: H.Response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n")
        ),
        "error_classes": [
            sorted(c.__name__ for c in type(_raised(action)).__mro__ if c.__module__ == "builtins")
            for action in (
                lambda: H.Request(b"GET / HTTP/1.1\r\nContent-Length: x\r\n\r\n"),
                lambda: H.Request(
                    b"GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"
                ),
                lambda: H.Request(
                    b"GET / HTTP/1.1\r\nTransfer-Encoding: a\r\nTransfer-Encoding: b\r\n\r\n"
                ),
                lambda: H.Request(b"GET / HTTP/1.1\r\nContent-Length: 9223372036854775808\r\n\r\n"),
                lambda: H.Response(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                    b"8000000000000000\r\nab\r\n0\r\n\r\n"
                ),
            )
        ],
        "unpack_again": attempt(lambda: shape(_unpacked(H.Request(), request))),
        "bytearray": attempt(lambda: shape(H.Request(bytearray(request)))),
    }
    return found


def kind(action):
    """The error class only, for errors whose message varies with the Python version."""
    found = attempt(action)
    return found.get("error", found) if isinstance(found, dict) else found


def _raised(action):
    try:
        action()
    except Exception as error:  # noqa: BLE001 - the error is the observation.
        return error
    return None


def _unpacked(message, buf):
    message.unpack(buf)
    return message


def exercise(package):
    output = {}
    for case in cases():
        try:
            message = getattr(package.http, case["kind"])(bytes.fromhex(case["wire"]))
        except package.UnpackError as e:
            output[case["id"]] = {"error": type(e).__name__}
        else:
            output[case["id"]] = snapshot(message)
    constructors = []
    for case in cases():
        if case["category"] != "equal" or "error" in case["expected"]:
            continue
        want = case["expected"]
        message = getattr(package.http, case["kind"])(
            **want["fields"],
            headers=dict(want["headers"]),
            body=bytes.fromhex(want["body"]),
            data=bytes.fromhex(want["data"]),
        )
        C.require(snapshot(message) == want, "HTTP independent constructor " + case["id"])
        constructors.append(case["id"])
    defaults = [bytes(package.http.Request()).hex(), bytes(package.http.Response()).hex()]
    C.require(
        defaults == [b"GET / HTTP/1.0\r\n\r\n".hex(), b"HTTP/1.0 200 OK\r\n\r\n".hex()],
        "HTTP independent defaults",
    )
    r = package.http.Request(bytes.fromhex(cases()[0]["wire"]))
    r.method, r.uri, r.body = "POST", "/changed", b"note"
    r.headers["content-length"] = "4"
    mutated = b"POST /changed HTTP/1.1\r\nhost: example.test\r\nuser-agent: offline-note/1\r\ncontent-length: 4\r\n\r\nnote"
    C.require(bytes(r) == mutated, "HTTP mutable independent bytes")
    r.body = b"ok"
    C.require(bytes(r) == mutated[:-4] + b"ok", "HTTP caller length retained")
    partial = package.http.Request()
    partial.method = partial.uri = partial.version = None
    try:
        partial.unpack(bytes.fromhex(next(c["wire"] for c in cases() if c["id"] == "short-body")))
    except package.NeedData:
        pass
    else:
        raise ValueError("HTTP partial body unexpectedly complete")
    C.require(
        (partial.method, partial.uri, partial.version, partial.headers)
        == ("POST", "/", "1.1", {"content-length": "4"}),
        "HTTP partial request demand",
    )
    return {
        "observations": observations(package),
        "cases": output,
        "constructors": constructors,
        "defaults": defaults,
        "mutations": 2,
        "partial_state": 1,
        "review": review_checks(
            package, "octetrail" if package.__name__ == "octetrail" else "dpkt"
        ),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(package.http.__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/http.py")).resolve(),
        "unverified HTTP origin",
    )
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. dpkt fails on a
# Content-Length that is not an integer, a repeated Content-Length and a repeated
# Transfer-Encoding, and a Content-Length or chunk size outside Py_ssize_t, with
# builtin errors; OctetRail raises classes that are both an UnpackError and that
# builtin error, with the same message.
_OVERFLOW = {
    "error": "LengthOverflowError",
    "message": "cannot fit 'int' into an index-sized integer",
}
DECLARED = {
    "huge_length": _OVERFLOW,
    "huge_negative_length": _OVERFLOW,
    "huge_chunk": _OVERFLOW,
    "huge_negative_chunk": _OVERFLOW,
    "bad_length": {
        "error": "HeaderValueError",
        "message": "invalid literal for int() with base 10: 'x'",
    },
    "two_lengths": "HeaderTypeError",
    "two_encodings": {
        "error": "HeaderAttributeError",
        "message": "'list' object has no attribute 'lower'",
    },
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--probe", action="store_true")
    p.add_argument("--module", choices=("dpkt", "octetrail"))
    p.add_argument("--version")
    p.add_argument("--oracle-196")
    p.add_argument("--oracle-198")
    p.add_argument("--python", action="append", default=[])
    a = p.parse_args()
    if a.probe:
        print(json.dumps(exercise(provenance(a.module, a.version))))
        return
    C.require(
        a.oracle_196 and a.oracle_198 and a.python,
        "both pinned references and an installed candidate are required",
    )
    version = tomllib.loads((C.ROOT / "pyproject.toml").read_text())["project"]["version"]
    providers = [
        (a.oracle_196, "dpkt", "1.9.6"),
        (a.oracle_198, "dpkt", "1.9.8"),
        *((x, "octetrail", version) for x in a.python),
    ]
    reports = []
    for python, module, v in providers:
        r = subprocess.run(
            [python, "-B", "-I", "-O", __file__, "--probe", "--module", module, "--version", v],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        report = json.loads(r.stdout)
        C.require(
            report["cases"] == {c["id"]: expected(c, module) for c in cases()},
            "HTTP observation mismatch " + module + v,
        )
        C.require(len(report["constructors"]) == 16, "HTTP constructor coverage")
        reports.append(report["observations"])
    reference = reports[1]
    for (_, module, v), report in zip(providers[2:], reports[2:], strict=True):
        wrong = sorted(k for k in reference if report.get(k) != DECLARED.get(k, reference[k]))
        C.require(not wrong, "HTTP observation mismatch " + module + v + ": " + ", ".join(wrong))
    print(
        json.dumps(
            {
                "fixtures": len(cases()),
                "equal_cases": 18,
                "fixtures_matching_dpkt_quirks": [
                    c["id"] for c in cases() if c["category"] != "equal"
                ],
                "constructors_per_provider": 16,
                "defaults_per_provider": 2,
                "mutations_per_provider": 2,
                "partial_state_per_provider": 1,
                "observations": len(reference),
                "dpkt_196_differs_on": sorted(
                    k for k in reference if reports[0].get(k) != reference[k]
                ),
                "providers": len(providers),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
