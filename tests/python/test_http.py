"""HTTP requests and responses parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import io
import subprocess
import sys
import time
import unittest
from collections import OrderedDict
from pathlib import Path
from unittest.mock import patch

import octetrail
from octetrail import NeedData, UnpackError, http, ip, tcp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("http_fixture", ROOT / "tools/http_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class HttpTests(unittest.TestCase):
    def test_independent_fields_serialization_constructors_mutation(self):
        report = F.exercise(octetrail)
        self.assertEqual(report["cases"], {c["id"]: F.expected(c, "octetrail") for c in F.cases()})
        self.assertEqual(len(report["constructors"]), 16)

    def test_explicit_api_preserves_transport_data(self):
        raw = bytes.fromhex(F.cases()[0]["wire"])
        packet = ip.IP(p=6, data=tcp.TCP(dport=80, data=raw))
        parsed = ip.IP(bytes(packet))
        self.assertIsInstance(parsed.data, tcp.TCP)
        self.assertEqual(parsed.data.data, raw)
        self.assertEqual(http.Request(parsed.data.data).uri, "/note?q=1")

    def test_decode_falls_back_to_the_bytes(self):
        raw = b"ordinary note"
        self.assertIs(http.decode(raw), raw)
        self.assertIsInstance(http.decode(b"HTTP/1.1 200 OK\r\n\r\n"), http.Response)
        self.assertIsInstance(http.decode(b"GET / HTTP/1.1\r\n\r\n"), http.Request)
        for error in (MemoryError("allocation"), ValueError("caller")):
            with (
                patch.object(http._native, "_http_request_line", side_effect=error),
                self.assertRaises(type(error)) as result,
            ):
                http.decode(raw)
            self.assertIs(result.exception, error)
        with self.assertRaises(TypeError):
            http.decode("note")

    def test_start_lines(self):
        r = http.Request(b"GET /a HTTP/1.1 extra\r\n\r\n")
        self.assertEqual((r.method, r.uri, r.version), ("GET", "/a", "1.1"))
        self.assertEqual(http.Request(b"GET /a\r\n").version, "0.9")
        self.assertEqual(http.Request(b"GET /a HTTP\r\n").version, "")
        self.assertEqual(http.Request(b"\x1cGET\x1c/a\x1cHTTPX2\r\n").version, "2")
        for raw in (b"GET\r\n", b"PATCH / HTTP/1.1\r\n", b"GET / FTP/1.0\r\n", b""):
            with self.assertRaises(UnpackError):
                http.Request(raw)
        r = http.Response(b"HTTP/1.1   200   All  Good \x1c\r\n\r\n")
        self.assertEqual((r.version, r.status, r.reason), ("1.1", "200", "All  Good \x1c"))
        self.assertEqual(http.Response(b"HTTP/1.1 200\r\n").reason, "")
        for raw in (b"HTTP/1.1\r\n", b"HTTP/1.1 2x0 OK\r\n", b"FTP/1.1 200 OK\r\n"):
            with self.assertRaises(UnpackError):
                http.Response(raw)

    def test_headers(self):
        r = http.Request(
            b"GET / HTTP/1.1\r\nX-A: 1\r\nHost:  h \r\nx-a: 2\r\nNo-Colon\r\nE:\r\n\r\nrest"
        )
        self.assertIsInstance(r.headers, OrderedDict)
        self.assertEqual(
            list(r.headers.items()),
            [("x-a", ["1", "2"]), ("host", "h"), ("no-colon", ""), ("e", "")],
        )
        self.assertEqual(r.data, b"rest")
        r = http.Request(b"GET / HTTP/1.1\r\nHost : h\r\n\xff\r\nafter: 1\r\n")
        self.assertEqual(list(r.headers), ["host "])
        self.assertEqual(r.data, b"after: 1\r\n")
        for line in (b"Two Words: x", b": empty name"):
            with self.assertRaises(UnpackError):
                http.Request(b"GET / HTTP/1.1\r\n" + line + b"\r\n\r\n")

    def test_body_selection_and_errors(self):
        head = b"POST / HTTP/1.1\r\n"
        cases = {
            b"Content-Length: 2\r\n\r\nokTAIL": (b"ok", b"TAIL"),
            b"Content-Length: +0_2\r\n\r\nok": (b"ok", b""),
            b"Content-Type: x\r\n\r\nall of it": (b"all of it", b""),
            b"X: 1\r\n\r\nunframed": (b"", b"unframed"),
            b"Transfer-Encoding: Chunked\r\n\r\n2 ext\r\nab\r\n0x1\r\nc\r\n0\r\nnext": (
                b"abc",
                b"",
            ),
        }
        for raw, (body, data) in cases.items():
            r = http.Request(head + raw)
            self.assertEqual((r.body, r.data), (body, data), raw)
        for raw in (
            b"Content-Length: 3\r\n\r\nno",
            b"Content-Length: -1\r\n\r\n",
            b"Transfer-Encoding: chunked\r\n\r\n3\r\nabcd\r\n0\r\n\r\n",
            b"Transfer-Encoding: chunked\r\n\r\n9\r\nabc",
        ):
            with self.assertRaises(NeedData):
                http.Request(head + raw)
        for raw in (
            b"Transfer-Encoding: chunked\r\n\r\n\r\n",
            b"Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
            b"Transfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"Content-Length: two\r\n\r\n",
            b"Content-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            b"Transfer-Encoding: a\r\nTransfer-Encoding: b\r\n\r\n",
        ):
            with self.assertRaises(UnpackError):
                http.Request(head + raw)

    def test_int_whitespace_is_ascii_only(self):
        head = b"POST / HTTP/1.1\r\n"
        for c in (b"\x1c", b"\x1d", b"\x1e", b"\x1f"):
            for raw in (
                b"Transfer-Encoding: chunked\r\n\r\n4" + c + b"\r\nabcd\r\n0\r\n\r\n",
                b"Content-Length: 2" + c + b"\r\n\r\nok",
            ):
                with self.assertRaises(UnpackError):
                    http.Request(head + raw)
            self.assertEqual(
                http.Request(head + b"Content-Length: " + c + b"2\r\n\r\nok").body, b"ok"
            )

    def test_responses_without_a_body(self):
        for status in ("100", "204", "304", "0199"):
            r = http.Response(
                b"HTTP/1.1 " + status.encode() + b" X\r\nContent-Length: 4\r\n\r\nnote"
            )
            self.assertEqual((r.body, r.data), (b"", b"note"))
        r = http.Response(b"HTTP/1.1 0200 X\r\nContent-Length: 4\r\n\r\nnote")
        self.assertEqual((r.body, r.data), (b"note", b""))

    def test_partial_state_after_errors(self):
        r = http.Request()
        with self.assertRaises(NeedData):
            r.unpack(b"POST /note HTTP/1.1\r\nContent-Length: 4\r\n\r\nno")
        self.assertEqual((r.method, r.uri, r.version), ("POST", "/note", "1.1"))
        self.assertEqual(r.headers, {"content-length": "4"})
        r = http.Request()
        with self.assertRaises(UnpackError):
            r.unpack(b"ordinary note\r\n\r\n")
        self.assertEqual((r.method, r.uri, r.version), ("GET", "/", "1.0"))

    def test_packing(self):
        r = http.Request(method="POST", uri="/é", headers={"x": ["a", "b"], "n": 5}, body=b"\xff")
        self.assertEqual(bytes(r), b"POST / HTTP/1.0\r\nx: ['a', 'b']\r\nn: 5\r\n\r\n\xff")
        self.assertEqual(str(r), "POST /é HTTP/1.0\r\nx: ['a', 'b']\r\nn: 5\r\n\r\n")
        self.assertEqual(len(r), len(str(r)))
        self.assertEqual(bytes(http.Response(status=404, body=None)), b"HTTP/1.0 404 OK\r\n\r\n")
        parsed = http.Response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokTAIL")
        self.assertEqual(bytes(parsed), b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
        a, b = http.Request(), http.Request()
        a.headers["x-note"] = "note"
        self.assertEqual(b.headers, {})
        self.assertEqual(http.Request(b"GET / HTTP/1.1\r\n\r\n", method="POST").method, "GET")

    def test_module_level_parsers_advance_the_file(self):
        f = io.BytesIO(b"A: 1\r\nB: 2\r\n\r\nbodyrest")
        headers = http.parse_headers(f)
        self.assertEqual(headers, {"a": "1", "b": "2"})
        self.assertEqual(f.tell(), 14)
        self.assertEqual(http.parse_body(f, {"content-length": "4"}), b"body")
        self.assertEqual(f.read(), b"rest")
        f = io.BytesIO(b"1\r\nx\r\n0\r\n\r\nafter")
        self.assertEqual(http.parse_body(f, {"transfer-encoding": "chunked"}), b"x")
        self.assertEqual(f.read(), b"after")
        with self.assertRaises(AttributeError):
            http.parse_body(io.BytesIO(b""), {"transfer-encoding": ["a", "b"]})
        with self.assertRaises(ValueError):
            http.parse_body(io.BytesIO(b""), {"content-length": "x"})
        message = http.Message(b"A: 1\r\n\r\n")
        self.assertEqual((message.headers, message.body), ({"a": "1"}, b""))
        self.assertEqual(bytes(message), b"a: 1\r\n\r\n")

    def test_large_messages_parse_whole(self):
        raw = b"POST / HTTP/1.1\r\n" + b"X-Note: n\r\n" * 5000 + b"Content-Length: 4\r\n\r\nnote"
        r = http.Request(raw)
        self.assertEqual((len(r.headers["x-note"]), r.body), (5000, b"note"))

    def test_distinct_header_names_parse_in_linear_time(self):
        def parse(count):
            names = b"".join(b"X-%d: v\r\n" % i for i in range(count))
            raw = b"GET / HTTP/1.1\r\n" + names + b"X-0: w\r\n\r\n"
            start = time.perf_counter()
            r = http.Request(raw)
            return r, time.perf_counter() - start

        small, small_time = parse(2000)
        large, large_time = parse(32000)
        self.assertEqual(len(small.headers), 2000)
        self.assertEqual(len(large.headers), 32000)
        self.assertEqual(list(large.headers)[:2], ["x-0", "x-1"])
        self.assertEqual(large.headers["x-0"], ["v", "w"])
        self.assertLess(large_time, max(small_time, 0.001) * 64)

    def test_optimized_probe_rejects_wrong_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/http_differential.py",
                "--probe",
                "--module",
                "octetrail",
                "--version",
                "9.9.9",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wrong provider version", result.stderr)


if __name__ == "__main__":
    unittest.main()
