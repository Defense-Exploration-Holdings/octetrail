"""Explicit HTTP message API using independent ordinary offline byte fixtures."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import octetrail
from octetrail import NeedData, PackError, UnpackError, http, ip, tcp

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

    def test_bytes_fallback_is_exact_and_does_not_swallow_other_errors(self):
        raw = b"ordinary note"
        self.assertIs(http.decode(raw), raw)
        self.assertIsInstance(http.decode(b"HTTP/1.1 200 OK\r\n\r\n"), http.Response)
        self.assertIsInstance(http.decode(b"GET / HTTP/1.1\r\n\r\n"), http.Request)
        for error in (MemoryError("allocation"), ValueError("caller")):
            with (
                patch.object(http._native, "_http_start", side_effect=error),
                self.assertRaises(type(error)) as result,
            ):
                http.decode(raw)
            self.assertIs(result.exception, error)
        oversized = b"GET /note HTTP/1.1\r\n\r\n" + bytes(http.MAX_MESSAGE_BYTES)
        self.assertIs(http.decode(oversized), oversized)
        with self.assertRaises(http.ParseLimitError) as result:
            http.Request(oversized)
        self.assertIsInstance(result.exception, UnpackError)
        self.assertIsInstance(result.exception, ValueError)
        self.assertIsInstance(result.exception, http.LimitError)

    def test_partial_header_and_body_leave_scoped_request_fields(self):
        for raw in (
            b"GET /note HTTP/1.1\r\nHost: example.test\r\n",
            b"GET /note HTTP/1.1\r\nContent-Length: 4\r\n\r\nno",
        ):
            r = http.Request()
            r.method = r.uri = r.version = None
            with self.assertRaises(NeedData):
                r.unpack(raw)
            self.assertEqual((r.method, r.uri, r.version), ("GET", "/note", "1.1"))
        r = http.Request()
        r.method = r.uri = r.version = None
        with self.assertRaises(UnpackError):
            r.unpack(b"ordinary note\r\n\r\n")
        self.assertEqual((r.method, r.uri, r.version), (None, None, None))

    def test_header_count_line_head_and_message_limits(self):
        start = b"GET / HTTP/1.1\r\n"
        raw = start + b"X-Note: note\r\n" * http.MAX_HEADERS + b"\r\n"
        self.assertEqual(len(http.Request(raw).headers["x-note"]), http.MAX_HEADERS)
        with self.assertRaises(http.LimitError):
            http.Request(start + b"X-Note: note\r\n" * (http.MAX_HEADERS + 1) + b"\r\n")
        header = b"X: " + b"a" * (http.MAX_LINE_BYTES - 5) + b"\r\n"
        self.assertEqual(
            len(http.Request(start + header + b"\r\n").headers["x"]), http.MAX_LINE_BYTES - 5
        )
        tight = b"X:" + b"a" * (http.MAX_LINE_BYTES - 4) + b"\r\n"
        self.assertEqual(
            len(http.Request(start + tight + b"\r\n").headers["x"]), http.MAX_LINE_BYTES - 4
        )
        with self.assertRaises(http.LimitError):
            http.Request(start + b"X: " + b"a" * (http.MAX_LINE_BYTES - 4) + b"\r\n\r\n")
        with self.assertRaises(http.LimitError):
            http.Request(start + (b"X: " + b"a" * 8000 + b"\r\n") * 9 + b"\r\n")
        prefix = b"POST / HTTP/1.1\r\nContent-Type: application/octet-stream\r\n\r\n"
        self.assertEqual(
            len(http.Request(prefix + bytes(http.MAX_MESSAGE_BYTES - len(prefix))).body),
            http.MAX_MESSAGE_BYTES - len(prefix),
        )
        with self.assertRaises(http.LimitError):
            http.Request(prefix + bytes(http.MAX_MESSAGE_BYTES - len(prefix) + 1))
        with self.assertRaises(http.LimitError):
            http.Request(b"POST / HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n")

    def test_serialization_is_bounded_and_errors_are_explicit(self):
        for obj in (
            http.Request(uri="a" * (http.MAX_LINE_BYTES + 1)),
            http.Request(headers={str(i): "x" for i in range(http.MAX_HEADERS + 1)}),
            http.Request(body=bytes(http.MAX_MESSAGE_BYTES)),
            http.Request(headers={"x": ["a" * http.MAX_LINE_BYTES]}),
        ):
            with self.assertRaises(http.LimitError):
                bytes(obj)
        for obj in (
            http.Request(uri="/café"),
            http.Request(version="2.0"),
            http.Request(headers={"Transfer-Encoding": "chunked"}),
        ):
            with self.assertRaises(PackError):
                bytes(obj)
        for obj in (
            http.Request(body="note"),
            http.Request(headers={"x": object()}),
            http.Request(method=1),
        ):
            with self.assertRaises(TypeError):
                bytes(obj)
        for operation in (
            lambda: http.Request(bytearray(b"note")),
            lambda: http.Request(unknown=1),
            lambda: http.Request(b"", b""),
            lambda: http.decode("note"),
        ):
            with self.assertRaises(TypeError):
                operation()

    def test_text_length_body_and_unread_tail_follow_reference_conventions(self):
        r = http.Response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\x00\xffTAIL")
        self.assertEqual((r.body, r.data), (b"\x00\xff", b"TAIL"))
        self.assertEqual(len(r), len(bytes(r)) - 1)
        self.assertTrue(str(r).endswith("\x00"))
        self.assertNotIn(b"TAIL", bytes(r))
        self.assertEqual(r.pack_hdr(), "content-length: 2\r\n")
        self.assertEqual(http.Request(b"GET / HTTP/1.1\r\n\r\n", method="POST").method, "GET")
        a, b = http.Request(), http.Request()
        a.headers["x-note"] = "note"
        self.assertEqual(b.headers, {})

    def test_request_metadata_fields(self):
        r = http.Request(bytes.fromhex(F.cases()[0]["wire"]))
        demand = {
            "host": r.headers["host"],
            "path": r.uri,
            "body": r.body,
            "user-agent": r.headers["user-agent"],
            "version": r.version,
            "method": r.method,
        }
        self.assertEqual(
            demand,
            {
                "host": "example.test",
                "path": "/note?q=1",
                "body": b"",
                "user-agent": "offline-note/1",
                "version": "1.1",
                "method": "GET",
            },
        )

    def test_header_field_validation_before_rendering(self):
        for name in ("Note", "x_note", "note!", "x-note"):
            self.assertEqual(
                http.Request(headers={name: "ordinary value"}).pack_hdr(),
                f"{name}: ordinary value\r\n",
            )
        for name in ("", "note name", "note:", "note/name", "noté"):
            with self.assertRaises(PackError):
                http.Request(headers={name: "ordinary"}).pack_hdr()
        for code in (0, 9, 10, 13, 31, 127):
            for value in (chr(code), [chr(code)]):
                with self.assertRaises(PackError):
                    http.Request(headers={"x-note": value}).pack_hdr()
            with self.assertRaises(PackError):
                bytes(http.Response(reason=chr(code)))
        with self.assertRaises(http.LimitError) as result:
            bytes(http.Request(body=bytes(http.MAX_MESSAGE_BYTES)))
        self.assertNotIsInstance(result.exception, UnpackError)

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
