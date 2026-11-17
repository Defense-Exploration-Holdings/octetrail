"""Passive TLS framing and metadata on generated benign offline bytes."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import octetrail
from octetrail import NeedData, PackError, ip, ssl, tcp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("tls_fixture", ROOT / "tools/tls_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class TlsTests(unittest.TestCase):
    def test_independent_fields_bytes_defaults_constructors_and_mutation(self):
        report = F.exercise(octetrail, "octetrail", octetrail.__version__)
        self.assertEqual(
            report["cases"],
            {c["id"]: F.expected(c, "octetrail", octetrail.__version__) for c in F.cases()},
        )
        self.assertEqual(report["constructors"], 10)

    def test_metadata_demand_only_and_failed_recognition(self):
        raw = F.record(22, 0x303, F.handshake(2, F.hello()))
        self.assertEqual(
            F.passive_metadata(octetrail, raw),
            {"random": F.RANDOM.hex(), "session": F.SESSION.hex()},
        )
        for value in (
            raw[:-1],
            F.record(23, 0x303, b"note"),
            F.record(22, 0x303, F.handshake(2, F.hello())[:-1]),
        ):
            self.assertIsNone(F.passive_metadata(octetrail, value))

    def test_tls_is_explicit_and_does_not_change_transport_data(self):
        raw = F.record(22, 0x303, F.handshake(2, F.hello()))
        p = ip.IP(p=6, data=tcp.TCP(dport=443, data=raw))
        decoded = ip.IP(bytes(p))
        self.assertIsInstance(decoded.data, tcp.TCP)
        self.assertEqual(decoded.data.data, raw)
        self.assertIsInstance(ssl.TLSRecord(raw).data, bytes)
        self.assertEqual(ssl.TLSHandshake(ssl.TLSRecord(raw).data).data.session_id, b"note")

    def test_record_flags_ignored_constructor_length_and_stale_mutated_length(self):
        raw = F.record(23, 0x303, b"note")
        parsed = ssl.TLSRecord(raw, compressed=False, encrypted=False, type=99)
        self.assertEqual((parsed.type, parsed.compressed, parsed.encrypted), (23, True, True))
        constructed = ssl.TLSRecord(
            type=23, version=0x303, length=999, data=b"note", compressed=True
        )
        self.assertEqual(
            (constructed.length, constructed.compressed, constructed.encrypted), (4, True, False)
        )
        constructed.data = b"ok"
        self.assertEqual(bytes(constructed), b"\x17\x03\x03\x00\x04ok")
        self.assertEqual(constructed.pack_hdr(), b"\x17\x03\x03\x00\x04")
        self.assertEqual(len(constructed), 7)
        self.assertEqual(ssl.TLSRecord(raw + b"unused").data, b"note")

    def test_opaque_handshakes_and_extensions_preserve_exact_bytes(self):
        raw = F.handshake(99, b"\0\xffnote")
        message = ssl.TLSHandshake(raw + b"unused")
        self.assertIsInstance(message.data, bytes)
        self.assertEqual(bytes(message), raw)
        self.assertEqual(message.pack_hdr(), raw[:4])
        body = F.hello(extensions=[(65000, b"\0\xffnote")])
        message = ssl.TLSServerHello(body)
        self.assertEqual(message.extensions, [(65000, b"\0\xffnote")])
        self.assertEqual(bytes(message), body)
        self.assertEqual(message.pack_hdr(), body[:34])
        message.session_id = b"other"
        self.assertEqual(bytes(message), body)
        message.data = F.hello(session=b"next", extensions=[(65000, b"\0\xffnote")])[34:]
        self.assertEqual(ssl.TLSServerHello(bytes(message)).session_id, b"next")

    def test_partial_record_handshake_and_hello_raise_need_data(self):
        for operation in (
            lambda: ssl.TLSRecord(b"\x17\x03\x03"),
            lambda: ssl.TLSRecord(F.record(23, 0x303, b"note")[:-1]),
            lambda: ssl.TLSHandshake(F.handshake(2, F.hello())[:-1]),
            lambda: ssl.TLSServerHello(F.hello()[:-1]),
            lambda: ssl.TLSServerHello(F.hello(extensions=[(65000, b"note")])[:-1]),
        ):
            with self.assertRaises(NeedData):
                operation()

    def test_incremental_factory_version_recognition_and_progress_limits(self):
        empty = F.record(23, 0x303, b"")
        records, consumed = ssl.tls_multi_factory(empty * ssl.MAX_RECORDS)
        self.assertEqual((len(records), consumed), (ssl.MAX_RECORDS, 5 * ssl.MAX_RECORDS))
        records, consumed = ssl.tls_multi_factory(empty * (ssl.MAX_RECORDS + 1))
        self.assertEqual((len(records), consumed), (ssl.MAX_RECORDS, 5 * ssl.MAX_RECORDS))
        tail, used = ssl.tls_multi_factory((empty * (ssl.MAX_RECORDS + 1))[consumed:])
        self.assertEqual((len(tail), used), (1, 5))
        with self.assertRaises(ssl.SSL3Exception):
            ssl.tls_multi_factory(F.record(23, 0x304, b"note"))
        self.assertEqual(ssl.TLSRecord(F.record(23, 0x304, b"note")).version, 0x304)
        complete = F.record(23, 0x303, b"note")
        partial = complete[:-1]
        records, consumed = ssl.tls_multi_factory(complete + partial)
        self.assertEqual(
            (len(records), consumed, (complete + partial)[consumed:]), (1, len(complete), partial)
        )
        with self.assertRaises(ssl.ParseLimitError) as result:
            ssl.TLSServerHello(bytes(ssl.MAX_MESSAGE_BYTES + 1))
        self.assertIsInstance(result.exception, octetrail.UnpackError)
        self.assertIsInstance(result.exception, ValueError)

    def test_record_handshake_session_and_extension_size_boundaries(self):
        raw = F.record(23, 0x303, bytes(ssl.MAX_RECORD_DATA_BYTES))
        self.assertEqual(len(ssl.TLSRecord(raw).data), ssl.MAX_RECORD_DATA_BYTES)
        with self.assertRaises(ssl.LimitError):
            ssl.TLSRecord(data=bytes(ssl.MAX_RECORD_DATA_BYTES + 1))
        h = ssl.TLSHandshake(F.handshake(99, bytes(ssl.MAX_MESSAGE_BYTES - 4)))
        self.assertEqual(len(h), ssl.MAX_MESSAGE_BYTES)
        with self.assertRaises(ssl.LimitError):
            ssl.TLSHandshake(F.handshake(99, bytes(ssl.MAX_MESSAGE_BYTES - 3)))
        self.assertEqual(len(ssl.TLSServerHello(F.hello(session=bytes(32))).session_id), 32)
        with self.assertRaises(ssl.SSL3Exception) as result:
            ssl.TLSServerHello(F.hello(session=bytes(33)))
        self.assertIsInstance(result.exception, octetrail.UnpackError)
        self.assertNotIsInstance(result.exception, ValueError)
        self.assertEqual(
            len(
                ssl.TLSServerHello(
                    F.hello(extensions=[(65000, b"")] * ssl.MAX_EXTENSIONS)
                ).extensions
            ),
            ssl.MAX_EXTENSIONS,
        )
        with self.assertRaises(ssl.LimitError):
            ssl.TLSServerHello(F.hello(extensions=[(65000, b"")] * (ssl.MAX_EXTENSIONS + 1)))

    def test_pack_types_limits_and_programmer_errors_propagate(self):
        for value in (-1, 256, "note"):
            with self.assertRaises(PackError):
                bytes(ssl.TLSRecord(type=value))
        with self.assertRaises(TypeError):
            ssl.TLSRecord(data=bytearray(b"note"))
        with self.assertRaises(TypeError):
            ssl.TLSRecord(unknown=1)
        h = ssl.TLSHandshake(F.handshake(99, b"note"))
        h.length_bytes = b"\0"
        with self.assertRaises(PackError):
            bytes(h)
        s = ssl.TLSServerHello(F.hello())
        s.random = bytes(31)
        with self.assertRaises(PackError):
            bytes(s)
        r = ssl.TLSRecord()
        r.data = bytes(ssl.MAX_RECORD_DATA_BYTES + 1)
        with self.assertRaises(ssl.LimitError) as result:
            bytes(r)
        self.assertNotIsInstance(result.exception, octetrail.UnpackError)
        for error in (MemoryError("allocation"), ValueError("caller")):
            with (
                patch.object(ssl._native, "_tls_records", side_effect=error),
                self.assertRaises(type(error)) as result,
            ):
                ssl.tls_multi_factory(b"")
            self.assertIs(result.exception, error)

    def test_framed_limits_incremental_continuation_and_stale_handshake_length(self):
        report = F.review_checks(octetrail, "octetrail")
        self.assertEqual(report["count_records"], ssl.MAX_RECORDS + 7)
        self.assertEqual(report["byte_records"], 20)
        raw = bytes((20,)) + ssl.MAX_MESSAGE_BYTES.to_bytes(3, "big")
        with self.assertRaises(NeedData):
            ssl.TLSHandshake(raw)
        with self.assertRaises(ssl.ParseLimitError):
            ssl.TLSHandshake(raw + bytes(ssl.MAX_MESSAGE_BYTES))
        message = ssl.TLSHandshake(F.handshake(20, b"note"))
        message.data = b"ok"
        self.assertEqual((message.length, len(message)), (4, 6))
        self.assertEqual(bytes(message), b"\x14\0\0\x04ok")
        record = ssl.TLSRecord()
        record.compressed = record.encrypted = False
        record.unpack(F.record(23, 0x303, b"note"))
        self.assertTrue(record.compressed and record.encrypted)

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/tls_differential.py",
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
