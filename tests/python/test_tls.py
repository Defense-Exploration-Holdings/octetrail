"""SSL and TLS records and handshakes on dpkt's vectors and generated offline bytes."""

import importlib.util
import subprocess
import sys
import time
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

import octetrail
from octetrail import NeedData, UnpackError, ip, ssl, ssl_ciphersuites, tcp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("tls_fixture", ROOT / "tools/tls_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class TlsTests(unittest.TestCase):
    def test_every_case_runs_and_known_vectors_parse(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(F.cases()))
        for name in ("record_dpkt", "handshake_client_dpkt", "handshake_server_dpkt", "multi_dpkt"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_dpkt_client_hello_vector(self):
        raw = bytes.fromhex(F.CLIENT_HELLO)
        message = ssl.TLSHandshake(raw)
        hello = message.data
        self.assertIsInstance(hello, ssl.TLSClientHello)
        self.assertEqual((hello.version, len(hello.session_id)), (0x301, 32))
        self.assertEqual(len(hello.ciphersuites), 41)
        self.assertEqual(hello.compression_methods, (0,))
        self.assertEqual([k for k, _ in hello.extensions], [0, 10, 11, 35, 13172])
        self.assertTrue(raw.startswith(bytes(message)))
        self.assertEqual(len(message), 413)

    def test_dpkt_server_hello_vector_and_deprecated_names(self):
        hello = ssl.TLSHandshake(bytes.fromhex(F.SERVER_HELLO)).data
        self.assertEqual(hello.version, 0x301)
        self.assertEqual(hello.ciphersuite.code, 0x0002)
        self.assertEqual(hello.compression_method, 0)
        self.assertEqual(hello.extensions, [(0xFF01, b"\x00")])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.assertIs(hello.cipher_suite, hello.ciphersuite)
            self.assertEqual(hello.compression, 0)
        self.assertEqual(len(caught), 2)
        self.assertIn("deprecated", str(caught[0].message))

    def test_records_runs_and_multi_factory(self):
        record = ssl.TLSRecord(b"\x17\x03\x01\x00\x08abcdefghzzzz")
        self.assertEqual((record.data, record.length), (b"abcdefgh", 8))
        self.assertEqual(bytes(record), b"\x17\x03\x01\x00\x08abcdefgh")
        with self.assertRaises(NeedData):
            ssl.TLSRecord(b"\x17\x03\x01\x00\x08abc")
        run = ssl.TLS(F.record(22, b"ab") + F.record(23, b"cde"))
        self.assertEqual([r.type for r in run.records], [22, 23])
        with self.assertRaises(NeedData):
            ssl.TLS(F.record(22, b"ab") + F.record(23, b"cde")[:6])
        raw = bytes.fromhex(
            "1703010010" + "aa" * 16 + "1703010010" + "bb" * 16 + "1703010010" + "cc" * 4
        )
        records, consumed = ssl.tls_multi_factory(raw)
        self.assertEqual((len(records), consumed), (2, 42))
        self.assertEqual(records[1].data, b"\xbb" * 16)
        with self.assertRaises(ssl.SSL3Exception) as result:
            ssl.tls_multi_factory(F.record(22, b"ab") + F.record(22, b"cd", b"\x09\x09"))
        self.assertIn("Bad TLS version", str(result.exception))
        self.assertEqual(ssl.tls_multi_factory(b""), ([], 0))

    def test_certificates_extensions_and_variable_arrays(self):
        certs = F.var(3, F.var(3, b"cert one") + F.var(3, b"two"))
        self.assertEqual(ssl.TLSCertificate(certs).certificates, [b"cert one", b"two"])
        with self.assertRaises(NeedData):
            ssl.TLSCertificate(certs[:9])
        self.assertEqual(ssl.parse_variable_array(b"\x05abcdefg", 1), (b"abcde", 6))
        self.assertEqual(ssl.parse_variable_array(b"\x00\x00\x02xyz", 3), (b"xy", 5))
        found = ssl.parse_extensions(F.var(2, b"\x00\x0a" + F.var(2, b"abc") + b"\xff\xff"))
        self.assertEqual(found[0], (10, b"abc"))

    def test_handshake_dispatch_and_unknown_type(self):
        self.assertIsInstance(ssl.TLSHandshake(F.handshake(20, b"verify")).data, ssl.TLSFinished)
        with self.assertRaises(ssl.SSL3Exception) as result:
            ssl.TLSHandshake(F.handshake(3, b"x"))
        self.assertIsInstance(result.exception, UnpackError)
        self.assertEqual(str(result.exception), "Unknown or invalid handshake type 3")
        for raw in (b"\x01\x00", F.handshake(1, F.hello())[:20]):
            with self.assertRaises(NeedData):
                ssl.TLSHandshake(raw)

    def test_ssl2_records_and_missing_pad_byte(self):
        padded = ssl.SSL2(b"\x00\x03\x02msgpdtail")
        self.assertEqual(
            (padded.len, padded.msg, padded.pad, padded.data), (3, b"msg", b"pd", b"tail")
        )
        self.assertIsInstance(ssl.SSLFactory(b"\x80\x03abcrest"), ssl.SSL2)
        self.assertIsInstance(ssl.SSLFactory(F.record(21, b"\x01\x00")), ssl.TLSRecord)
        with self.assertRaises(ssl.SSL2IndexError) as result:
            ssl.SSL2(b"\x40\x02")
        self.assertIsInstance(result.exception, UnpackError)
        self.assertIsInstance(result.exception, IndexError)
        self.assertEqual(str(result.exception), "index out of range")

    def test_ciphersuite_table(self):
        suite = ssl_ciphersuites.BY_CODE[0xC02B]
        self.assertEqual(suite.name, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
        self.assertTrue(suite.pfs and suite.aead)
        self.assertEqual(len(ssl_ciphersuites.CIPHERSUITES), 351)
        self.assertEqual(ssl_ciphersuites.get_unknown_ciphersuite(0x1234).code, 0x1234)

    def test_tls_stays_opaque_in_transport(self):
        raw = F.record(22, F.handshake(2, F.hello(False)))
        decoded = ip.IP(bytes(ip.IP(p=6, data=tcp.TCP(dport=443, data=raw))))
        self.assertEqual(decoded.data.data, raw)

    def test_long_lists_parse_in_linear_time(self):
        extensions = F.var(2, b"\x00\x01\x00\x00" * 16383)
        certificates = F.var(3, b"\x00\x00\x00" * 200000)
        start = time.perf_counter()
        self.assertEqual(len(ssl.parse_extensions(extensions)), 16383)
        self.assertEqual(len(ssl.TLSCertificate(certificates).certificates), 200000)
        self.assertLess(time.perf_counter() - start, 5)

    def test_native_errors_propagate_unchanged(self):
        for error in (MemoryError("allocation"), ValueError("caller")):
            with (
                patch.object(ssl._native, "_tls_records", side_effect=error),
                self.assertRaises(type(error)) as result,
            ):
                ssl.TLS(F.record(22, b"ab"))
            self.assertIs(result.exception, error)

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
