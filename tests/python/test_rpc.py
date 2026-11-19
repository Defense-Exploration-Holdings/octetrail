"""RPC calls and replies parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, UnpackError, rpc

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("rpc_fixture", ROOT / "tools/rpc_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
RPC = rpc.RPC


def case(name):
    return bytes.fromhex(F.cases()[name])


class RpcTests(unittest.TestCase):
    def test_call(self):
        raw = case("call_unix")
        message = RPC(raw)
        self.assertIsInstance(message, Packet)
        self.assertIs(message.data, message.call)
        call = message.call
        self.assertEqual((call.prog, call.vers, call.proc), (100003, 3, 1))
        self.assertEqual(call.cred.flavor, rpc.AUTH_UNIX)
        self.assertEqual(call.verf.data, b"")
        self.assertEqual(call.data, b"\x00\x00\x00\x01")
        self.assertEqual(bytes(call), raw[8:])
        self.assertEqual(bytes(message), raw)

    def test_replies(self):
        accept = RPC(case("reply_prog_mismatch")).reply.accept
        self.assertEqual((accept.stat, accept.low, accept.high, accept.data), (2, 2, 4, b"tail"))
        reject = RPC(case("reply_auth_error")).reply.reject
        self.assertEqual((reject.stat, reject.why), (rpc.AUTH_ERROR, 5))
        for name in ("reply_success", "reply_rpc_mismatch", "reply_prog_mismatch"):
            self.assertEqual(bytes(RPC(case(name))), case(name))

    def test_errors(self):
        for name in ("call_cred_cut", "call_short", "short"):
            with self.assertRaises(NeedData):
                RPC(case(name))
        for name in ("reply_prog_mismatch_cut", "reply_reject_cut"):
            with self.assertRaises(UnpackError):
                RPC(case(name))

    def test_xdr_lists(self):
        class Entry(Packet):
            __hdr__ = (("n", "I", 0),)

        packed = rpc.pack_xdrlist(Entry(n=1), Entry(n=2))
        found = rpc.unpack_xdrlist(Entry, b"\x00\x00\x00\x01" + packed)
        self.assertEqual([e.n for e in found], [1, 2])
        with self.assertRaises(UnpackError):
            rpc.unpack_xdrlist(RPC.Auth, F.u32(2))

    def test_driver_has_no_declared_differences(self):
        self.assertEqual(F.DECLARED, {})


if __name__ == "__main__":
    unittest.main()
