"""RPC messages run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same calls and replies, builds them from keywords,
packs them again and reads XDR lists. OctetRail must match dpkt
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


def u32(*values):
    return b"".join(v.to_bytes(4, "big") for v in values)


def auth(flavor=0, body=b""):
    return u32(flavor, len(body)) + body


UNIX_CRED = auth(1, u32(0x5F3A, 4) + b"host" + u32(0, 0, 1, 0))


def cases():
    """Hex by name."""
    found = {
        "call_null": u32(7, 0, 2, 100000, 2, 3) + auth() + auth() + b"args",
        "call_unix": u32(8, 0, 2, 100003, 3, 1) + UNIX_CRED + auth() + b"\x00\x00\x00\x01",
        "call_cred_cut": u32(9, 0, 2, 1, 1, 1) + u32(1, 40) + b"short",
        "call_no_verf": u32(9, 0, 2, 1, 1, 1) + auth(),
        "call_short": u32(9, 0, 2, 1),
        "reply_success": u32(7, 1, 0) + auth() + u32(0) + b"result",
        "reply_prog_mismatch": u32(7, 1, 0) + auth() + u32(2, 2, 4) + b"tail",
        "reply_prog_mismatch_cut": u32(7, 1, 0) + auth() + u32(2, 2),
        "reply_garbage": u32(7, 1, 0) + auth() + u32(4) + b"left",
        "reply_accept_short": u32(7, 1, 0) + auth(),
        "reply_rpc_mismatch": u32(7, 1, 1, 0, 2, 2) + b"tail",
        "reply_auth_error": u32(7, 1, 1, 1, 5),
        "reply_reject_other": u32(7, 1, 1, 9) + b"x",
        "reply_reject_cut": u32(7, 1, 1, 0, 2),
        "reply_other_stat": u32(7, 1, 5) + b"opaque",
        "other_dir": u32(7, 2) + b"opaque",
        "header_only": u32(7, 0),
        "short": b"\x00\x00\x00\x07\x00",
    }
    return {k: v.hex() for k, v in found.items()}


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
    found["fields"] = {
        k: snapshot(v) if hasattr(v, "__hdr__") else repr(v)
        for k, v in sorted(vars(packet).items())
        if k[0] != "_"
    }
    return found


def constructed(package):
    rpc = package.rpc
    RPC = rpc.RPC

    def built_call():
        call = RPC.Call(prog=100000, vers=2, proc=4)
        call.cred = RPC.Auth(flavor=rpc.AUTH_UNIX, data=b"cred")
        message = RPC(xid=5, dir=rpc.CALL, data=call)
        return [bytes(message).hex(), len(message), len(call)]

    def built_replies():
        accept = RPC.Reply.Accept(stat=rpc.PROG_MISMATCH)
        accept.verf, accept.low, accept.high, accept.data = RPC.Auth(), 1, 3, b""
        reject = RPC.Reply.Reject(stat=rpc.AUTH_ERROR)
        reject.why, reject.data = 2, b""
        mismatch = RPC.Reply.Reject(stat=rpc.RPC_MISMATCH)
        mismatch.low, mismatch.high, mismatch.data = 2, 2, b""
        found = []
        for part in (accept, reject, mismatch, RPC.Reply.Reject(stat=7)):
            found.append([bytes(part).hex(), len(part)])
        return found

    xdr = b"\x00\x00\x00\x01" + auth(1, b"ab") + b"\x00\x00\x00\x01" + auth(0) + bytes(4)
    return {
        "default_rpc": attempt(lambda: snapshot(RPC())),
        "default_auth": attempt(lambda: snapshot(RPC.Auth())),
        "default_call": attempt(lambda: snapshot(RPC.Call())),
        "default_reply": attempt(lambda: snapshot(RPC.Reply())),
        "default_accept": attempt(lambda: [repr(RPC.Reply.Accept()), bytes(RPC.Reply.Accept())]),
        "default_reject": attempt(lambda: snapshot(RPC.Reply.Reject())),
        "built_call": attempt(built_call),
        "built_replies": attempt(built_replies),
        "xdrlist": attempt(lambda: [snapshot(a) for a in rpc.unpack_xdrlist(RPC.Auth, xdr)]),
        "xdrlist_empty": attempt(lambda: rpc.unpack_xdrlist(RPC.Auth, b"")),
        "xdrlist_invalid": attempt(lambda: rpc.unpack_xdrlist(RPC.Auth, u32(2))),
        "xdrlist_cut": attempt(lambda: rpc.unpack_xdrlist(RPC.Auth, u32(1) + u32(0))),
        "pack_xdrlist": attempt(lambda: rpc.pack_xdrlist(RPC.Auth(data=b"a"), RPC.Auth())),
        "pack_xdrlist_empty": attempt(lambda: rpc.pack_xdrlist()),
        "auth_unpack_direct": attempt(lambda: RPC.Auth().unpack(u32(0) + b"\x00")),
        "accept_unpack_direct": attempt(lambda: RPC.Reply.Accept().unpack(auth())),
        "bytearray": attempt(lambda: snapshot(RPC(bytearray(bytes.fromhex(cases()["call_unix"]))))),
        "constants": attempt(
            lambda: [
                rpc.CALL,
                rpc.REPLY,
                rpc.AUTH_NONE,
                rpc.AUTH_NULL,
                rpc.AUTH_UNIX,
                rpc.AUTH_SHORT,
                rpc.AUTH_DES,
                rpc.MSG_ACCEPTED,
                rpc.MSG_DENIED,
                rpc.SUCCESS,
                rpc.PROG_UNAVAIL,
                rpc.PROG_MISMATCH,
                rpc.PROC_UNAVAIL,
                rpc.GARBAGE_ARGS,
                rpc.SYSTEM_ERR,
                rpc.RPC_MISMATCH,
                rpc.AUTH_ERROR,
            ]
        ),
    }


def exercise(package):
    return {
        "cases": {
            name: attempt(lambda h=h: snapshot(package.rpc.RPC(bytes.fromhex(h))))
            for name, h in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".rpc").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/rpc.py")).resolve(),
        "unverified RPC module origin",
    )
    package.rpc = importlib.import_module(module + ".rpc")
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. There are none.
# OctetRail fixes dpkt here (a call packs its data once, and auth bodies are padded). These keys are not compared;
# tests/python checks the fixed results.
FIXED = {
    "cases.call_null",
    "cases.call_unix",
    "constructed.bytearray",
    "constructed.pack_xdrlist",
}

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
        wrong = sorted(
            k
            for k in reference
            if k not in FIXED and report.get(k) != DECLARED.get(k, reference[k])
        )
        C.require(not wrong, "RPC mismatch " + module + v + ": " + ", ".join(wrong))
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
                "fixed_dpkt_bugs": sorted(FIXED),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
