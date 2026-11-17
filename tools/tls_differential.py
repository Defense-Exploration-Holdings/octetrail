"""Independent benign TLS envelopes and passive ServerHello metadata fixtures."""

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
RANDOM = bytes(range(32))
SESSION = b"note"


def record(kind, version, data):
    return bytes((kind,)) + version.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def handshake(kind, data):
    return bytes((kind,)) + len(data).to_bytes(3, "big") + data


def hello(session=SESSION, extensions=None, cipher=0x2F):
    tail = bytes((len(session),)) + session + cipher.to_bytes(2, "big") + b"\0"
    if extensions is not None:
        raw = b"".join(k.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v for k, v in extensions)
        tail += len(raw).to_bytes(2, "big") + raw
    return b"\x03\x03" + RANDOM + tail


def cases():
    rows = []
    for version in (0x300, 0x301, 0x302, 0x303):
        rows.append(
            {
                "id": f"record-{version}",
                "kind": "record",
                "wire": record(23, version, b"note").hex(),
                "type": 23,
                "version": version,
                "payload": b"note".hex(),
            }
        )
    for kind, data in (
        (20, b"\1"),
        (21, b"\1\0"),
        (22, handshake(2, hello())),
        (23, b"\0\xffnote"),
        (42, b"note"),
        (23, b""),
    ):
        rows.append(
            {
                "id": f"record-type-{kind}-{len(data)}",
                "kind": "record",
                "wire": record(kind, 0x303, data).hex(),
                "type": kind,
                "version": 0x303,
                "payload": data.hex(),
            }
        )
    for name, session, extensions, cipher in (
        ("hello", SESSION, None, 0x2F),
        ("empty-session", b"", None, 0x2F),
        ("extensions", SESSION, [(43, b"\x03\x04"), (65000, b"note")], 0x2F),
        ("empty-extensions", SESSION, [], 0x2F),
        ("unknown-cipher", SESSION, None, 0xFF00),
    ):
        rows.append(
            {
                "id": name,
                "kind": "hello",
                "wire": hello(session, extensions, cipher).hex(),
                "session": session.hex(),
                "extensions": None if extensions is None else [[k, v.hex()] for k, v in extensions],
                "cipher": cipher,
            }
        )
    for kind, body in ((2, hello()), (20, b"synthetic123"), (99, b"note\0\xff")):
        rows.append(
            {
                "id": f"handshake-{kind}",
                "kind": "handshake",
                "wire": handshake(kind, body).hex(),
                "type": kind,
                "payload": body.hex(),
            }
        )
    for name, wire, kind in (
        ("partial-record", record(23, 0x303, b"note")[:-1], "record"),
        ("partial-handshake", handshake(2, hello())[:-1], "handshake"),
        ("partial-hello", hello()[:-2], "hello"),
    ):
        rows.append({"id": name, "kind": kind, "wire": wire.hex(), "error": "NeedData"})
    return rows


def hello_expected(raw, session, extensions, cipher, provider, version):
    if provider == "dpkt" and version == "1.9.6" and cipher == 0xFF00:
        return {"error": "SSL3Exception"}
    return {
        "version": 0x303,
        "random": RANDOM.hex(),
        "session": session,
        "cipher": cipher,
        "compression": 0,
        "extensions": None if provider == "dpkt" and extensions == [] else extensions,
        "data": raw[34:].hex(),
        "wire": raw.hex(),
        "length": len(raw),
    }


def expected(case, provider, version):
    if "error" in case:
        return {"error": case["error"]}
    raw = bytes.fromhex(case["wire"])
    if case["kind"] == "record":
        return {
            "type": case["type"],
            "version": case["version"],
            "length": len(bytes.fromhex(case["payload"])),
            "data": case["payload"],
            "compressed": True,
            "encrypted": True,
            "wire": raw.hex(),
            "size": len(raw),
        }
    if case["kind"] == "hello":
        return hello_expected(
            raw, case["session"], case["extensions"], case["cipher"], provider, version
        )
    kind = case["type"]
    if kind == 99 and provider == "dpkt":
        return {"error": "SSL3Exception"}
    body = bytes.fromhex(case["payload"])
    state = (
        hello_expected(body, SESSION.hex(), None, 0x2F, provider, version)
        if kind == 2
        else {
            "opaque": body.hex(),
            "class": "TLSUnknownHandshake" if provider == "dpkt" else "bytes",
        }
    )
    return {
        "type": kind,
        "length": len(body),
        "length_bytes": len(body).to_bytes(3, "big").hex(),
        "data": state,
        "wire": raw.hex(),
        "size": len(raw),
    }


def hello_state(h, provider, version):
    code = (
        h.cipher_suite_code
        if provider == "octetrail"
        else (h.cipher_suite if version == "1.9.6" else h.ciphersuite).code
    )
    compression = (
        h.compression if provider == "dpkt" and version == "1.9.6" else h.compression_method
    )
    return {
        "version": h.version,
        "random": h.random.hex(),
        "session": h.session_id.hex(),
        "cipher": code,
        "compression": compression,
        "extensions": [[k, v.hex()] for k, v in h.extensions] if hasattr(h, "extensions") else None,
        "data": h.data.hex(),
        "wire": bytes(h).hex(),
        "length": len(h),
    }


def snapshot(message, kind, package, provider, version):
    if kind == "record":
        return {
            "type": message.type,
            "version": message.version,
            "length": message.length,
            "data": message.data.hex(),
            "compressed": message.compressed,
            "encrypted": message.encrypted,
            "wire": bytes(message).hex(),
            "size": len(message),
        }
    if kind == "hello":
        return hello_state(message, provider, version)
    if isinstance(message.data, package.ssl.TLSServerHello):
        state = hello_state(message.data, provider, version)
    else:
        state = {"opaque": bytes(message.data).hex(), "class": type(message.data).__name__}
    return {
        "type": message.type,
        "length": message.length,
        "length_bytes": message.length_bytes.hex(),
        "data": state,
        "wire": bytes(message).hex(),
        "size": len(message),
    }


def passive_metadata(package, raw):
    """Select passive fields from a complete supplied metadata envelope."""
    S = package.ssl
    try:
        record = S.TLSRecord(raw)
        parser = S.RECORD_TYPES.get(record.type)
        if parser is None:
            return None
        message = parser(record.data)
        if isinstance(message, S.TLSHandshake) and isinstance(message.data, S.TLSServerHello):
            return {"random": message.data.random.hex(), "session": message.data.session_id.hex()}
    except (package.UnpackError, S.SSL3Exception):
        return None
    return None


def review_checks(package, provider):
    S = package.ssl
    results = {}
    for label, data, count in (("count", b"note", 1031), ("byte", b"note" * 15000, 20)):
        frame = record(23, 0x303, data)
        source = frame * count
        offset, framed, batches = 0, [], []
        while offset < len(source):
            rows, used = S.tls_multi_factory(source[offset:])
            C.require(used > 0, "complete TLS batch must advance")
            if provider == "octetrail":
                C.require(
                    len(rows) <= S.MAX_RECORDS and used <= S.MAX_MESSAGE_BYTES,
                    "TLS per-call budgets",
                )
            C.require(
                b"".join(bytes(r) for r in rows) == source[offset : offset + used],
                "TLS incremental prefix bytes",
            )
            framed.extend(rows)
            offset += used
            batches.append(len(rows))
        C.require(len(framed) == count and offset == len(source), "TLS continuation coverage")
        C.require(bytes(S.TLSRecord(source)) == frame, "record prefix ignores backing-buffer size")
        results[label + "_records"] = count
        results[label + "_batches"] = batches
    short = handshake(20, b"note")
    backing = short + bytes(1024 * 1024 + 32)
    C.require(
        bytes(S.TLSHandshake(backing)) == short, "handshake prefix ignores backing-buffer size"
    )
    incomplete = bytes((20,)) + (1024 * 1024).to_bytes(3, "big")
    try:
        S.TLSHandshake(incomplete)
    except package.NeedData:
        pass
    else:
        raise ValueError("missing handshake data precedence")
    h = S.TLSHandshake(short)
    h.data = b"ok"
    C.require(bytes(h) == b"\x14\0\0\x04ok" and h.length == 4, "handshake retained declared length")
    r = S.TLSRecord()
    r.compressed = r.encrypted = False
    r.unpack(record(23, 0x303, b"note"))
    C.require(r.compressed and r.encrypted, "unpack reference flags")
    return results


def exercise(package, provider, version):
    S = package.ssl
    output = {}
    classes = {"record": S.TLSRecord, "handshake": S.TLSHandshake, "hello": S.TLSServerHello}
    for case in cases():
        try:
            obj = classes[case["kind"]](bytes.fromhex(case["wire"]))
        except (package.NeedData, S.SSL3Exception) as error:
            output[case["id"]] = {"error": type(error).__name__}
        else:
            output[case["id"]] = snapshot(obj, case["kind"], package, provider, version)
    constructors = 0
    for case in cases():
        if case["kind"] != "record" or "error" in case:
            continue
        r = S.TLSRecord(
            type=case["type"],
            version=case["version"],
            length=999,
            data=bytes.fromhex(case["payload"]),
        )
        C.require(
            bytes(r).hex() == case["wire"]
            and r.length == len(r.data)
            and not r.compressed
            and not r.encrypted,
            "TLS record independent constructor",
        )
        constructors += 1
    r = S.TLSRecord()
    C.require(
        bytes(r) == bytes(5) and len(r) == 5 and not r.compressed and not r.encrypted,
        "TLS default record",
    )
    r = S.TLSRecord(type=23, version=0x303, data=b"note")
    r.data = b"ok"
    C.require(
        bytes(r) == b"\x17\x03\x03\0\x04ok" and len(r) == 7, "TLS record retained length mutation"
    )
    h = S.TLSHandshake(handshake(2, hello()))
    h.data.random = bytes(reversed(range(32)))
    C.require(
        bytes(h) == handshake(2, b"\x03\x03" + bytes(reversed(range(32))) + hello()[34:]),
        "TLS fixed metadata mutation",
    )
    h.data.session_id = b"other"
    C.require(
        bytes(h) == handshake(2, b"\x03\x03" + bytes(reversed(range(32))) + hello()[34:]),
        "TLS raw variable tail precedence",
    )
    prefix = record(22, 0x303, handshake(2, hello()))
    partial = record(23, 0x303, b"note")[:-1]
    sequences = [
        b"",
        prefix,
        prefix + record(23, 0x303, b"note"),
        prefix + partial,
        b"\x17\x03\x03",
        partial,
    ]
    multi = []
    for raw in sequences:
        records, used = S.tls_multi_factory(raw)
        serialized = b"".join(bytes(r) for r in records)
        expected_used = (
            0
            if raw in (b"", b"\x17\x03\x03", partial)
            else len(prefix)
            if raw in (prefix, prefix + partial)
            else len(raw)
        )
        C.require(
            used == expected_used and serialized == raw[:expected_used],
            "TLS incremental independent framing",
        )
        multi.append({"used": used, "remaining": raw[used:].hex(), "records": len(records)})
    # Selected record/handshake metadata remains bytes at the API boundary.
    r = S.TLSRecord(prefix)
    C.require(r.type in S.RECORD_TYPES, "TLS selected record dispatch")
    wrapped = S.RECORD_TYPES[r.type](r.data)
    C.require(
        isinstance(wrapped, S.TLSHandshake) and isinstance(wrapped.data, S.TLSServerHello),
        "TLS selected metadata class path",
    )
    C.require(
        wrapped.data.random == RANDOM and wrapped.data.session_id == SESSION,
        "TLS benign passive metadata demand",
    )
    C.require(
        passive_metadata(package, prefix) == {"random": RANDOM.hex(), "session": SESSION.hex()},
        "TLS metadata demand",
    )
    for value in (
        prefix[:-1],
        record(23, 0x303, b"note"),
        record(22, 0x303, handshake(2, hello())[:-1]),
    ):
        C.require(
            passive_metadata(package, value) is None,
            "TLS incomplete or unrelated metadata selection",
        )
    return {
        "cases": output,
        "constructors": constructors,
        "defaults": 1,
        "mutations": 3,
        "multi": multi,
        "metadata_demand": 4,
        "record_dispatch_types": sorted(S.RECORD_TYPES),
        "review": review_checks(package, provider),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(package.ssl.__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/ssl.py")).resolve(),
        "unverified TLS origin",
    )
    return package


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
        print(json.dumps(exercise(provenance(a.module, a.version), a.module, a.version)))
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
            report["cases"] == {c["id"]: expected(c, module, v) for c in cases()},
            "TLS observation mismatch " + module + v,
        )
        C.require(
            report["constructors"] == 10
            and report["record_dispatch_types"]
            == ([22] if module == "octetrail" else [20, 21, 22, 23]),
            "TLS constructor/dispatch inventory mismatch",
        )
    print(
        json.dumps(
            {
                "fixtures": len(cases()),
                "shared_equal_cases": 17,
                "declared_fixture_differences": [
                    "empty-extensions",
                    "unknown-cipher",
                    "handshake-20",
                    "handshake-99",
                ],
                "constructors_per_provider": 10,
                "defaults_per_provider": 1,
                "mutations_per_provider": 3,
                "incremental_sequences_per_provider": 6,
                "passive_metadata_demand_per_provider": 4,
                "partial_record_dispatch_inventory": True,
                "providers": len(providers),
                "review_count_stream_records": 1031,
                "review_byte_stream_records": 20,
                "review_prefix_and_precedence_checks": 2,
                "review_stale_length_and_flags": 2,
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
