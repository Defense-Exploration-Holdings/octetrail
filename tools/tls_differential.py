"""SSL and TLS records and handshakes run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same records, record runs, handshakes, hellos,
certificate lists and SSLv2 records, including dpkt's own test vectors, and
packs them again. OctetRail must match dpkt 1.9.8 on every observation except
the declared ones; the keys where 1.9.6 differs are listed.
"""

import argparse
import importlib
import importlib.metadata
import importlib.util
import json
import struct
import subprocess
import sys
import warnings

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

# dpkt's TestClientHello and TestServerHello vectors, taken from Wireshark.
CLIENT_HELLO = (
    "0100019903015008220ce5e0e78b6891afe204498c9363feffbe03235a2d9e05b7d990eb708d"
    "2009bc0192e008e6fa8fe47998fca91311ba30ddde14a9587dc674b11c3d3e5ed1005200ffc0"
    "0ac0140088008700390038c00fc00500840035c007c009c011c0130045004400330032c00cc0"
    "0ec002c0040096004100050004002fc008c01200160013c00dc003000ac006c010c00bc00100"
    "020001010000fc0000000e000c0000096c6f63616c686f7374000a0008000600170018001900"
    "0b00020100002300d0a50b2e9f618a9ea9bf493ef49b421835cd2f6b05bbe1179d8edf70d58c"
    "33d656e8696d36d7e7e0b9d3ecc0e4de339552fa06c64c0fcb550a334bc43944e2739ca342d1"
    "5a9ebbe981ac87a0d38160507d47af09bdc16c5f0ee4cdceea551539382333226048a026d3a9"
    "0a0535f4a64236467db8fee22b041af986ad0f253bc369137cd8d8cd061925461d7f4d7895ca"
    "9a4181ab554dad50360ac31860e971483877c9335ac1300c5e78f3e56f3b8e0fc16358fcacee"
    "fd5c8d8aaae7b35be116f8832856ca61144fcdd95e071b94d0cf7233740000ffffffffffffff"
    "ff"
)
SERVER_HELLO = (
    "0200004d03015008220c8ec43c5462315a7c99f5d5b6bff009ad285b51dc18485f352e9fdecd2009"
    "bc0192e008e6fa8fe47998fca91311ba30ddde14a9587dc674b11c3d3e5ed10002000005ff01000100"
)


def var(lenbytes, data):
    return len(data).to_bytes(lenbytes, "big") + data


def handshake(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def record(kind, body, version=b"\x03\x03"):
    return bytes([kind]) + version + struct.pack(">H", len(body)) + body


def hello(client=True, session=b"", suites=(0x2F,), extensions=None, odd=False):
    raw = b"\x03\x03" + bytes(range(32)) + var(1, session)
    if client:
        codes = b"".join(struct.pack(">H", c) for c in suites) + (b"\x01" if odd else b"")
        raw += var(2, codes) + var(1, b"\x00")
    else:
        raw += struct.pack(">HB", suites[0], 0)
    if extensions is not None:
        raw += var(2, b"".join(struct.pack(">H", k) + var(2, d) for k, d in extensions))
    return raw


def cases():
    """(target, hex) by name."""
    sni = [(0, b"\x00\x0c\x00\x00\x09localhost"), (0xFF01, b"\x00")]
    certs = var(3, var(3, b"cert one") + var(3, b"two"))
    found = {
        "record_dpkt": ("record", b"\x17\x03\x01\x00\x08abcdefghzzzzzzzzzzz"),
        "record_short": ("record", b"\x17\x03\x01\x00\x08abc"),
        "record_header_short": ("record", b"\x17\x03"),
        "change_cipher_spec": ("ccs", b"\x01"),
        "alert": ("alert", b"\x02\x28"),
        "handshake_hello_request": ("handshake", b"\x00\x00\x00\x01\xff"),
        "handshake_client_dpkt": ("handshake", bytes.fromhex("".join(CLIENT_HELLO))),
        "handshake_server_dpkt": ("handshake", bytes.fromhex("".join(SERVER_HELLO))),
        "handshake_client_sni": (
            "handshake",
            handshake(1, hello(True, b"sess", (0xC02B, 0x1234), sni)),
        ),
        "handshake_server_ext": (
            "handshake",
            handshake(2, hello(False, bytes(32), (0x1234,), sni)),
        ),
        "handshake_certificate": ("handshake", handshake(11, certs)),
        "handshake_certificate_short": ("handshake", handshake(11, certs[:9])),
        "handshake_finished": ("handshake", handshake(20, b"verify")),
        "handshake_unknown_type": ("handshake", handshake(3, b"x")),
        "handshake_short_body": ("handshake", handshake(1, hello())[:20]),
        "handshake_header_short": ("handshake", b"\x01\x00"),
        "client_odd_suites": ("client", hello(True, odd=True)),
        "client_short_session": ("client", hello(True)[:34] + b"\x05ab"),
        "client_no_extensions": ("client", hello(True) + b"\x00\x00"),
        "client_extension_cut": ("client", hello(True, extensions=sni)[:-3]),
        "client_fixed_short": ("client", b"\x03\x03" + bytes(10)),
        "server_short": ("server", hello(False)[:36]),
        "server_fixed_short": ("server", b"\x03\x03"),
        "certificate_empty": ("certificate", b"\x00\x00\x00"),
        "certificate_short": ("certificate", b"\x00\x00"),
        "tls_two_records": ("tls", record(22, b"ab") + record(23, b"cde")),
        "tls_short_record": ("tls", record(22, b"ab") + record(23, b"cde")[:6]),
        "tls_header_only": ("tls", b"\x16\x03\x01\x00\x00"),
        "multi_dpkt": (
            "multi",
            bytes.fromhex(
                "1703010010" + "aa" * 16 + "1703010010" + "bb" * 16 + "1703010010" + "cc" * 4
            ),
        ),
        "multi_bad_version": ("multi", record(22, b"ab") + record(22, b"cd", b"\x09\x09")),
        "multi_empty": ("multi", b""),
        "factory_tls": ("factory", record(21, b"\x01\x00")),
        "factory_ssl2": ("factory", b"\x80\x03abcrest"),
        "ssl2_long": ("ssl2", b"\x80\x03abcrest"),
        "ssl2_padded": ("ssl2", b"\x00\x03\x02msgpdtail"),
        "ssl2_no_pad_byte": ("ssl2", b"\x40\x02"),
        "extensions": ("extensions", var(2, b"\x00\x0a" + var(2, b"abc") + b"\xff\xff")),
        "extensions_cut": ("extensions", b"\x00\x09\x00\x0a\x00"),
        "variable_1": ("variable1", b"\x05ab"),
        "variable_3": ("variable3", b"\x00\x00\x02xyz"),
        "variable_short": ("variable2", b"\x00"),
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
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            value = action()
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}
    if caught:
        return {"value": as_json(value), "warnings": [str(w.message) for w in caught]}
    return as_json(value)


def snapshot(packet):
    found = {"class": type(packet).__name__, "repr": repr(packet)}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    for name in ("records",):
        if hasattr(packet, name):
            found[name] = [repr(r) for r in getattr(packet, name)]
    data = getattr(packet, "data", None)
    if data is not None and not isinstance(data, (bytes, str)):
        found["data_class"] = type(data).__name__
        found["data_fields"] = {k: repr(v) for k, v in sorted(vars(data).items())}
    return found


def parse(ssl, target, raw):
    def run():
        if target == "multi":
            msgs, used = ssl.tls_multi_factory(raw)
            return {"records": [repr(m) for m in msgs], "used": used}
        if target == "extensions":
            return repr(ssl.parse_extensions(raw))
        if target.startswith("variable"):
            return repr(ssl.parse_variable_array(raw, int(target[-1])))
        cls = {
            "record": ssl.TLSRecord,
            "ccs": ssl.TLSChangeCipherSpec,
            "alert": ssl.TLSAlert,
            "handshake": ssl.TLSHandshake,
            "client": ssl.TLSClientHello,
            "server": ssl.TLSServerHello,
            "certificate": ssl.TLSCertificate,
            "tls": ssl.TLS,
            "factory": ssl.SSLFactory,
            "ssl2": ssl.SSL2,
        }[target]
        return snapshot(cls(raw))

    return attempt(run)


def constructed(ssl):
    r = {}
    for name in (
        "TLSRecord",
        "TLSHandshake",
        "TLSClientHello",
        "TLSServerHello",
        "TLSCertificate",
        "TLSAlert",
        "TLSChangeCipherSpec",
        "TLSHelloRequest",
        "TLS",
        "SSL2",
    ):
        r["default_" + name] = attempt(lambda name=name: snapshot(getattr(ssl, name)()))
    r["record_fields"] = attempt(
        lambda: snapshot(
            ssl.TLSRecord(type=23, version=0x0303, length=99, data=b"app", encrypted=True)
        )
    )
    r["handshake_fields"] = attempt(
        lambda: snapshot(ssl.TLSHandshake(type=20, length_bytes=b"\x00\x00\x02", data=b"ok"))
    )
    server = ssl.TLSHandshake(bytes.fromhex(SERVER_HELLO)).data
    r["deprecated"] = attempt(lambda: [repr(server.cipher_suite), server.compression])
    server.version = 0x0302
    r["server_repacked"] = attempt(lambda: bytes(server).hex())
    client = ssl.TLSHandshake(bytes.fromhex("".join(CLIENT_HELLO))).data
    r["client_suites"] = attempt(
        lambda: [
            [c.code, c.name, c.kx, c.auth, c.mac_size, c.block_size, c.pfs, c.aead]
            for c in client.ciphersuites
        ]
    )
    r["client_extensions"] = attempt(lambda: repr(client.extensions))
    r["record_types"] = sorted((k, v.__name__) for k, v in ssl.RECORD_TYPES.items())
    r["handshake_types"] = sorted((k, n, c.__name__) for k, (n, c) in ssl.HANDSHAKE_TYPES.items())
    r["versions"] = [
        ssl.SSL3_V,
        ssl.TLS12_V,
        sorted(ssl.SSL3_VERSION_BYTES),
        ssl.ssl3_versions_str[0x0303],
    ]
    r["alerts"] = [
        len(ssl.alert_description_str),
        ssl.alert_level_str[2],
        ssl.TLS1_AD_UNKNOWN_PSK_IDENTITY,
    ]
    cs = importlib.import_module(ssl.__name__.rsplit(".", 1)[0] + ".ssl_ciphersuites")
    r["ciphersuites"] = attempt(
        lambda: [
            len(cs.CIPHERSUITES),
            repr(cs.BY_CODE[0xC02B]),
            repr(cs.BY_NAME("TLS_RSA_WITH_AES_128_CBC_SHA")),
            repr(cs.NULL_SUITE),
            repr(cs.get_unknown_ciphersuite(0x1234)),
            [repr(s) for s in cs.CIPHERSUITES],
        ]
    )
    r["app_data"] = attempt(lambda: [ssl.TLSAppData("note"), isinstance(ssl.TLSAppData("n"), str)])
    return as_json(r)


def exercise(package):
    ssl = package.ssl
    return {
        "cases": {name: parse(ssl, t, bytes.fromhex(h)) for name, (t, h) in cases().items()},
        "constructed": constructed(ssl),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for member in ("ssl", "ssl_ciphersuites"):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified TLS module origin",
        )
    return package


# Observations where OctetRail differs from 1.9.8 on purpose: parse errors stay
# UnpackError. SSL3Exception keeps its name and message, and an SSLv2 record
# without its padding byte raises SSL2IndexError, an UnpackError and IndexError.
DECLARED = {
    "cases.ssl2_no_pad_byte": {"error": "SSL2IndexError", "message": "index out of range"},
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
        C.require(not wrong, "TLS mismatch " + module + v + ": " + ", ".join(wrong))
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
