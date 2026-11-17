"""Independent ordinary IPv6 fixtures, explicit differences and installed probes."""

import argparse
import importlib
import importlib.metadata
import importlib.util
import json
import struct
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

SRC = bytes.fromhex("20010db8000000000000000000000001")
DST = bytes.fromhex("20010db8000000000000000000000002")
MAC = bytes.fromhex("02aabbccddee02112233445586dd")


def fixture(name, protocol=6, payload=b"note", kinds=(), fragment=0, category="equal"):
    if protocol == 6:
        body = struct.pack("!HHIIBBHHH", 12345, 23456, 17, 18, 0x50, 0x18, 4096, 0, 0) + payload
    elif protocol == 17:
        body = struct.pack("!HHHH", 12345, 23456, 8 + len(payload), 0) + payload
    else:
        body = payload
    if protocol in (6, 17):
        checksum = C.checksum(SRC + DST + struct.pack("!I3xB", len(body), protocol) + body)
        offset = 16 if protocol == 6 else 6
        body = body[:offset] + struct.pack("!H", checksum) + body[offset + 2 :]
    extensions = []
    for index, kind in enumerate(kinds):
        nxt = kinds[index + 1] if index + 1 < len(kinds) else protocol
        if kind == 44:
            raw = struct.pack("!BBHI", nxt, 0, fragment, 17)
        elif kind == 51:
            raw = struct.pack("!BBHII", nxt, 1, 0, 17, 18)
        else:
            raw = bytes((nxt, 0)) + bytes(6)
        extensions.append([kind, raw.hex()])
    extension_bytes = b"".join(bytes.fromhex(x[1]) for x in extensions)
    plen = len(extension_bytes) + len(body)
    nxt = kinds[0] if kinds else protocol
    fixed = struct.pack("!IHBB16s16s", 0x61200345, plen, nxt, 31, SRC, DST)
    return {
        "id": name,
        "wire": (fixed + extension_bytes + body).hex(),
        "fields": [6, 18, 837, plen, nxt, 31, SRC.hex(), DST.hex(), protocol],
        "body": body.hex(),
        "extensions": extensions,
        "fragment": fragment,
        "category": category,
    }


def fixtures():
    cases = [
        fixture(f"{p}-{n}", p, payload)
        for p in (6, 17)
        for n, payload in enumerate((b"", b"x", b"ordinary note"))
    ]
    cases += [fixture("unknown", 253, b"opaque"), fixture("no-next", 59, b"")]
    cases += [
        fixture(name, p, b"note", kinds)
        for name, p, kinds in (
            ("hop", 17, (0,)),
            ("destination", 6, (60,)),
            ("passive-route", 17, (43,)),
            ("hop-destination", 6, (0, 60)),
            ("duplicate-destination", 17, (60, 60)),
            ("atomic", 6, (44,)),
        )
    ]
    cases.append(fixture("authentication-framing", 17, b"note", (51,), category="ah-serialization"))
    cases.append(
        fixture("first-fragment", 6, b"note", (44,), fragment=1, category="fragment-bytes")
    )
    short = fixture("short-declared-payload", 6, b"ordinary note", category="incomplete-bytes")
    short["wire"], short["body"] = short["wire"][:-6], short["body"][:-6]
    cases.append(short)
    short = fixture("short-extension", 253, b"", (0,), category="incomplete-extension")
    raw = bytearray.fromhex(short["wire"])
    raw[5] = 4
    raw = raw[:-4]
    short.update(wire=raw.hex(), body=raw[40:].hex(), extensions=[])
    short["fields"][3], short["fields"][-1] = 4, 0
    cases.append(short)
    zero = fixture("zero-length-with-data", 6, b"note", category="zero-length-bytes")
    raw = bytearray.fromhex(zero["wire"])
    raw[4:6] = bytes(2)
    zero["wire"], zero["fields"][3] = raw.hex(), 0
    cases.append(zero)
    return cases


def data_state(kind, raw):
    body = bytes.fromhex(raw)
    if kind == 6:
        return ["TCP", 12345, 23456, body[20:].hex(), int.from_bytes(body[16:18], "big")]
    if kind == 17:
        return ["UDP", 12345, 23456, body[8:].hex(), int.from_bytes(body[6:8], "big")]
    return ["bytes", raw]


def expected(case, module):
    category = case["category"]
    if category == "incomplete-extension" and module == "dpkt":
        return {"error": "NeedData"}
    raw = bytes.fromhex(case["wire"])
    opaque = case["fields"][-1] not in (6, 17) or (
        module == "octetrail"
        and category in ("fragment-bytes", "incomplete-bytes", "zero-length-bytes")
    )
    body = data_state(253 if opaque else case["fields"][-1], case["body"])
    if category == "ah-serialization" and module == "dpkt":
        raw += bytes.fromhex(case["body"])
    return {
        "fields": case["fields"],
        "data": body,
        "extensions": case["extensions"],
        "length": len(raw),
        "wire": raw.hex(),
    }


def snapshot(packet):
    data = packet.data
    if isinstance(data, bytes):
        body = ["bytes", data.hex()]
    else:
        body = [type(data).__name__, data.sport, data.dport, data.data.hex(), data.sum]
    nxt = packet.nxt
    extensions = []
    for ext in packet.all_extension_headers:
        extensions.append([nxt, bytes(ext)[: ext.length].hex()])
        nxt = ext.nxt
    return {
        "fields": [
            packet.v,
            packet.fc,
            packet.flow,
            packet.plen,
            packet.nxt,
            packet.hlim,
            packet.src.hex(),
            packet.dst.hex(),
            packet.p,
        ],
        "data": body,
        "extensions": extensions,
        "length": len(packet),
        "wire": bytes(packet).hex(),
    }


def ordinary_routed_capture(protocol):
    """Independent type-2 routing envelope with a capture-style absent checksum."""
    payload = b"local note"
    if protocol == 6:
        body = struct.pack("!HHIIBBHHH", 12345, 23456, 17, 18, 0x50, 0x18, 4096, 0, 0) + payload
    else:
        body = struct.pack("!HHHH", 12345, 23456, 8 + len(payload), 0) + payload
    route = bytes((protocol, 2, 2, 1)) + bytes(4) + bytes.fromhex("20010db8" + "00" * 11 + "44")
    fixed = struct.pack("!IHBB16s16s", 0x60000000, len(route) + len(body), 43, 31, SRC, DST)
    return fixed + route + body


def passive_capture_checks(package, module):
    observations = []
    for protocol in (6, 17):
        wire = ordinary_routed_capture(protocol)
        packet = package.ip6.IP6(wire)
        observed = bytes(packet)
        offset = 40 + 24 + (16 if protocol == 6 else 6)
        if module == "octetrail":
            C.require(observed == wire and packet.data.sum == 0, "unchanged passive capture bytes")
            C.require(
                bytes(package.ethernet.Ethernet(MAC + wire)) == MAC + wire,
                "unchanged nested passive bytes",
            )
            packet.data.data = b"other note"
            try:
                bytes(packet)
            except NotImplementedError:
                pass
            else:
                raise ValueError("changed unsupported checksum context accepted")
        else:
            C.require(observed != wire and packet.data.sum != 0, "reference fills missing checksum")
            C.require(
                observed[:offset] == wire[:offset] and observed[offset + 2 :] == wire[offset + 2 :],
                "reference ordinary routing frame retention",
            )
        observations.append(
            {
                "protocol": protocol,
                "wire": observed.hex(),
                "checksum": int.from_bytes(observed[offset : offset + 2], "big"),
            }
        )
    return observations


def exercise(package, module):
    output = {}
    v4 = C.encode({"kind": "opaque", "p": 253, "payload": "6e6f7465"})[14:]
    selected = package.raw.decode(v4) if module == "octetrail" else package.ip.IP(v4)
    C.require(
        (selected.v, selected.p, selected.data, bytes(selected)) == (4, 253, b"note", v4),
        "raw IPv4 selection",
    )
    for case in fixtures():
        try:
            packet = package.ip6.IP6(bytes.fromhex(case["wire"]))
        except package.UnpackError as error:
            output[case["id"]] = {"error": type(error).__name__}
        else:
            output[case["id"]] = snapshot(packet)
            if case["category"] == "equal":
                eth = package.ethernet.Ethernet(MAC + bytes.fromhex(case["wire"]))
                C.require(snapshot(eth.data) == expected(case, module), "Ethernet nested IPv6")
                C.require(bytes(eth) == MAC + bytes.fromhex(case["wire"]), "Ethernet exact bytes")
            if module == "octetrail":
                C.require(
                    snapshot(package.raw.decode(bytes.fromhex(case["wire"]))) == output[case["id"]],
                    "raw IPv6 dispatch",
                )
    constructed = []
    for proto in (6, 17):
        child = (
            package.tcp.TCP(
                sport=12345, dport=23456, seq=17, ack=18, flags=0x18, win=4096, data=b"note"
            )
            if proto == 6
            else package.udp.UDP(sport=12345, dport=23456, ulen=12, data=b"note")
        )
        packet = package.ip6.IP6(
            _v_fc_flow=0x61200345, plen=len(child), nxt=proto, hlim=31, src=SRC, dst=DST, data=child
        )
        wanted = fixture("constructor", proto, b"note")
        C.require(bytes(packet).hex() == wanted["wire"], "constructor checksum bytes")
        child.data = b"new note"
        child.sum = 0
        if proto == 17:
            child.ulen = len(child)
        packet.plen = len(packet) - 40
        wanted = fixture("mutated", proto, b"new note")
        C.require(bytes(packet).hex() == wanted["wire"], "mutation checksum bytes")
        packet.fc, packet.flow, packet.hlim = 20, 32, 33
        raw = bytearray.fromhex(wanted["wire"])
        raw[:4] = struct.pack("!I", (6 << 28) | (20 << 20) | 32)
        raw[7] = 33
        C.require(bytes(packet) == raw, "base bit-field mutation")
        constructed.append(bytes(packet).hex())
    child = package.udp.UDP(sport=1, dport=2, ulen=10, data=bytes.fromhex("ffd7"))
    zero = package.ip6.IP6(nxt=17, plen=10, src=bytes(16), dst=bytes(16), data=child)
    stored = 65535 if module == "octetrail" else 0
    wanted = struct.pack("!IHBB16s16s", 0x60000000, 10, 17, 0, bytes(16), bytes(16))
    wanted += struct.pack("!HHHH", 1, 2, 10, stored) + bytes.fromhex("ffd7")
    C.require(
        bytes(zero) == wanted and child.sum == stored, "explicit UDP zero-checksum difference"
    )
    return {
        "cases": output,
        "constructed_mutated": constructed,
        "zero_udp_checksum": stored,
        "passive_review": passive_capture_checks(package, module),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for suffix in ("ip6", "raw") if module == "octetrail" else ("ip6",):
        origin = Path(importlib.import_module(module + "." + suffix).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + suffix + ".py")).resolve(),
            "unverified IPv6 module origin",
        )
    return package


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
        print(json.dumps(exercise(provenance(args.module, args.version), args.module)))
        return
    C.require(
        args.oracle_196 and args.oracle_198 and args.python,
        "both pins and an installed provider are required",
    )
    version = tomllib.loads((C.ROOT / "pyproject.toml").read_text())["project"]["version"]
    reports = []
    for python, module, v in [
        (args.oracle_196, "dpkt", "1.9.6"),
        (args.oracle_198, "dpkt", "1.9.8"),
        *((p, "octetrail", version) for p in args.python),
    ]:
        result = subprocess.run(
            [python, "-B", "-I", "-O", __file__, "--probe", "--module", module, "--version", v],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        report = json.loads(result.stdout)
        C.require(
            report["cases"] == {c["id"]: expected(c, module) for c in fixtures()},
            "IPv6 observation mismatch " + module + v,
        )
        C.require(
            not reports or report["constructed_mutated"] == reports[0]["constructed_mutated"],
            "constructor/mutation mismatch",
        )
        reports.append(report)
    C.require(
        reports[0]["passive_review"] == reports[1]["passive_review"],
        "pinned passive checksum observations disagree",
    )
    print(
        json.dumps(
            {
                "fixtures": len(fixtures()),
                "equal_cases": sum(c["category"] == "equal" for c in fixtures()),
                "explicit_differences": [c["id"] for c in fixtures() if c["category"] != "equal"],
                "constructor_mutation_cases_per_provider": 2,
                "raw_ipv4_selection_cases_per_provider": 1,
                "udp_zero_checksum_difference": "OctetRail maps zero to ffff; both references retain zero",
                "passive_review_cases_per_provider": 2,
                "passive_reference_observations": reports[0]["passive_review"],
                "passive_product_observations": reports[2]["passive_review"],
                "passive_checksum_difference": "unchanged captured zero is retained when routing prevents safe recomputation; both references fill it",
                "installed_providers": len(args.python),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
