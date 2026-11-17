"""Independent offline composition fixtures and installed-provider comparisons.

Run the comparison from the standalone project root with separate hash-pinned
dpkt interpreters. The probe uses -I and -O and explicit provenance failures.
No application protocols, network sockets or downstream services are exercised.
"""

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import struct
import subprocess
import sys
import tempfile

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: only release tooling reads TOML.
    tomllib = None
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC, DST = bytes.fromhex("c0000201"), bytes.fromhex("c6336402")
MACS = bytes.fromhex("02aabbccddee021122334455")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checksum(raw):
    # Independent byte arithmetic, not a provider checksum or serialization API.
    padded = raw + b"\0" * (len(raw) % 2)
    total = sum(padded[i] * 256 + padded[i + 1] for i in range(0, len(padded), 2))
    while total > 65535:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def encode(spec, *, ip_sum=None, transport_sum=None, declared_length=None):
    payload = bytes.fromhex(spec["payload"])
    opts = bytes.fromhex(spec.get("opts", ""))
    tcp_opts = bytes.fromhex(spec.get("tcp_opts", ""))
    proto = spec.get("p", 6 if spec["kind"] == "tcp" else 17)
    src = bytes.fromhex(spec.get("src", SRC.hex()))
    if spec["kind"] == "tcp":
        body = (
            struct.pack(
                "!HHIIBBHHH",
                spec.get("sport", 32000),
                32001,
                17,
                18,
                (5 + len(tcp_opts) // 4) << 4,
                0x18,
                4096,
                spec.get("transport_sum", 0),
                0,
            )
            + tcp_opts
            + payload
        )
    elif spec["kind"] == "udp":
        body = (
            struct.pack(
                "!HHHH",
                spec.get("sport", 32000),
                32001,
                spec.get("ulen", 8 + len(payload)),
                spec.get("transport_sum", 0),
            )
            + payload
        )
    else:
        body = payload
    flags = spec.get("flags", 0)
    network_sum = spec.get("ip_sum", 0) if ip_sum is None else ip_sum
    if spec["kind"] in ("tcp", "udp"):
        stored = spec.get("transport_sum", 0) if transport_sum is None else transport_sum
        if network_sum == 0 and stored == 0 and flags & 0x3FFF == 0 and proto in (6, 17):
            stored = checksum(src + DST + struct.pack("!BBH", 0, proto, len(body)) + body)
            if proto == 17 and stored == 0:
                stored = 65535
        offset = 16 if spec["kind"] == "tcp" else 6
        body = body[:offset] + struct.pack("!H", stored) + body[offset + 2 :]
    total = 20 + len(opts) + len(body) if declared_length is None else declared_length
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45 + len(opts) // 4,
        0,
        total,
        0x1234,
        flags,
        64,
        proto,
        network_sum,
        src,
        DST,
    )
    if network_sum == 0:
        header = header[:10] + struct.pack("!H", checksum(header + opts)) + header[12:]
    return MACS + b"\x08\x00" + header + opts + body


def fixtures():
    result = []

    def add(identifier, **spec):
        spec.setdefault("payload", b"rail".hex())
        result.append({"id": identifier, "spec": spec, "wire": encode(spec).hex()})

    for kind in ("tcp", "udp"):
        for payload in (b"", b"x", b"rail", b"ordinary offline payload"):
            add(f"{kind}_payload_{len(payload)}", kind=kind, payload=payload.hex())
        for n in (4, 40):
            add(f"{kind}_ip_options_{n}", kind=kind, opts=(b"\x01" * n).hex())
        for flags in (0x4000, 0x2000, 1):
            add(f"{kind}_flags_{flags}", kind=kind, flags=flags)
        add(f"{kind}_explicit_transport_sum", kind=kind, transport_sum=0x1234)
        add(f"{kind}_explicit_ip_sum", kind=kind, ip_sum=0x3456)
    for n in (4, 40):
        for ip_options in (b"", b"\x01" * 4):
            add(
                f"tcp_options_{n}_ip_{len(ip_options)}",
                kind="tcp",
                tcp_opts=(b"\x01" * n).hex(),
                opts=ip_options.hex(),
            )
    add("udp_stored_length", kind="udp", ulen=8)
    # Choose an ordinary two-byte payload whose UDP checksum is all zero bits.
    base = SRC + DST + struct.pack("!BBHHHHH", 0, 17, 10, 32000, 32001, 10, 0)
    add(
        "udp_zero_checksum_maps_to_ones",
        kind="udp",
        payload=checksum(base).to_bytes(2, "big").hex(),
    )
    add("unknown_ip_protocol", kind="opaque", p=253)
    result.append(
        {"id": "unknown_ethertype", "spec": None, "wire": (MACS + b"\x88\xb5opaque").hex()}
    )
    return result


def expected(raw):
    """Normalize independent wire fields using struct, never provider parsing."""
    frame = {
        "class": "Ethernet",
        "dst": raw[:6].hex(),
        "src": raw[6:12].hex(),
        "type": int.from_bytes(raw[12:14], "big"),
        "length": len(raw),
    }
    if frame["type"] != 0x0800:
        frame["data"] = raw[14:].hex()
        return frame
    h = struct.unpack("!BBHHHBBH4s4s", raw[14:34])
    start = 14 + (h[0] & 15) * 4
    body = raw[start:]
    ip = {
        "class": "IP",
        "v": h[0] >> 4,
        "hl": h[0] & 15,
        "tos": h[1],
        "len": h[2],
        "id": h[3],
        "flags": h[4],
        "ttl": h[5],
        "p": h[6],
        "sum": h[7],
        "src": h[8].hex(),
        "dst": h[9].hex(),
        "opts": raw[34:start].hex(),
        "length": len(raw) - 14,
    }
    if h[4] & 8191 or h[6] not in (6, 17):
        ip["data"] = body.hex()
    elif h[6] == 6:
        t = struct.unpack("!HHIIBBHHH", body[:20])
        off = t[4] >> 4
        ip["data"] = dict(
            zip(
                ("sport", "dport", "seq", "ack", "off", "flags", "win", "sum", "urp"),
                (*t[:4], off, *t[5:]),
                strict=True,
            )
        )
        ip["data"].update(
            {
                "class": "TCP",
                "opts": body[20 : off * 4].hex(),
                "data": body[off * 4 :].hex(),
                "length": len(body),
            }
        )
    else:
        t = struct.unpack("!HHHH", body[:8])
        ip["data"] = dict(zip(("sport", "dport", "ulen", "sum"), t, strict=True))
        ip["data"].update({"class": "UDP", "data": body[8:].hex(), "length": len(body)})
    frame["data"] = ip
    return frame


def snapshot(packet):
    name = type(packet).__name__
    if name == "Ethernet":
        fields = ("type",)
        result = {"dst": packet.dst.hex(), "src": packet.src.hex()}
    elif name == "IP":
        fields = ("v", "hl", "tos", "len", "id", "ttl", "p", "sum")
        result = {
            "src": packet.src.hex(),
            "dst": packet.dst.hex(),
            "opts": packet.opts.hex(),
            "flags": int.from_bytes(packet.pack_hdr()[6:8], "big"),
        }
    elif name == "TCP":
        fields = ("sport", "dport", "seq", "ack", "off", "flags", "win", "sum", "urp")
        result = {"opts": packet.opts.hex()}
    else:
        require(name == "UDP", "unexpected packet class")
        fields, result = ("sport", "dport", "ulen", "sum"), {}
    result.update({key: getattr(packet, key) for key in fields})
    result.update(
        {
            "class": name,
            "length": len(packet),
            "data": packet.data.hex() if isinstance(packet.data, bytes) else snapshot(packet.data),
        }
    )
    return result


def construct(module, spec):
    if spec["kind"] == "tcp":
        opts = bytes.fromhex(spec.get("tcp_opts", ""))
        child = module.tcp.TCP(
            sport=spec.get("sport", 32000),
            dport=32001,
            seq=17,
            ack=18,
            flags=0x18,
            win=4096,
            opts=opts,
            off=5 + len(opts) // 4,
            sum=spec.get("transport_sum", 0),
            data=bytes.fromhex(spec["payload"]),
        )
    elif spec["kind"] == "udp":
        data = bytes.fromhex(spec["payload"])
        child = module.udp.UDP(
            sport=spec.get("sport", 32000),
            dport=32001,
            ulen=spec.get("ulen", 8 + len(data)),
            sum=spec.get("transport_sum", 0),
            data=data,
        )
    else:
        child = bytes.fromhex(spec["payload"])
    opts = bytes.fromhex(spec.get("opts", ""))
    network = module.ip.IP(
        src=bytes.fromhex(spec.get("src", SRC.hex())),
        dst=DST,
        p=spec.get("p", 6 if spec["kind"] == "tcp" else 17),
        id=0x1234,
        hl=5 + len(opts) // 4,
        opts=opts,
        sum=spec.get("ip_sum", 0),
        data=child,
    )
    # Raw flag storage differs across references; this comparison measures wire flags.
    setattr(
        network,
        "_flags_offset" if hasattr(network, "_flags_offset") else "off",
        spec.get("flags", 0),
    )
    return module.ethernet.Ethernet(dst=MACS[:6], src=MACS[6:], data=network)


def exercise(module, case):
    raw = bytes.fromhex(case["wire"])
    packet = module.ethernet.Ethernet(raw)
    report = {"parse": snapshot(packet), "roundtrip": bytes(packet).hex()}
    if case["spec"] is not None:
        constructed = construct(module, case["spec"])
        report["constructed_wire"] = bytes(constructed).hex()
        # Noninitial fragments decode to bytes, even when construction used an object.
        report["constructed_reparse"] = snapshot(module.ethernet.Ethernet(bytes(constructed)))
        report["aliases"] = getattr(packet, "ip", None) is packet.data
        if isinstance(packet.data.data, bytes):
            report["transport_alias"] = False
        else:
            report["transport_alias"] = (
                getattr(packet.data, type(packet.data.data).__name__.lower(), None)
                is packet.data.data
            )
        keyword = module.ethernet.Ethernet(dst=MACS[:6], src=MACS[6:], data=raw[14:])
        report["keyword_parse"] = snapshot(keyword)
    return report


def mutations(module):
    result = {}
    for kind in ("tcp", "udp"):
        for reset in (False, True):
            spec = {"kind": kind, "payload": b"rail".hex()}
            packet = construct(module, spec)
            bytes(packet)
            packet.data.src = DST
            packet.data.data.sport = 1234
            packet.data.data.data = b"changed ordinary payload"
            if reset:
                packet.data.sum = packet.data.data.sum = 0
            result[f"{kind}_{reset}"] = {"wire": bytes(packet).hex(), "state": snapshot(packet)}
    return result


def expected_mutations(version):
    result = {}
    for kind in ("tcp", "udp"):
        base = {"kind": kind, "payload": b"rail".hex()}
        old = encode(base)
        for reset in (False, True):
            spec = {
                **base,
                "src": DST.hex(),
                "sport": 1234,
                "payload": b"changed ordinary payload".hex(),
            }
            if kind == "udp":
                spec["ulen"] = 12  # UDP never silently updates its stored length.
            transport_offset = 34 + (16 if kind == "tcp" else 6)
            wire = encode(
                spec,
                ip_sum=0 if reset else int.from_bytes(old[24:26], "big"),
                transport_sum=0
                if reset
                else int.from_bytes(old[transport_offset : transport_offset + 2], "big"),
                declared_length=None if reset or version == "1.9.6" else len(old) - 14,
            )
            result[f"{kind}_{reset}"] = {"wire": wire.hex(), "state": expected(wire)}
    return result


def errors(module):
    rows = {}
    for name, operation in {
        "short_tcp": lambda: module.tcp.TCP(bytes(19)),
        "short_udp": lambda: module.udp.UDP(bytes(7)),
        "short_ethernet": lambda: module.ethernet.Ethernet(bytes(13)),
        "ip_options_mismatch": lambda: bytes(module.ip.IP(opts=b"\x01" * 4)),
        "tcp_options_mismatch": lambda: bytes(module.tcp.TCP(opts=b"\x01" * 4)),
        "short_ip_options": lambda: module.ip.IP(
            bytes.fromhex("460000181234000040fd0001c0000201c6336402010101")
        ),
        "short_tcp_options": lambda: module.tcp.TCP(bytes(12) + b"\x60" + bytes(10)),
    }.items():
        try:
            operation()
        except (module.UnpackError, module.PackError) as error:
            rows[name] = type(error).__name__
        else:
            rows[name] = "ok"
    return rows


def provenance(module, version):
    package = importlib.import_module(module)
    dist = importlib.metadata.distribution(module)
    require(dist.version == version, "wrong provider version")
    prefix = Path(sys.prefix).resolve()
    for name in ("", ".ethernet", ".ip", ".tcp", ".udp"):
        imported = importlib.import_module(module + name)
        origin = Path(imported.__file__).resolve()
        member = module + "/" + (name[1:] + ".py" if name else "__init__.py")
        require(
            origin.is_relative_to(prefix) and origin == Path(dist.locate_file(member)).resolve(),
            "unverified provider origin",
        )
    if module == "octetrail":
        native = Path(package._native.__file__).resolve()
        require(
            native.is_relative_to(prefix)
            and any(Path(dist.locate_file(f)).resolve() == native for f in dist.files),
            "unverified native origin",
        )
    return package


def probe(python, module, version, cases):
    completed = subprocess.run(
        [python, "-B", "-I", "-O", __file__, "--probe", "--module", module, "--version", version],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        check=True,
        cwd=tempfile.gettempdir(),
        timeout=60,
    )
    return json.loads(completed.stdout)


def validate(report, cases, module, version):
    require(
        report["origin_verified"] is True
        and report["module"] == module
        and report["version"] == version,
        "provider identity",
    )
    require(set(report["cases"]) == {c["id"] for c in cases}, "fixture inventory")
    for case in cases:
        actual = report["cases"][case["id"]]
        wire = bytes.fromhex(case["wire"])
        want = expected(wire)
        require(
            actual["parse"] == want and actual["roundtrip"] == case["wire"],
            "parse/roundtrip " + case["id"],
        )
        if case["spec"] is not None:
            require(
                actual["constructed_wire"] == case["wire"]
                and actual["constructed_reparse"] == want
                and actual["keyword_parse"] == want,
                "construction " + case["id"],
            )
            require(
                actual["aliases"]
                and actual["transport_alias"] == isinstance(want["data"]["data"], dict),
                "aliases " + case["id"],
            )
    require(report["mutations"] == expected_mutations(version), "mutation fields/bytes")
    errors_wanted = dict.fromkeys(("short_tcp", "short_udp", "short_ethernet"), "NeedData")
    errors_wanted.update(
        dict.fromkeys(
            ("ip_options_mismatch", "tcp_options_mismatch"),
            "PackError" if module == "octetrail" else "ok",
        )
    )
    errors_wanted.update(
        dict.fromkeys(
            ("short_ip_options", "short_tcp_options"), "NeedData" if module == "octetrail" else "ok"
        )
    )
    require(report["errors"] == errors_wanted, "declared errors/strict differences")


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
        package = provenance(args.module, args.version)
        cases = json.load(sys.stdin)
        print(
            json.dumps(
                {
                    "origin_verified": True,
                    "module": args.module,
                    "version": args.version,
                    "cases": {c["id"]: exercise(package, c) for c in cases},
                    "mutations": mutations(package),
                    "errors": errors(package),
                }
            )
        )
        return
    cases = fixtures()
    for version, python in (("1.9.6", args.oracle_196), ("1.9.8", args.oracle_198)):
        require(python, "both pinned oracle interpreters are required")
        validate(probe(python, "dpkt", version, cases), cases, "dpkt", version)
    project_version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    for python in args.python:
        validate(
            probe(python, "octetrail", project_version, cases), cases, "octetrail", project_version
        )
    print(
        json.dumps(
            {
                "shared_fixtures": len(cases),
                "operations_per_fixture": "parse, exact roundtrip; nested construction and byte-keyword dispatch for IPv4",
                "mutation_cases": 4,
                "version_difference_cases": 2,
                "strict_error_differences": 4,
                "shared_truncation_errors": 3,
                "installed_providers": len(args.python),
                "oracle_versions": ["1.9.6", "1.9.8"],
                "corpus_sha256": hashlib.sha256(
                    json.dumps(cases, sort_keys=True).encode()
                ).hexdigest(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
