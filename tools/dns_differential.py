"""Independent DNS messages decoded by dpkt 1.9.6, 1.9.8 and OctetRail, which must agree."""

import argparse
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
QN = b"\x04note\x07example\0"
QNAME = "note.example"
NAMES = {
    2: ("nsname",),
    5: ("cname",),
    12: ("ptrname",),
    15: ("mxname",),
    6: ("mname", "rname"),
    33: ("srvname",),
}
NUMBERS = {
    15: ("preference",),
    6: ("serial", "refresh", "retry", "expire", "minimum"),
    33: ("priority", "weight", "port"),
}


def header(counts, op=0x8180, id_=0x1234):
    return struct.pack("!6H", id_, op, *counts)


def fullname(text):
    return (
        b"".join(bytes((len(x),)) + x.encode() for x in text.split(".")) + b"\0" if text else b"\0"
    )


def record_fixture(kind):
    raw, attrs = {
        1: (bytes.fromhex("c0000209"), {"ip": "c0000209"}),
        28: (
            bytes.fromhex("20010db8000000000000000000000009"),
            {"ip6": "20010db8000000000000000000000009"},
        ),
        2: (b"\x02ns\xc0\x11", {"nsname": "ns.example"}),
        5: (b"\x05alias\xc0\x11", {"cname": "alias.example"}),
        12: (b"\x04host\xc0\x11", {"ptrname": "host.example"}),
        15: (b"\x00\x0a\x04mail\xc0\x11", {"preference": 10, "mxname": "mail.example"}),
        6: (
            b"\x02ns\xc0\x11\x05admin\xc0\x11" + struct.pack("!5I", 1, 3600, 600, 86400, 60),
            {
                "mname": "ns.example",
                "rname": "admin.example",
                "serial": 1,
                "refresh": 3600,
                "retry": 600,
                "expire": 86400,
                "minimum": 60,
            },
        ),
        16: (b"\x05first\x06second", {"text": ["first", "second"]}),
        13: (b"\x06x86_64\x04unix", {"text": ["x86_64", "unix"]}),
        33: (
            struct.pack("!3H", 1, 2, 5353) + b"\x03srv\xc0\x11",
            {"priority": 1, "weight": 2, "port": 5353, "srvname": "srv.example"},
        ),
        10: (b"note\0", {"null": "6e6f746500"}),
        41: (struct.pack("!HH", 65001, 4) + b"note", {}),
        65280: (b"\0\x01note", {}),
        65281: (b"", {}),
    }[kind]
    name, owner, cls, ttl = ("", b"\0", 4096, 0x8000) if kind == 41 else (QNAME, b"\xc0\x0c", 1, 60)
    rr = owner + struct.pack("!HHIH", kind, cls, ttl, len(raw)) + raw
    state = {
        "name": name,
        "type": kind,
        "cls": cls,
        "ttl": ttl,
        "rlen": len(raw),
        "rdata": raw.hex(),
        "attrs": attrs,
    }
    return rr, state


def cases():
    output = []
    for kind in (1, 28, 2, 5, 12, 15, 6, 16, 13, 33, 10, 41, 65280, 65281):
        rr, state = record_fixture(kind)
        section = 3 if kind == 41 else 1
        counts = [1, 0, 0, 0]
        counts[section] = 1
        qtype = 1 if kind == 41 else kind
        wire = header(counts) + QN + struct.pack("!HH", qtype, 1) + rr
        rows = [[], [], []]
        rows[section - 1] = [state]
        output.append(
            {
                "id": "rr-" + str(kind),
                "wire": wire.hex(),
                "id_value": 0x1234,
                "op": 0x8180,
                "questions": [[QNAME, qtype, 1]],
                "sections": rows,
                "tail": "",
                "category": "unknown"
                if kind >= 65280
                else "mx-preference"
                if kind == 15
                else "equal",
            }
        )
    for label, question, op in (
        ("query", [QNAME, 1, 1], 0x100),
        ("root", ["", 1, 1], 0x100),
        ("nxdomain", [QNAME, 1, 1], 0x8183),
    ):
        wire = (
            header([1, 0, 0, 0], op)
            + fullname(question[0])
            + struct.pack("!HH", question[1], question[2])
        )
        output.append(
            {
                "id": label,
                "wire": wire.hex(),
                "id_value": 0x1234,
                "op": op,
                "questions": [question],
                "sections": [[], [], []],
                "tail": "",
                "category": "equal",
            }
        )
    output.append(
        {
            "id": "empty",
            "wire": header([0, 0, 0, 0], 0x100).hex(),
            "id_value": 0x1234,
            "op": 0x100,
            "questions": [],
            "sections": [[], [], []],
            "tail": "",
            "category": "equal",
        }
    )
    wire = (
        header([2, 0, 0, 0], 0x100)
        + QN
        + struct.pack("!HH", 1, 1)
        + b"\x03www\xc0\x11"
        + struct.pack("!HH", 28, 1)
    )
    output.append(
        {
            "id": "questions",
            "wire": wire.hex(),
            "id_value": 0x1234,
            "op": 0x100,
            "questions": [[QNAME, 1, 1], ["www.example", 28, 1]],
            "sections": [[], [], []],
            "tail": "",
            "category": "equal",
        }
    )
    a, sa = record_fixture(1)
    ns, sns = record_fixture(2)
    a6, sa6 = record_fixture(28)
    wire = header([1, 1, 1, 1]) + QN + struct.pack("!HH", 1, 1) + a + ns + a6
    output.append(
        {
            "id": "sections",
            "wire": wire.hex(),
            "id_value": 0x1234,
            "op": 0x8180,
            "questions": [[QNAME, 1, 1]],
            "sections": [[sa], [sns], [sa6]],
            "tail": "",
            "category": "equal",
        }
    )
    trailing = json.loads(json.dumps(output[0]))
    trailing.update(
        id="trailing",
        wire=trailing["wire"] + b"tail".hex(),
        tail=b"tail".hex(),
        category="trailing",
    )
    output.append(trailing)
    canonical = next(c for c in output if c["id"] == "rr-5")
    uncompressed = json.loads(json.dumps(canonical))
    rdata = fullname("alias.example")
    record = QN + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata
    uncompressed.update(
        id="uncompressed-name-rdata",
        wire=(header([1, 1, 0, 0]) + QN + struct.pack("!HH", 5, 1) + record).hex(),
        category="rebased",
    )
    uncompressed["sections"][0][0].update(rdata=rdata.hex(), rlen=len(rdata))
    output.append(uncompressed)
    return output


def expected(case, module):
    """What dpkt 1.9.8 reports for a fixture; OctetRail must match it exactly."""
    if case["category"] == "unknown":
        return {"error": "UnpackError"}
    wire = bytes.fromhex(case["wire"])
    tail = case["tail"]
    if case["category"] == "trailing":
        wire = wire[:-4]
        tail = ""
    if case["category"] == "rebased":
        # Questions and owners are recompressed; the raw name RDATA is copied.
        wire = (
            header([1, 1, 0, 0])
            + QN
            + struct.pack("!HH", 5, 1)
            + b"\xc0\x0c"
            + struct.pack("!HHIH", 5, 1, 60, len(fullname("alias.example")))
            + fullname("alias.example")
        )
    sections = json.loads(json.dumps(case["sections"]))
    for rows in sections:
        for record in rows:
            if record["type"] == 15:
                record["attrs"]["preference"] = [record["attrs"]["preference"]]
    return {
        "id": case["id_value"],
        "op": case["op"],
        "questions": case["questions"],
        "sections": sections,
        "tail": tail,
        "wire": wire.hex(),
        "length": len(wire),
    }


def snapshot(message):
    sections = []
    for rows in (message.an, message.ns, message.ar):
        result = []
        for r in rows:
            attrs = {n: getattr(r, n) for n in (*NAMES.get(r.type, ()), *NUMBERS.get(r.type, ()))}
            for key in ("ip", "ip6", "null"):
                if hasattr(r, key):
                    attrs[key] = getattr(r, key).hex() if key != "null" else r.null.decode("ascii")
            if r.type in (13, 16):
                attrs["text"] = r.text
            result.append(
                {
                    "name": r.name,
                    "type": r.type,
                    "cls": r.cls,
                    "ttl": r.ttl,
                    "rlen": r.rlen,
                    "rdata": r.rdata.hex(),
                    "attrs": attrs,
                }
            )
        sections.append(result)
    return {
        "id": message.id,
        "op": message.op,
        "questions": [[q.name, q.type, q.cls] for q in message.qd],
        "sections": sections,
        "tail": message.data.hex(),
        "wire": bytes(message).hex(),
        "length": len(message),
    }


def ordinary_large_response():
    """Independent compressed NS response within the declared record limit."""
    owner = "records.api.cache.office.region.site.example"
    target = "resolver.edge.example"
    qname = fullname(owner)
    example_offset = 12 + qname.index(b"\x07example")
    prefix = header([1, 768, 0, 0]) + qname + struct.pack("!HH", 2, 1)
    rdata_offset = len(prefix) + 12
    first = b"\x08resolver\x04edge" + struct.pack("!H", 0xC000 | example_offset)
    rows = []
    for index in range(768):
        rdata = first if index == 0 else struct.pack("!H", 0xC000 | rdata_offset)
        rows.append(b"\xc0\x0c" + struct.pack("!HHIH", 2, 1, 60, len(rdata)) + rdata)
    return prefix + b"".join(rows), owner, target


def review_checks(package, module):
    wire, owner, target = ordinary_large_response()
    message = package.dns.DNS(wire)
    C.require(
        len(message.an) == 768 and all(r.name == owner and r.nsname == target for r in message.an),
        "ordinary larger DNS response fields",
    )
    C.require(bytes(message) == wire, "ordinary larger DNS response independent bytes")
    for kind, key, address in (
        (1, "ip", bytes.fromhex("c000024d")),
        (28, "ip6", bytes.fromhex("20010db8" + "00" * 11 + "77")),
    ):
        case = next(c for c in cases() if c["id"] == "rr-" + str(kind))
        original = bytes.fromhex(case["wire"])
        packet = package.dns.DNS(original)
        setattr(packet.an[0], key, address)
        C.require(bytes(packet) == original, "address edit retains explicit raw precedence")
        packet.an[0].rdata = b""
        C.require(
            bytes(packet) == original[: -len(address)] + address,
            "explicit address alias edit independent bytes",
        )
    minimum = header([1025, 0, 0, 0])
    try:
        package.dns.DNS(minimum)
    except package.UnpackError:
        pass
    else:
        raise ValueError("incomplete declared sections accepted")
    complete = minimum + b"\0\0\1\0\1" * 1025
    C.require(len(package.dns.DNS(complete).qd) == 1025, "complete 1025-question message")
    return {
        "large_response_records": 768,
        "large_response_bytes": len(wire),
        "address_edit_sequences": 2,
        "minimum_size_check": 1,
    }


def as_json(v):
    if isinstance(v, (bytes, bytearray, memoryview)):
        return {"hex": bytes(v).hex(), "type": type(v).__name__}
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


def kind(action):
    """The outcome without the message, for errors whose text varies by Python version."""
    found = attempt(action)
    return found["error"] if isinstance(found, dict) and "error" in found else found


def _query(name=QN, counts=(1, 0, 0, 0)):
    return header(list(counts)) + name + b"\0\1\0\1"


def _record(kind, rdata, owner=b"\xc0\x0c"):
    return (
        header([1, 1, 0, 0])
        + QN
        + b"\0\1\0\1"
        + owner
        + struct.pack("!HHIH", kind, 1, 60, len(rdata))
        + rdata
    )


def observations(package):
    """Outcomes compared with dpkt 1.9.8 as they are: classes, messages and reprs."""
    D = package.dns

    class Record(D.DNS.RR):
        def unpack_rdata(self, buf, off):
            if self.type == 0x20:
                self.flags = self.rdata[:2]
            else:
                D.DNS.RR.unpack_rdata(self, buf, off)

    class Question(D.DNS.Q):
        pass

    class Sub(D.DNS):
        Q, RR = Question, Record

    def subclass():
        message = Sub(_record(0x20, b"\x60\x00\x0a\x00\x00\x01"))
        return [
            type(message.qd[0]).__name__,
            type(message.an[0]).__name__,
            message.an[0].flags,
            repr(message),
            bytes(message),
        ]

    def parsed(wire):
        message = D.DNS(wire)
        return [repr(message), [repr(q) for q in message.qd], [repr(r) for r in message.an]]

    def packed(**keywords):
        return bytes(D.DNS(**keywords))

    mx = _record(15, b"\0\x0a\x04mail\xc0\x11")

    def mx_repacked():
        message = D.DNS(mx)
        message.an[0].rdata = b""
        return bytes(message)

    def txt_repacked():
        message = D.DNS(_record(16, b"\x03abc"))
        message.an[0].rdata = b""
        return bytes(message)

    def label_ptrs_removed():
        message = D.DNS(qd=[D.DNS.Q(name="a.b")])
        bytes(message)
        return hasattr(message, "label_ptrs")

    def pointers():
        table = {}
        return [D.pack_name("x.note.example", 12, table), sorted(table.items())]

    return {
        "repr_query": attempt(lambda: parsed(_query())),
        "repr_records": attempt(lambda: parsed(_record(1, b"\xc0\0\2\1") + b"tail")),
        "repr_soa": attempt(
            lambda: parsed(_record(6, b"\x02ns\xc0\x11\x04host\xc0\x11" + bytes(range(20))))
        ),
        "repr_txt": attempt(lambda: parsed(_record(16, b"\x03abc\x00\x05cut"))),
        "default_message": attempt(lambda: [repr(D.DNS()), bytes(D.DNS()), len(D.DNS())]),
        "default_q": attempt(lambda: repr(D.DNS.Q())),
        "default_rr": attempt(lambda: repr(D.DNS.RR())),
        "q_len": attempt(lambda: len(D.DNS.Q())),
        "q_parse": attempt(lambda: D.DNS.Q(b"\0\0\1\0\1")),
        "rr_str": attempt(lambda: str(D.DNS.RR())),
        "bytearray_rdata": attempt(lambda: D.DNS(bytearray(_record(1, b"\1\2\3\4"))).an[0].rdata),
        "subclass_hooks": attempt(subclass),
        "short_header": attempt(lambda: D.DNS(bytes(11))),
        "name_cut": attempt(lambda: D.DNS(_query(b"\x04note\x07exa"))),
        "name_no_end": attempt(lambda: D.DNS(_query(b"\x04note")[:-4])),
        "question_cut": attempt(lambda: D.DNS(_query()[:-1])),
        "record_cut": attempt(lambda: D.DNS(_record(1, b"\1\2\3\4")[:-6])),
        "pointer_forward": attempt(lambda: D.DNS(_query(b"\xc0\x20"))),
        "label_type": attempt(lambda: D.DNS(_query(b"\x40abc\0"))),
        "name_too_long": attempt(lambda: D.DNS(_query((b"\x3f" + b"a" * 63) * 4 + b"\0"))),
        "unsupported_type": attempt(lambda: D.DNS(_record(99, b"x"))),
        "soa_cut": attempt(lambda: D.DNS(_record(6, b"\0\0" + bytes(10)))),
        "mx_cut": attempt(lambda: D.DNS(_record(15, b"\0"))),
        "srv_cut": attempt(lambda: D.DNS(_record(33, b"\0\1\0"))),
        "mx_repacked": attempt(mx_repacked),
        "txt_repacked": attempt(txt_repacked),
        "pack_id_range": attempt(lambda: packed(id=65536)),
        "pack_default_q": kind(lambda: packed(qd=[D.DNS.Q()])),
        "pack_object_q": attempt(lambda: packed(qd=[object()])),
        "pack_long_label": kind(lambda: packed(qd=[D.DNS.Q(name="x" * 256)])),
        "pack_bytes_name": kind(lambda: packed(qd=[D.DNS.Q(name=b"a")])),
        "pack_unknown_rr": attempt(lambda: packed(an=[D.DNS.RR(name="", type=99)])),
        "pack_missing_field": attempt(lambda: packed(an=[D.DNS.RR(name="", type=2)])),
        "pack_long_rdata": attempt(
            lambda: packed(an=[D.DNS.RR(name="", type=10, rdata=b"x" * 65536)])
        ),
        "pack_hdr_lists": attempt(lambda: D.DNS().pack_hdr()),
        "label_ptrs_removed": attempt(label_ptrs_removed),
        "pointers": attempt(pointers),
        "pointer_too_far": attempt(lambda: D.pack_name("a", 0, {b"A.": 0x4000})),
        "unpack_name_cut": attempt(lambda: D.unpack_name(b"\x01a", 0)),
        "unpack_name_pointer": attempt(lambda: D.unpack_name(b"\0\x01b\xc0\x00", 1)),
        "flags": attempt(
            lambda: [
                (lambda m: [m.qr, m.opcode, m.aa, m.tc, m.rd, m.ra, m.zero, m.rcode])(
                    D.DNS(header([0, 0, 0, 0], 0xFFFF))
                )
            ]
        ),
        "bad_utf8_name": attempt(lambda: D.DNS(_query(b"\x02\xff\xfe\0"))),
        "bad_utf8_text": attempt(lambda: D.DNS(_record(16, b"\x01\xff"))),
    }


def exercise(package, module):
    D = package.dns
    output = {}
    for case in cases():
        try:
            message = D.DNS(bytes.fromhex(case["wire"]))
        except package.UnpackError as e:
            output[case["id"]] = {"error": type(e).__name__}
        else:
            output[case["id"]] = snapshot(message)
    constructors = []
    for case in cases():
        if not case["id"].startswith("rr-") or case["category"] not in ("equal", "mx-preference"):
            continue
        spec = next(row for section in case["sections"] for row in section)
        attrs = dict(spec["attrs"])
        attrs.pop("null", None)
        if "ip" in attrs:
            attrs["ip"] = bytes.fromhex(attrs["ip"])
        if "ip6" in attrs:
            attrs["ip6"] = bytes.fromhex(attrs["ip6"])
        if "text" in attrs:
            attrs["text"] = [t.encode() for t in attrs["text"]]
        if spec["type"] in (10, 41):
            attrs["rdata"] = bytes.fromhex(spec["rdata"])
        rr = D.DNS.RR(
            name=spec["name"], type=spec["type"], cls=spec["cls"], ttl=spec["ttl"], **attrs
        )
        message = D.DNS(
            id=case["id_value"],
            op=case["op"],
            qd=[D.DNS.Q(name=n, type=t, cls=c) for n, t, c in case["questions"]],
        )
        getattr(message, "ar" if spec["type"] == 41 else "an").append(rr)
        C.require(
            bytes(message).hex() == case["wire"], "DNS constructor independent bytes " + case["id"]
        )
        constructors.append(case["id"])
    mutations = {}
    for kind, field, value in ((5, "cname", "mail.example"), (16, "text", ["third"])):
        case = next(c for c in cases() if c["id"] == "rr-" + str(kind))
        message = D.DNS(bytes.fromhex(case["wire"]))
        setattr(message.an[0], field, value)
        rdata = b"\x04mail\xc0\x11" if kind == 5 else b"\x05third"
        want = (
            header([1, 1, 0, 0])
            + QN
            + struct.pack("!HH", kind, 1)
            + b"\xc0\x0c"
            + struct.pack("!HHIH", kind, 1, 60, len(rdata))
            + rdata
        )
        C.require(bytes(message) == bytes.fromhex(case["wire"]), "raw rdata precedence")
        mutations[str(kind)] = bytes(message).hex()
        message.an[0].rdata = b""
        if kind == 16:
            message.an[0].text = [b"third"]
        C.require(bytes(message) == want, "explicit re-encoding mutation")
    flags = D.DNS()
    flags.qr = 1
    flags.opcode = 3
    flags.aa = 1
    flags.tc = 1
    flags.rd = 0
    flags.ra = 1
    flags.zero = 1
    flags.rcode = 2
    C.require(bytes(flags) == header([0, 0, 0, 0], 0x9EC2, 0), "header bit mutation")
    return {
        "cases": output,
        "constructors": constructors,
        "mutations": mutations,
        "review": review_checks(package, module),
        "observations": observations(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(package.dns.__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/dns.py")).resolve(),
        "unverified DNS origin",
    )
    return package


# Observations where OctetRail differs from 1.9.8 on purpose. A name or
# character string that is not UTF-8 raises UnicodeDecodeError in dpkt;
# OctetRail raises dns.TextDecodeError, which is both an UnpackError and a
# UnicodeDecodeError, with dpkt's message.
_DECODE = "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
DECLARED = {
    "bad_utf8_name": {"error": "TextDecodeError", "message": _DECODE},
    "bad_utf8_text": {"error": "TextDecodeError", "message": _DECODE},
}
# What dpkt 1.9.8 must still do for each declared case, so a declared
# difference stays a measured one.
DECLARED_REFERENCE = {
    "bad_utf8_name": {"error": "UnicodeDecodeError", "message": _DECODE},
    "bad_utf8_text": {"error": "UnicodeDecodeError", "message": _DECODE},
}


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
        print(json.dumps(exercise(provenance(a.module, a.version), a.module)))
        return
    C.require(
        a.oracle_196 and a.oracle_198 and a.python,
        "both pinned references and an installed candidate are required",
    )
    version = tomllib.loads((C.ROOT / "pyproject.toml").read_text())["project"]["version"]
    count = 0
    observed = []
    for python, module, v in [
        (a.oracle_196, "dpkt", "1.9.6"),
        (a.oracle_198, "dpkt", "1.9.8"),
        *((x, "octetrail", version) for x in a.python),
    ]:
        r = subprocess.run(
            [python, "-B", "-I", "-O", __file__, "--probe", "--module", module, "--version", v],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        report = json.loads(r.stdout)
        observed.append((module + v, report["observations"]))
        C.require(
            report["cases"] == {c["id"]: expected(c, module) for c in cases()},
            "DNS observation mismatch " + module + v,
        )
        C.require(len(report["constructors"]) == 12, "DNS constructor coverage")
        count += 1
    reference = observed[1][1]
    C.require(
        all(reference.get(k) == v for k, v in DECLARED_REFERENCE.items()),
        "a declared DNS difference no longer matches dpkt 1.9.8",
    )
    for name, found in observed[2:]:
        wrong = sorted(k for k in reference if found.get(k) != DECLARED.get(k, reference[k]))
        C.require(not wrong, "DNS observation mismatch " + name + ": " + ", ".join(wrong))
    print(
        json.dumps(
            {
                "fixtures": len(cases()),
                "equal_cases": sum(c["category"] == "equal" for c in cases()),
                "fixtures_matching_dpkt_quirks": [
                    c["id"] for c in cases() if c["category"] != "equal"
                ],
                "constructor_cases_per_provider": 12,
                "raw_rdata_precedence_sequences": 2,
                "header_flag_mutations": 1,
                "review_large_response_records_per_provider": 768,
                "review_address_edits_per_provider": 2,
                "review_minimum_and_count_checks_per_provider": 2,
                "providers": count,
                "observations": len(reference),
                "dpkt_196_differs_on": sorted(
                    k for k in reference if observed[0][1].get(k) != reference[k]
                ),
                "declared_differences": sorted(DECLARED),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
