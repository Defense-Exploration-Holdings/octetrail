"""The dpkt Packet base and checksum helpers run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider defines the same Packet subclasses on its own base class and
reports what they do. OctetRail must match dpkt 1.9.8 exactly; the keys where
1.9.6 differs are listed.
"""

import argparse
import contextlib
import importlib.metadata
import importlib.util
import io
import json
import struct
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 runs only the probes, which read no TOML.

    class tomllib:
        @staticmethod
        def loads(_text):
            raise SystemExit("reading pyproject.toml needs Python 3.11 or later")


SPEC = importlib.util.spec_from_file_location(
    "composition_fixture", Path(__file__).with_name("composition_differential.py")
)
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


PACK_ERRORS = ()


def attempt(action):
    try:
        value = action()
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        if isinstance(error, PACK_ERRORS):
            # The message is the struct module's, which changes between Python versions.
            return {"error": type(error).__name__}
        return {"error": type(error).__name__, "message": str(error)}
    if isinstance(value, (bytes, bytearray)):
        return {"hex": bytes(value).hex()}
    if isinstance(value, (int, str, bool, type(None))):
        return value
    return {"repr": repr(value)}


def printed(action):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        action()
    return out.getvalue()


def classes(base):
    Packet = base.Packet

    class Foo(Packet):
        __hdr__ = (("foo", "I", 1), ("bar", "H", 2), ("baz", "4s", b"quux"))

    class Bits(Packet):
        __hdr__ = (("_a_b", "B", 0x12), ("_rsv", "B", 0), ("_c_flag", "B", 1), ("d", "B", 0))
        __bit_fields__ = {"_a_b": (("a", 4), ("b", 4))}

        @property
        def c_flag(self):
            return self.a | self.b

    class Wide(Packet):
        __hdr__ = (("_v_x_y", "I", 0x60000000), ("n", "H", 0))
        __bit_fields__ = {"_v_x_y": (("v", 4), ("_skip", 8), ("y", 20))}
        __pprint_funcs__ = {"n": hex}

    class Pair(Packet):
        __hdr__ = (("bar", "II", (1, 2)),)

    class Little(Packet):
        __byte_order__ = "<"
        __hdr__ = (("x", "H", 0x0102), ("y", "I", 3))

    class Strict(Packet):
        __hdr__ = (("test", "B", 0),)

        def unpack(self, buf):
            Packet.unpack(self, buf)
            self.attribute = struct.unpack("B", buf[1:])

    class Empty(Packet):
        pass

    return Foo, Bits, Wide, Pair, Little, Strict, Empty


def exercise(base):
    global PACK_ERRORS
    PACK_ERRORS = (base.PackError,)
    Foo, Bits, Wide, Pair, Little, Strict, Empty = classes(base)
    r = {}
    foo = Foo(bar=3)
    r["meta"] = attempt(
        lambda: [
            Foo.__hdr_fields__,
            Foo.__hdr_fmt__,
            Foo.__hdr_len__,
            sorted(Foo.__hdr_defaults__.items()),
            Foo.__slots__,
            Bits.__bit_fields_defaults__,
            Little.__hdr_fmt__,
            Wide.__bit_fields_defaults__,
        ]
    )
    r["kwargs"] = attempt(lambda: [repr(foo), bytes(foo).hex(), len(foo), dict(foo)])
    foo.foo, foo.baz = 7, b"whee"
    r["changed"] = attempt(lambda: [repr(foo), bytes(foo).hex(), str(foo), foo.pack().hex()])
    parsed = Foo(b"hello, world!", bar=9)
    r["parsed"] = attempt(
        lambda: [repr(parsed), parsed.foo, parsed.bar, parsed.baz.hex(), parsed.data.hex()]
    )
    r["extra_attr"] = attempt(lambda: repr(Foo(note=b"n", data=b"tail")))
    r["short"] = attempt(lambda: Foo(b"hello"))
    r["strict"] = attempt(lambda: Strict(b"\x00"))
    r["strict_ok"] = attempt(lambda: repr(Strict(b"\x00\x05")))
    r["overflow"] = attempt(lambda: bytes(Foo(foo=2**32)))
    r["negative"] = attempt(lambda: bytes(Foo(bar=-1)))
    r["str_field"] = attempt(lambda: bytes(Foo(baz="text")))
    r["tuple"] = attempt(lambda: bytes(Pair()))
    r["tuple_unpack"] = attempt(lambda: repr(Pair(b"\0\0\0\1\0\0\0\2tail")))
    r["tuple_bad"] = attempt(lambda: bytes(Pair(bar=(1,))))
    r["little"] = attempt(lambda: [bytes(Little()).hex(), Little(b"\x01\x00\x02\x00\x00\x00z").y])
    r["data_packet"] = attempt(lambda: bytes(Foo(data=Little())).hex())
    bits = Bits()
    r["bits_default"] = attempt(lambda: [repr(bits), bits.a, bits.b, Bits.__public_fields__])
    r["bits_parsed"] = attempt(lambda: repr(Bits(b"\x12\x11\x00\x04")))
    bits.a = 15
    r["bits_set"] = attempt(lambda: [bits._a_b, repr(bits)])
    r["bits_too_large"] = attempt(lambda: setattr(bits, "b", 16))
    r["bits_negative"] = attempt(lambda: [setattr(bits, "b", -1), bits._a_b])
    del bits.a
    r["bits_deleted"] = attempt(lambda: bits._a_b)
    wide = Wide(b"\x6f\xf1\x23\x45\x00\x10")
    r["wide"] = attempt(lambda: [wide.v, wide.y, repr(wide), Wide.__public_fields__])
    wide.y = 1
    r["wide_set"] = attempt(lambda: [wide._v_x_y, bytes(wide).hex()])
    r["pprint"] = attempt(lambda: printed(lambda: Wide(b"\x60\x00\x00\x01\x00\x10").pprint()))
    nested = Foo(note=[1, 2], data=Wide(n=5, data=b"end"))
    r["pprint_nested"] = attempt(lambda: printed(nested.pprint))
    r["pprint_empty_list"] = attempt(lambda: printed(Foo(items=[]).pprint))
    chain = Foo(data=Wide(data=Little(data=b"x")))
    r["getitem"] = attempt(
        lambda: [
            type(chain[Wide]).__name__,
            type(chain[Little]).__name__,
            Wide in chain,
            Little in chain,
            Foo in chain,
            Empty in chain,
        ]
    )
    r["getitem_missing"] = attempt(lambda: chain[Foo])
    r["empty"] = attempt(lambda: [Empty().data, repr(Empty(x=1))])
    r["empty_len"] = attempt(lambda: len(Empty()))
    r["empty_bytes"] = attempt(lambda: bytes(Empty()))
    r["empty_parse"] = attempt(lambda: Empty(b"x"))
    r["data_repr"] = attempt(lambda: repr(Foo(data=Wide(n=1))))
    sample = bytes(range(40)) + b"\\\x7f\xff"
    r["hexdump"] = attempt(
        lambda: [base.hexdump(sample), base.hexdump(sample, 8), base.hexdump(b"")]
    )
    r["cksum"] = attempt(
        lambda: [
            base.in_cksum_add(0, bytes(range(15))),
            base.in_cksum(bytes(range(15))),
            base.in_cksum(b""),
            base.in_cksum(b"\xff" * 4097),
            base.in_cksum_done(0x1FFFF),
            base.in_cksum_add(5, b"\x01"),
        ]
    )
    r["errors"] = attempt(
        lambda: [
            issubclass(base.NeedData, base.UnpackError),
            issubclass(base.UnpackError, base.Error),
            issubclass(base.PackError, base.Error),
        ]
    )
    return r


def provenance(module, version):
    package = C.provenance(module, version)
    member = "dpkt" if module == "dpkt" else "packet"
    base = importlib.import_module(module + "." + member)
    dist = importlib.metadata.distribution(module)
    origin = Path(base.__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
        "unverified Packet origin",
    )
    return package, base


# OctetRail fixes dpkt here (str() of a packet is its repr). These keys are not compared;
# tests/python checks the fixed results.
FIXED = {
    "changed",
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
        _, base = provenance(a.module, a.version)
        print(json.dumps(exercise(base)))
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
    reports = []
    for python, module, v in providers:
        r = subprocess.run(
            [python, "-B", "-I", "-O", __file__, "--probe", "--module", module, "--version", v],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        reports.append(json.loads(r.stdout))
    reference = reports[1]
    for (_, module, v), report in zip(providers[2:], reports[2:], strict=True):
        wrong = sorted(k for k in reference if k not in FIXED and report.get(k) != reference[k])
        C.require(not wrong, "Packet mismatch " + module + v + ": " + ", ".join(wrong))
    print(
        json.dumps(
            {
                "observations": len(reference),
                "providers": len(providers),
                "dpkt_196_differs_on": sorted(
                    k for k in reference if reports[0][k] != reference[k]
                ),
                "unexpected_mismatches": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
