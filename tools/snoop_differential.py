"""Snoop capture files run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider reads the same files, parses and builds both headers, and writes
packets with the same timestamps. OctetRail must match dpkt 1.9.8 on every
observation except the declared ones; the keys where 1.9.6 differs are listed.
"""

import argparse
import importlib
import importlib.metadata
import importlib.util
import io
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


MAGIC = bytes.fromhex("736e6f6f70000000")


def file_header(linktype=4, version=2, magic=MAGIC):
    return magic + version.to_bytes(4, "big") + linktype.to_bytes(4, "big")


def record(data, orig=None, incl=None, rec=None, drops=0, sec=1, usec=0, pad=None):
    if pad is None:
        pad = (4 - len(data)) & 3
    incl = len(data) if incl is None else incl
    orig = incl if orig is None else orig
    rec = 24 + len(data) + pad if rec is None else rec
    fields = (orig, incl, rec, drops, sec, usec)
    return b"".join(v.to_bytes(4, "big") for v in fields) + data + bytes(pad)


def files():
    """Hex by name."""
    one = record(b"abcde", sec=100, usec=250000)
    found = {
        "empty": b"",
        "header_short": file_header()[:15],
        "header_only": file_header(),
        "bad_magic": file_header(magic=b"\xd4\xc3\xb2\xa1" + bytes(4)),
        "linktype_fddi": file_header(8) + one,
        "linktype_other": file_header(9),
        "version_1": file_header(version=1) + one,
        "one": file_header() + one,
        "two": file_header() + one + record(b"x" * 8, sec=2**32 - 1, usec=999999),
        "unpadded_aligned": file_header() + record(b"abcd"),
        "no_padding_written": file_header() + record(b"abc", pad=0) + record(b"z"),
        "extra_padding": file_header() + record(b"ab", pad=6) + record(b"z"),
        "incl_short": file_header() + record(b"abcdef", incl=2),
        "incl_long": file_header() + record(b"abcd", incl=40),
        "orig_and_drops": file_header() + record(b"abcd", orig=1500, drops=7),
        "usec_overflow": file_header() + record(b"abcd", usec=2_500_000),
        "rec_short": file_header() + record(b"abcd", rec=10) + record(b"next"),
        "rec_zero": file_header() + record(b"abcd", rec=0),
        "rec_24": file_header() + record(b"abcd", rec=24) + record(b"next"),
        "rec_past_end": file_header() + record(b"abcd", rec=1000),
        "rec_huge": file_header() + record(b"abcd", rec=2**32 - 1),
        "record_cut": file_header() + one[:10],
        "record_body_cut": file_header() + one[:26],
        "trailing_byte": file_header() + one + b"\x00",
    }
    return {k: v.hex() for k, v in found.items()}


def as_json(v):
    if isinstance(v, (bytes, bytearray)):
        return {"hex": bytes(v).hex()}
    if isinstance(v, float):
        return {"float": v.hex()}
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
    # struct error messages differ between Python versions, so only the class is kept.
    found = attempt(action)
    return found.get("error", "packed") if isinstance(found, dict) else found


def snapshot(packet):
    found = {"class": type(packet).__name__, "repr": repr(packet)}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {k: repr(getattr(packet, k)) for k in packet.__hdr_fields__}
    found["data"] = repr(packet.data)
    return found


def read(snoop, raw):
    def run():
        reader = snoop.Reader(io.BytesIO(raw))
        found = {"datalink": reader.datalink(), "dloff": reader.dloff, "name": reader.name}
        found["filter"] = reader.filter
        found["packets"] = []
        while True:
            try:
                found["packets"].append(next(reader))
            except StopIteration:
                break
            except Exception as error:  # noqa: BLE001 - the error ends the file.
                found["packets"].append({"error": type(error).__name__, "message": str(error)})
                break
        return found

    return attempt(run)


def builtin_classes(action):
    try:
        action()
    except Exception as error:  # noqa: BLE001 - the error is the observation.
        return [c.__name__ for c in type(error).__mro__ if c.__module__ == "builtins"]
    return None


def written(snoop):
    def write(action, *args, **kwargs):
        def run():
            out = io.BytesIO()
            writer = snoop.Writer(out, *args, **kwargs)
            action(writer)
            return out.getvalue()

        return attempt(run)

    class Milli(snoop.Writer):
        precision_multiplier = 1000

    def milli():
        out = io.BytesIO()
        Milli(out).writepkt(b"abc", ts=1.5)
        return out.getvalue()

    stamps = (0, 1, 1.5, 0.0000004, 0.0000005, 0.0000015, 1.9999999, 1.9999994, 2**32 - 1)
    return {
        "header_only": write(lambda w: None),
        "linktype": write(lambda w: None, linktype=snoop.SDL_FDDI),
        "linktype_keyword_huge": kind(lambda: write(lambda w: None, linktype=2**32)),
        "stamps": write(lambda w: [w.writepkt(b"p" * (i % 5), ts=t) for i, t in enumerate(stamps)]),
        "writepkts": write(lambda w: w.writepkts([(1.25, b""), (2, b"abcdefg"), (3.5, b"q" * 9)])),
        "writepkt_time": write(lambda w: w.writepkt_time(b"abc", 7.000001)),
        "packet_object": write(lambda w: w.writepkt(snoop.PktHdr(ts_sec=3), ts=4)),
        "negative_ts": kind(lambda: write(lambda w: w.writepkt(b"a", ts=-1))),
        "ts_too_big": kind(lambda: write(lambda w: w.writepkt(b"a", ts=2**32))),
        "str_packet": write(lambda w: w.writepkts([(1, "text")])),
        "milli": attempt(milli),
        "now_is_recent": attempt(lambda: _now_written(snoop)),
    }


def _now_written(snoop):
    import time

    out = io.BytesIO()
    before = int(time.time())
    snoop.Writer(out).writepkt(b"abc")
    sec = int.from_bytes(out.getvalue()[16 + 16 : 16 + 20], "big")
    return before <= sec <= before + 5


def reader_api(snoop):
    raw = bytes.fromhex(files()["two"])

    def dispatch(cnt):
        seen = []
        count = snoop.Reader(io.BytesIO(raw)).dispatch(
            cnt, lambda ts, pkt, *a: seen.append([ts, pkt, a]), 1, "x"
        )
        return [count, seen]

    def loop():
        seen = []
        count = snoop.Reader(io.BytesIO(raw)).loop(lambda ts, pkt: seen.append([ts, pkt]))
        return [count, seen]

    class Named(io.BytesIO):
        name = "capture.snoop"

    return {
        "readpkts": attempt(lambda: snoop.Reader(io.BytesIO(raw)).readpkts()),
        "iter_is_self": attempt(lambda: (lambda r: iter(r) is r)(snoop.Reader(io.BytesIO(raw)))),
        "next_alias": attempt(lambda: snoop.Reader(io.BytesIO(raw)).next()),
        "dispatch_1": attempt(lambda: dispatch(1)),
        "dispatch_5": attempt(lambda: dispatch(5)),
        "dispatch_0": attempt(lambda: dispatch(0)),
        "dispatch_negative": attempt(lambda: dispatch(-1)),
        "loop": attempt(loop),
        "named": attempt(lambda: snoop.Reader(Named(raw)).name),
        "setfilter": attempt(lambda: snoop.Reader(io.BytesIO(raw)).setfilter("tcp")),
        "fileno_bytesio": attempt(lambda: snoop.Reader(io.BytesIO(raw)).fileno()),
        "bytearray_file": attempt(lambda: snoop.Reader(io.BytesIO(bytearray(raw))).readpkts()),
        "header_error_classes": attempt(
            lambda: builtin_classes(
                lambda: snoop.Reader(io.BytesIO(bytes.fromhex(files()["bad_magic"])))
            )
        ),
        "linktype_error_classes": attempt(
            lambda: builtin_classes(
                lambda: snoop.Reader(io.BytesIO(bytes.fromhex(files()["linktype_fddi"])))
            )
        ),
        "linktype_error_args": attempt(
            lambda: _raised(lambda: snoop.Reader(io.BytesIO(file_header(9)))).args
        ),
        "close": attempt(lambda: _closed(snoop)),
    }


def _closed(snoop):
    out = io.BytesIO()
    writer = snoop.Writer(out)
    writer.close()
    return out.closed


def _raised(action):
    try:
        action()
    except Exception as error:  # noqa: BLE001 - the error is the observation.
        return error
    return None


def headers(snoop):
    pkt = record(b"abcd", orig=60, drops=2, sec=5, usec=6)
    return {
        "pkthdr_default": attempt(lambda: snapshot(snoop.PktHdr())),
        "filehdr_default": attempt(lambda: snapshot(snoop.FileHdr())),
        "pkthdr_parse": attempt(lambda: snapshot(snoop.PktHdr(pkt))),
        "filehdr_parse": attempt(lambda: snapshot(snoop.FileHdr(file_header(9, 1) + b"rest"))),
        "pkthdr_short": attempt(lambda: snapshot(snoop.PktHdr(pkt[:23]))),
        "filehdr_short": attempt(lambda: snapshot(snoop.FileHdr(b"snoop"))),
        "pkthdr_keywords": attempt(
            lambda: snapshot(snoop.PktHdr(incl_len=4, rec_len=28, data=b"abcd"))
        ),
        "filehdr_bad_value": kind(lambda: bytes(snoop.FileHdr(v=-1))),
        "constants": attempt(
            lambda: sorted(
                (k, getattr(snoop, k))
                for k in dir(snoop)
                if (k.startswith("SDL_") or k.startswith("SNOOP_"))
                and isinstance(getattr(snoop, k), int)
            )
        ),
        "dltoff": attempt(lambda: sorted(snoop.dltoff.items())),
        "hdr_lens": attempt(lambda: [snoop.PktHdr.__hdr_len__, snoop.FileHdr.__hdr_len__]),
        "precision": attempt(lambda: snoop.Writer.precision_multiplier),
    }


def exercise(package):
    snoop = package.snoop
    return {
        "files": {name: read(snoop, bytes.fromhex(h)) for name, h in files().items()},
        "headers": headers(snoop),
        "written": written(snoop),
        "reader": reader_api(snoop),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".snoop").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/snoop.py")).resolve(),
        "unverified snoop module origin",
    )
    package.snoop = importlib.import_module(module + ".snoop")
    return package


# Observations where OctetRail differs from 1.9.8 on purpose: a file without
# the snoop magic and a link type with no known offset raise errors that are
# also UnpackError subclasses, with dpkt's messages.
DECLARED = {
    "files.bad_magic": {"error": "HeaderError", "message": "invalid snoop header"},
    "files.linktype_fddi": {"error": "LinktypeError", "message": "8"},
    "files.linktype_other": {"error": "LinktypeError", "message": "9"},
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
        C.require(not wrong, "snoop mismatch " + module + v + ": " + ", ".join(wrong))
    print(
        json.dumps(
            {
                "files": len(files()),
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
