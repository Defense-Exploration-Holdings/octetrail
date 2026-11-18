"""HTTP/2 frames run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same frames one at a time and as a stream, builds
them from keywords and packs them again. OctetRail must match dpkt
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


PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(kind, payload=b"", flags=0, stream=1, length=None):
    size = len(payload) if length is None else length
    return size.to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


SETTINGS = frame(4, bytes.fromhex("000300000064000400010000"), stream=0)
HEADERS = frame(1, b"\x82\x86\x84", flags=0x05)
STREAM = (
    SETTINGS + HEADERS + frame(0, b"body", flags=0x01) + frame(8, b"\x00\x00\x10\x00", stream=0)
)


def cases():
    """(target, hex) by name. Targets are a frame class, the factory or the multi factory."""
    found = {
        "data": ("FrameFactory", frame(0, b"hello")),
        "data_padded": ("FrameFactory", frame(0, b"\x02hi\x00\x00", flags=0x08)),
        "data_pad_zero": ("FrameFactory", frame(0, b"\x00hi", flags=0x08)),
        "data_pad_missing": ("FrameFactory", frame(0, b"", flags=0x08)),
        "data_pad_too_long": ("FrameFactory", frame(0, b"\x05hi", flags=0x08)),
        "headers": ("FrameFactory", HEADERS),
        "headers_priority": ("FrameFactory", frame(1, b"\x80\x00\x00\x03\x0fblock", flags=0x24)),
        "headers_priority_short": ("FrameFactory", frame(1, b"\x00\x00", flags=0x20)),
        "priority": ("FrameFactory", frame(2, b"\x80\x00\x00\x05\x10")),
        "priority_long": ("FrameFactory", frame(2, b"\x00\x00\x00\x05\x10x")),
        "priority_short": ("FrameFactory", frame(2, b"\x00\x00")),
        "rst_stream": ("FrameFactory", frame(3, b"\x00\x00\x00\x08")),
        "rst_stream_bad": ("FrameFactory", frame(3, b"\x00\x08")),
        "settings": ("FrameFactory", SETTINGS),
        "settings_ack": ("FrameFactory", frame(4, flags=0x01, stream=0)),
        "settings_bad": ("FrameFactory", frame(4, b"\x00\x03\x00")),
        "push_promise": ("FrameFactory", frame(5, b"\x00\x00\x00\x02block")),
        "push_promise_padded": ("FrameFactory", frame(5, b"\x01\x00\x00\x00\x02b\x00", flags=0x08)),
        "push_promise_short": ("FrameFactory", frame(5, b"\x00\x00")),
        "ping": ("FrameFactory", frame(6, b"12345678", stream=0)),
        "ping_bad": ("FrameFactory", frame(6, b"1234")),
        "goaway": ("FrameFactory", frame(7, b"\x00\x00\x00\x03\x00\x00\x00\x01debug", stream=0)),
        "goaway_short": ("FrameFactory", frame(7, b"\x00\x00\x00\x03")),
        "window_update": ("FrameFactory", frame(8, b"\x00\x00\x10\x00")),
        "window_update_bad": ("FrameFactory", frame(8, b"\x00")),
        "continuation": ("FrameFactory", frame(9, b"\x82", flags=0x04)),
        "unknown_type": ("FrameFactory", frame(10, b"x")),
        "factory_short": ("FrameFactory", b"\x00\x00\x00"),
        "frame_cut": ("FrameFactory", frame(0, b"abc", length=9)),
        "frame_header_short": ("FrameFactory", frame(0)[:6]),
        "frame_extra": ("Frame", frame(0, b"abc") + b"next"),
        "preface": ("Preface", PREFACE + b"rest"),
        "preface_bad": ("Preface", b"GET / HTTP/1.1\r\n\r\nxxxxxxxxxx"),
        "preface_short": ("Preface", PREFACE[:10]),
        "multi": ("multi", STREAM),
        "multi_preface": ("multi_preface", PREFACE + STREAM),
        "multi_preface_short": ("multi_preface", PREFACE[:10]),
        "multi_preface_bad": ("multi_preface", b"x" * 30),
        "multi_tail_cut": ("multi", STREAM + frame(0, b"abc", length=9)),
        "multi_tail_header": ("multi", STREAM + b"\x00\x00\x01\x00"),
        "multi_tail_unknown": ("multi", STREAM + b"\x00\x00\x01\x0e\x00"),
        "multi_tail_three": ("multi", STREAM + b"\x00\x00\x01"),
        "multi_inner_needdata": ("multi", SETTINGS + frame(2, b"\x00\x00") + HEADERS),
        "multi_inner_error": ("multi", SETTINGS + frame(6, b"1234") + HEADERS),
        "multi_unknown_middle": ("multi", SETTINGS + frame(12, b"x") + HEADERS),
        "multi_empty": ("multi", b""),
        "multi_many": ("multi", frame(0, b"x") * 400),
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
        return as_json(action())
    except Exception as error:  # noqa: BLE001 - exceptions are observations.
        return {"error": type(error).__name__, "message": str(error)}


EXTRA = (
    "length",
    "pad_length",
    "unpadded_data",
    "block_fragment",
    "error_code",
    "settings",
    "last_stream_id",
    "debug_data",
    "window_increment",
    "exclusive",
    "promised_id",
    "payload",
)


def snapshot(packet):
    found = {"class": type(packet).__name__, "repr": repr(packet)}
    found["len"] = attempt(lambda: len(packet))
    found["bytes"] = attempt(lambda: bytes(packet).hex())
    found["fields"] = {
        k: snapshot(v) if hasattr(v, "__hdr__") else repr(v)
        for k, v in sorted(vars(packet).items())
        if k[0] != "_"
    }
    found["extra"] = {
        k: attempt(lambda k=k: [snapshot(x) for x in getattr(packet, k)])
        if k == "settings"
        else attempt(lambda k=k: getattr(packet, k))
        for k in EXTRA
        if hasattr(packet, k)
    }
    return found


def parse(package, target, raw):
    h2 = package.http2
    if target == "multi":
        frames, used = h2.frame_multi_factory(raw)
        return [[snapshot(f) for f in frames], used]
    if target == "multi_preface":
        frames, used = h2.frame_multi_factory(raw, preface=True)
        return [[snapshot(f) for f in frames], used]
    return snapshot(getattr(h2, target)(raw))


def constructed(package):
    h2 = package.http2

    def built():
        found = []
        for cls in (h2.Frame, h2.DataFrame, h2.SettingsFrame, h2.PingFrame):
            packet = cls(length_bytes=b"\x00\x00\x04", type=6, data=b"abcd")
            found.append([bytes(packet).hex(), packet.length, len(packet)])
        settings = h2.SettingsFrame(length_bytes=b"\x00\x00\x06", type=4)
        settings.data = bytes(h2.Setting(identifier=3, value=100))
        found.append(bytes(settings).hex())
        return found

    return {
        "default_frame": attempt(lambda: snapshot(h2.Frame())),
        "default_preface": attempt(lambda: [repr(h2.Preface()), bytes(h2.Preface()).hex()]),
        "default_priority": attempt(lambda: snapshot(h2.Priority())),
        "default_setting": attempt(lambda: snapshot(h2.Setting())),
        "built": attempt(built),
        "bytearray_multi": attempt(lambda: parse(package, "multi", bytearray(STREAM))),
        "exception_mro": attempt(lambda: [c.__name__ for c in h2.HTTP2Exception.__mro__]),
        "frame_types": attempt(
            lambda: sorted((k, v[0], v[1].__name__) for k, v in h2.FRAME_TYPES.items())
        ),
        "error_code_str": attempt(lambda: sorted(h2.error_code_str.items())),
        "constants": attempt(
            lambda: sorted(
                (k, getattr(h2, k))
                for k in dir(h2)
                if k.startswith("HTTP2_") and isinstance(getattr(h2, k), (int, bytes))
            )
        ),
    }


def _raised(action):
    try:
        action()
    except Exception as error:  # noqa: BLE001 - the error is the observation.
        return error
    return None


def exercise(package):
    return {
        "cases": {
            name: attempt(lambda t=t, h=h: parse(package, t, bytes.fromhex(h)))
            for name, (t, h) in cases().items()
        },
        "constructed": constructed(package),
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    origin = Path(importlib.import_module(module + ".http2").__file__).resolve()
    C.require(
        origin.is_relative_to(Path(sys.prefix).resolve())
        and origin == Path(dist.locate_file(module + "/http2.py")).resolve(),
        "unverified HTTP/2 module origin",
    )
    package.http2 = importlib.import_module(module + ".http2")
    return package


# Observations where OctetRail differs from 1.9.8 on purpose: HTTP2Exception is
# also an UnpackError. The errors raised keep dpkt's class name and message.
DECLARED = {
    "constructed.exception_mro": [
        "HTTP2Exception",
        "UnpackError",
        "Error",
        "Exception",
        "BaseException",
        "object",
    ],
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
        C.require(not wrong, "HTTP/2 mismatch " + module + v + ": " + ", ".join(wrong))
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
