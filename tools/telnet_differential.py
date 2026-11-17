"""Telnet option stripping run by dpkt 1.9.6, 1.9.8 and OctetRail.

Each provider parses the same messages, including dpkt's own test vectors,
builds them from keywords and packs them again. OctetRail must match dpkt
1.9.8 on every observation except the declared ones; the keys where 1.9.6
differs are listed.
"""

import argparse
import importlib
import importlib.metadata
import importlib.util
import json
import random
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

# dpkt's test vectors.
DPKT = [
    "fffb25fffa25000000fff0fffd26fffa2605fff0fffa26010102fff0fffb18fffb20fffb23fffb27fffc24fffa200033383430302c3338343030fff0fffa2300646f756768626f792e636974692e756d6963682e6564753a302e30fff0fffa270000444953504c415901646f756768626f792e636974692e756d6963682e6564753a302e30005553455201647567736f6e67fff0fffa1800585445524dfff0fffd03fffc01fffb1ffffa1f00500028fff0fffd05fffb21fffd016675676c790d00796f64610d0062617368746172640d00",
    "fffd01fffd03fffb18fffb1ffffa1f00580032fff061646d696e0d00fffa18004c494e5558fff0666f6f6261720d00656e61626c650d00666f6f6261720d000d0073686f7720697020696e7420566c616e203636360d00",
    "fffb25fffa25000000fff0fffd26fffa2605fff0fffa26010102fff0fffb26fffb18fffb20fffb23fffb27fffc24fffa200033383430302c3338343030fff0fffa2300646f756768626f792e636974692e756d6963682e6564753a302e30fff0fffa270000444953504c415901646f756768626f792e636974692e756d6963682e6564753a302e30005553455201647567736f6e67fff0fffa1800585445524dfff0fffd03fffc01fffb22fffa220301030003620304020f0500ffff07621c08020409421a0a027f0b02150c02170d02120e02160f02111002131100ffff1200fffffff0fffb1ffffa1f00500028fff0fffd05fffb21fffa22010ffff0fffd01fffe01fffa2203018000fff0fffd01776572640d0afffe01796f64610d0afffd01646172746876616465720d0afffe01",
]


def generated():
    """Buffers built from the bytes the parser treats specially."""
    rng = random.Random(1)
    alphabet = [255, 255, 250, 240, 251, 253, 0, 0, 13, 10, 1, 97] + list(b"USERDISPLAYTERM")
    return [bytes(rng.choice(alphabet) for _ in range(rng.randrange(0, 40))) for _ in range(300)]


def cases():
    """Hex input by name."""
    found = {"dpkt_%d" % i: bytes.fromhex(h) for i, h in enumerate(DPKT)}
    found.update(
        {
            "trailing_null": bytes.fromhex("0100020000"),
            "empty": b"",
            "plain_lines": b"one\r\ntwo\rthree\nfour",
            "cr_nul": b"a\r\x00b\r\x00",
            "double_newline": b"a\n\n",
            "escaped_iac": b"a\xff\xffb",
            "lone_iac": b"text\xff",
            "short_command": b"\xff\xfb",
            "sb_without_se": b"\xff\xfa\x18\x00TERM\x01vt100\x00\xffhidden\xffmore",
            "se_resumes": b"\xff\xfa\x18\x00\xff\xf0visible",
            "value_without_nul": b"\xff\xfa\x27USER\x01bob",
            "repeated_user": b"\xff\xfaUSER\x01a\x00\xff\xf0\xff\xfaUSER\x01b\x00\xff\xf0",
            "order_display_first": b"\xff\xfaTERM\x01x\x00\xff\xfaDISPLAY\x01:0\x00USER\x01u",
            "low_command": b"\xff\xf1nop text",
        }
    )
    for i, buf in enumerate(generated()):
        found["generated_%03d" % i] = buf
    return {k: v.hex() for k, v in found.items()}


def as_json(v):
    if isinstance(v, (bytes, bytearray)):
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


def exercise(package):
    strip = package.telnet.strip_options
    found = {name: attempt(lambda h=h: strip(bytes.fromhex(h))) for name, h in cases().items()}
    sample = bytes.fromhex(DPKT[0])
    return {
        "cases": found,
        "constructed": {
            "bytearray": attempt(lambda: strip(bytearray(sample))),
            "memoryview": attempt(lambda: strip(memoryview(sample))),
            "text": attempt(lambda: strip("text")),
            "constants": attempt(
                lambda: [
                    package.telnet.IAC,
                    package.telnet.SB,
                    package.telnet.SE,
                    package.telnet.xEOF,
                    package.telnet.SYNCH,
                    package.telnet.ABORT,
                ]
            ),
        },
    }


def provenance(module, version):
    package = C.provenance(module, version)
    dist = importlib.metadata.distribution(module)
    for member in ("telnet",):
        origin = Path(importlib.import_module(module + "." + member).__file__).resolve()
        C.require(
            origin.is_relative_to(Path(sys.prefix).resolve())
            and origin == Path(dist.locate_file(module + "/" + member + ".py")).resolve(),
            "unverified Telnet module origin",
        )
        setattr(package, member, importlib.import_module(module + "." + member))
    return package


# OctetRail matches 1.9.8 on every observation.
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
        wrong = sorted(k for k in reference if report.get(k) != DECLARED.get(k, reference[k]))
        C.require(not wrong, "Telnet mismatch " + module + v + ": " + ", ".join(wrong))
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
