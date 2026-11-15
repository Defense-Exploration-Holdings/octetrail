"""Build wheels locally, removing build-machine paths from their SBOM records.

Uses the pinned maturin in the invoking build environment. This script never
installs or publishes a wheel. Rust paths are remapped before compilation, and
only local component identifiers in generated SBOM text are made relative.
Dependency identifiers, licenses and hashes remain intact. RECORD is regenerated.
"""

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write_portable_wheel(source, destination):
    with zipfile.ZipFile(source) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if any(name.endswith(("RECORD.jws", "RECORD.p7s")) for name in names):
            raise ValueError("refusing to modify a signed wheel")
        record = next(name for name in names if name.endswith(".dist-info/RECORD"))
        rows = []
        with zipfile.ZipFile(destination, "w") as output:
            for info in infos:
                if info.filename == record:
                    continue
                data = archive.read(info.filename)
                if ".dist-info/sboms/" in info.filename and info.filename.endswith(".json"):
                    data = data.replace(str(ROOT).encode(), b".")
                    json.loads(data)  # Reject a malformed transformed SBOM.
                output.writestr(info, data)
                digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
                rows.append((info.filename, "sha256=" + digest.decode(), str(len(data))))
            text = io.StringIO(newline="")
            writer = csv.writer(text, lineterminator="\n")
            writer.writerows(rows)
            writer.writerow((record, "", ""))
            output.writestr(archive.getinfo(record), text.getvalue())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interpreter", action="append", required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    parser.add_argument("--offline", action="store_true", help="require a populated Cargo cache")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    encoded = environment.get("CARGO_ENCODED_RUSTFLAGS")
    flags = encoded.split("\x1f") if encoded else shlex.split(environment.get("RUSTFLAGS", ""))
    cargo_home = Path(environment.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
    flags.extend(
        [
            f"--remap-path-prefix={ROOT}=octetrail",
            f"--remap-path-prefix={cargo_home / 'registry' / 'src'}=cargo-registry",
        ]
    )
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
    with tempfile.TemporaryDirectory(prefix="octetrail-wheel-build-") as directory:
        command = [
            sys.executable,
            "-m",
            "maturin",
            "build",
            "--release",
            "--locked",
            "--out",
            directory,
        ]
        if args.offline:
            command.append("--offline")
        for interpreter in args.interpreter:
            command.extend(["--interpreter", interpreter])
        subprocess.run(command, cwd=ROOT, env=environment, check=True)
        for wheel in sorted(Path(directory).glob("*.whl")):
            destination = args.out / wheel.name
            write_portable_wheel(wheel, destination)
            print(
                f"{destination.name} sha256={hashlib.sha256(destination.read_bytes()).hexdigest()}"
            )


if __name__ == "__main__":
    main()
