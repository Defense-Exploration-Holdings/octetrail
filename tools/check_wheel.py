"""Verify local wheel records, namespace boundaries and portable package metadata."""

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check(path, expected_version=None):
    version = (
        expected_version
        or tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    )
    require(
        bool(re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version)),
        "version format",
    )
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "duplicate wheel entry")
        require(
            {name.split("/", 1)[0] for name in names}
            == {"octetrail", f"octetrail-{version}.dist-info"},
            "wheel validation failed",
        )
        require("octetrail/capture.py" in names, "wheel validation failed")
        require(not any((name.startswith("dpkt/") for name in names)), "wheel validation failed")
        require("dpkt.py" not in names, "wheel validation failed")
        require(
            not any(
                (
                    name.endswith(".pth")
                    or Path(name).name in ("sitecustomize.py", "usercustomize.py")
                    for name in names
                )
            ),
            "wheel validation failed",
        )
        require(
            {name.split("/", 1)[0] for name in names if ".dist-info/" in name}
            == {f"octetrail-{version}.dist-info"},
            "wheel validation failed",
        )
        record_name = next((name for name in names if name.endswith(".dist-info/RECORD")))
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode())))
        require({row[0] for row in rows} == set(names), "wheel validation failed")
        for name, digest, length in rows:
            if name == record_name:
                require(digest == length == "", "wheel validation failed")
                continue
            data = archive.read(name)
            encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
            require(digest == "sha256=" + encoded.decode(), "wheel validation failed")
            require(int(length) == len(data), "wheel validation failed")
            for forbidden in (str(ROOT).encode(), b"/workspace/", b"/home/agent/"):
                require(forbidden not in data, f"build-machine path in {name}")
            if ".dist-info/sboms/" in name:
                sbom = json.loads(data)
                require(
                    sbom["metadata"]["component"]["name"] == "octetrail-python",
                    "wheel validation failed",
                )
                require(b"path+file://./" in data, "wheel validation failed")
        metadata_name = next((name for name in names if name.endswith(".dist-info/METADATA")))
        metadata = BytesParser().parsebytes(archive.read(metadata_name))
        require(
            metadata["Name"] == "octetrail" and metadata["Version"] == version,
            "wheel validation failed",
        )
        require(not metadata.get_all("Requires-Dist"), "wheel validation failed")
        require(not metadata.get_all("Provides-Dist"), "wheel validation failed")
        require(
            not any(
                (
                    metadata.get(key)
                    for key in ("Author", "Author-email", "Maintainer", "Maintainer-email")
                )
            ),
            "wheel validation failed",
        )
        for suffix in ("licenses/LICENSE", "licenses/NOTICE", "licenses/licenses/dpkt.txt"):
            require(any((name.endswith(suffix) for name in names)), "wheel validation failed")
        require(
            any(("licenses/rust/pyo3-0.30.1-LICENSE-MIT.txt" in name for name in names)),
            "wheel validation failed",
        )
        require(any(("LICENSE-UNICODE.txt" in name for name in names)), "wheel validation failed")
    print(f"{path.name}: RECORD, namespace, licenses and path checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path, nargs="+")
    for wheel in parser.parse_args().wheel:
        check(wheel)
