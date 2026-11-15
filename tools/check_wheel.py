"""Verify local wheel records, namespace boundaries and portable package metadata."""

import argparse
import base64
import csv
import hashlib
import io
import json
import zipfile
from email.parser import BytesParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names)), "duplicate wheel entry"
        assert {name.split("/", 1)[0] for name in names} == {
            "octetrail",
            "octetrail-0.1.0.dist-info",
        }
        assert "octetrail/capture.py" in names
        assert not any(name.startswith("dpkt/") for name in names)
        assert "dpkt.py" not in names
        assert not any(
            name.endswith(".pth") or Path(name).name in ("sitecustomize.py", "usercustomize.py")
            for name in names
        )
        assert {name.split("/", 1)[0] for name in names if ".dist-info/" in name} == {
            "octetrail-0.1.0.dist-info"
        }
        record_name = next(name for name in names if name.endswith(".dist-info/RECORD"))
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode())))
        assert {row[0] for row in rows} == set(names)
        for name, digest, length in rows:
            if name == record_name:
                assert digest == length == ""
                continue
            data = archive.read(name)
            encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
            assert digest == "sha256=" + encoded.decode()
            assert int(length) == len(data)
            for forbidden in (str(ROOT).encode(), b"/workspace/", b"/home/agent/"):
                assert forbidden not in data, f"build-machine path in {name}"
            if ".dist-info/sboms/" in name:
                sbom = json.loads(data)
                assert sbom["metadata"]["component"]["name"] == "octetrail-python"
                assert b"path+file://./" in data
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(archive.read(metadata_name))
        assert metadata["Name"] == "octetrail" and metadata["Version"] == "0.1.0"
        assert not metadata.get_all("Requires-Dist")
        assert not metadata.get_all("Provides-Dist")
        assert not any(
            metadata.get(key)
            for key in ("Author", "Author-email", "Maintainer", "Maintainer-email")
        )
        for suffix in ("licenses/LICENSE", "licenses/NOTICE", "licenses/licenses/dpkt.txt"):
            assert any(name.endswith(suffix) for name in names)
        assert any("licenses/rust/pyo3-0.30.1-LICENSE-MIT.txt" in name for name in names)
        assert any("LICENSE-UNICODE.txt" in name for name in names)
    print(f"{path.name}: RECORD, namespace, licenses and path checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path, nargs="+")
    for wheel in parser.parse_args().wheel:
        check(wheel)
