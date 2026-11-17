"""Synthetic release artifact layout shared by the release workflow tests."""

import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("release_ci", ROOT / "tools/release_ci.py")
R = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(R)

VERSION = "0.1.0"
NAMES = sorted(R.expected_names(VERSION).values())
ASSETS = [*NAMES, "SHA256SUMS"]


def write_manifest(root):
    """Write release/SHA256SUMS for whatever is in release/dist; return its SHA-256."""
    dist = root / "release/dist"
    text = "".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
        for p in sorted(dist.iterdir(), key=lambda p: p.name)
    )
    (root / "release/SHA256SUMS").write_text(text)
    return hashlib.sha256(text.encode()).hexdigest()


def make_release(root, label=b""):
    """Benign stand-in bytes for every expected file, laid out as the build job uploads them."""
    dist = root / "release/dist"
    dist.mkdir(parents=True)
    for name in NAMES:
        (dist / name).write_bytes(b"ordinary immutable artifact fixture " + label + name.encode())
    return write_manifest(root)
