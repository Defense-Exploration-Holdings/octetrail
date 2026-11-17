"""Credential-free release gates, source checks and checks of the collected release files."""

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: only release tooling reads TOML.
    tomllib = None
import zipfile
from email.parser import BytesParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = "Defense-Exploration-Holdings/octetrail"
REPOSITORY_ID = 1457516742
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def run(*args, cwd=ROOT, **kwargs):
    return subprocess.run([str(a) for a in args], cwd=cwd, check=True, **kwargs)


def source_version(root):
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    version = project["version"]
    require(project["name"] == "octetrail" and bool(VERSION.fullmatch(version)), "version_format")
    for path in ("Cargo.toml", "bindings/python/Cargo.toml"):
        require(
            tomllib.loads((root / path).read_text())["package"]["version"] == version,
            "version_metadata_mismatch",
        )
    module = ast.parse((root / "python/octetrail/__init__.py").read_text())
    declared = [
        ast.literal_eval(node.value)
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        )
    ]
    require(declared == [version], "python_version_mismatch")
    return version


def publication_candidate(env, event, version):
    """Only an initial protected tag push in the canonical public repository."""
    repo = event.get("repository", {})
    return (
        env.get("GITHUB_EVENT_NAME") == "push"
        and env.get("GITHUB_REPOSITORY") == CANONICAL
        and repo.get("full_name") == CANONICAL
        and repo.get("id") == REPOSITORY_ID
        and repo.get("private") is False
        and repo.get("default_branch") == "main"
        and env.get("GITHUB_REF_TYPE") == "tag"
        and env.get("RELEASE_REF_PROTECTED") == "true"
        and env.get("GITHUB_REF") == "refs/tags/v" + version
        and env.get("GITHUB_RUN_ATTEMPT") == "1"
        and event.get("created") is True
        and event.get("deleted") is False
        and event.get("forced") is False
        and event.get("ref") == env.get("GITHUB_REF")
    )


def verify_history(root, sha, ref):
    require(bool(re.fullmatch(r"[0-9a-f]{40}", sha)), "source_sha")
    require(bool(re.fullmatch(r"refs/tags/v" + VERSION.pattern, ref)), "tag_format")

    def git(*args):
        return run("git", "--no-replace-objects", *args, cwd=root, capture_output=True, text=True)

    require(git("rev-parse", "HEAD").stdout.strip() == sha, "checkout_sha_mismatch")
    require(git("rev-parse", ref + "^{commit}").stdout.strip() == sha, "tag_sha_mismatch")
    git("merge-base", "--is-ancestor", sha, "refs/remotes/origin/main")


def write_outputs(values):
    destination = os.environ.get("GITHUB_OUTPUT")
    if destination:
        with Path(destination).open("a") as output:
            for key, value in values.items():
                require("\n" not in str(value) and "\r" not in str(value), "output_format")
                output.write(f"{key}={value}\n")


def gate():
    version = source_version(ROOT)
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    candidate = publication_candidate(os.environ, event, version)
    # Invalid public tag pushes fail before a wheel can be offered for publication.
    if (
        os.environ.get("GITHUB_EVENT_NAME") == "push"
        and os.environ.get("GITHUB_REPOSITORY") == CANONICAL
        and os.environ.get("GITHUB_REF_TYPE") == "tag"
    ):
        require(candidate, "publication_gate_rejected")
    if candidate:
        verify_history(ROOT, os.environ.get("GITHUB_SHA", ""), os.environ["GITHUB_REF"])
    write_outputs({"publish": str(candidate).lower(), "version": version})
    print("release gate: " + ("protected tag verified" if candidate else "build/test only"))


# Platform tags of the release wheels, keyed by build name. Every wheel uses the stable ABI
# (abi3) from CPython 3.10, so one wheel per platform covers every later CPython.
PLATFORMS = {
    "linux-x86_64": "manylinux2014_x86_64.manylinux_2_17_x86_64",
    "linux-aarch64": "manylinux2014_aarch64.manylinux_2_17_aarch64",
    "musllinux-x86_64": "musllinux_1_2_x86_64",
    "musllinux-aarch64": "musllinux_1_2_aarch64",
    "macos-x86_64": "macosx_10_12_x86_64",
    "macos-arm64": "macosx_11_0_arm64",
    "windows-x64": "win_amd64",
    "windows-arm64": "win_arm64",
}
ABI = "cp310-abi3"
TEST_PYTHONS = ((3, 10), (3, 14))


def expected_names(version):
    require(bool(VERSION.fullmatch(version)), "version_format")
    names = {key: f"octetrail-{version}-{ABI}-{tag}.whl" for key, tag in PLATFORMS.items()}
    names["sdist"] = f"octetrail-{version}.tar.gz"
    return names


def legal_files(root):
    legal = [root / "LICENSE", root / "NOTICE"]
    legal += sorted(p for p in (root / "licenses").rglob("*") if p.is_file())
    return legal


def validate_wheel(path, root, version, platform):
    with zipfile.ZipFile(path) as archive:
        members = archive.namelist()
        require(len(set(members)) == len(members), "wheel_duplicate")
        require(archive.testzip() is None, "wheel_crc")
        require(
            all(not n.startswith("/") and ".." not in Path(n).parts for n in members),
            "wheel_path",
        )
        prefix = f"octetrail-{version}.dist-info/"
        meta = BytesParser().parsebytes(archive.read(prefix + "METADATA"))
        require(meta["Name"] == "octetrail" and meta["Version"] == version, "wheel_metadata")
        wheel = BytesParser().parsebytes(archive.read(prefix + "WHEEL"))
        tags = sorted(f"{ABI}-{tag}" for tag in platform.split("."))
        require(sorted(wheel.get_all("Tag") or []) == tags, "wheel_tag")
        for source in legal_files(root):
            relative = source.relative_to(root).as_posix()
            require(
                archive.read(prefix + "licenses/" + relative) == source.read_bytes(),
                f"wheel_legal_bytes: {path.name} {relative}",
            )


def validate_sdist(path, root, version):
    top = f"octetrail-{version}"
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        require(len(set(names)) == len(names), "sdist_duplicate")
        for member in members:
            parts = Path(member.name).parts
            require(
                parts[:1] == (top,) and ".." not in parts and not member.name.startswith("/"),
                "sdist_path",
            )
            require(member.isfile() or member.isdir(), "sdist_member_type")
            require(
                not any(part in {".git", ".github", "target", "dist"} for part in parts[1:]),
                "sdist_private_path",
            )
        info = BytesParser().parsebytes(archive.extractfile(top + "/PKG-INFO").read())
        require(info["Name"] == "octetrail" and info["Version"] == version, "sdist_metadata")
        for source in [*legal_files(root), root / "Cargo.lock", root / "pyproject.toml"]:
            member = archive.extractfile(top + "/" + source.relative_to(root).as_posix())
            require(member is not None and member.read() == source.read_bytes(), "sdist_bytes")


def validate_dist(directory, root, version):
    """Exactly the expected wheels and sdist, each well formed; returns name -> SHA-256."""
    names = expected_names(version)
    require({p.name for p in directory.iterdir()} == set(names.values()), "dist_inventory")
    hashes = {}
    for key, name in names.items():
        path = directory / name
        require(path.is_file() and not path.is_symlink(), "dist_type")
        if key == "sdist":
            validate_sdist(path, root, version)
        else:
            validate_wheel(path, root, version, PLATFORMS[key])
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def manifest_text(hashes):
    return "".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items()))


def check():
    """Source checks that do not depend on a built artifact."""
    run("cargo", "fetch", "--locked")
    run("cargo", "fmt", "--check")
    run(
        "cargo",
        "clippy",
        "--locked",
        "--offline",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    )
    run("cargo", "test", "--locked", "--offline", "--workspace")
    run("cargo", "test", "--locked", "--offline", "--doc")
    for args in (("check",), ("format", "--check")):
        run(
            sys.executable,
            "-I",
            "-m",
            "ruff",
            *args,
            "python",
            "tools",
            "tests/python",
            "tests/consumers",
            "tests/release",
        )
    run(sys.executable, "-B", "-I", "-m", "unittest", "discover", "-s", "tests/release", "-v")
    print("source checks passed")


def interpreter_version(executable):
    result = run(
        executable,
        "-I",
        "-c",
        "import sys;print(*sys.version_info[:2])",
        capture_output=True,
        text=True,
    )
    return tuple(map(int, result.stdout.split()))


def verify(directory, interpreters, manifest):
    """Check the collected release files, then test the Linux x86-64 wheel against dpkt."""
    version = source_version(ROOT)
    require(len(interpreters) == len(TEST_PYTHONS), "interpreter_count")
    for executable, expected in zip(interpreters, TEST_PYTHONS, strict=True):
        require(interpreter_version(executable) == expected, "interpreter_version")
    names = expected_names(version)
    hashes = validate_dist(directory, ROOT, version)
    wheels = [directory / n for k, n in names.items() if k != "sdist"]
    run(sys.executable, "-I", "tools/check_wheel.py", *wheels)
    run(sys.executable, "-I", "-m", "twine", "check", "--strict", *directory.iterdir())
    # auditwheel analyses glibc wheels on this glibc host; musl wheels are tested in Alpine.
    for key in ("linux-x86_64", "linux-aarch64"):
        audit = run(
            sys.executable,
            "-I",
            "-m",
            "auditwheel",
            "show",
            directory / names[key],
            capture_output=True,
            text=True,
        )
        print(audit.stdout)
        policy = PLATFORMS[key].split(".")[-1]
        require(
            re.search(r'platform tag[^"]*"' + re.escape(policy) + '"', audit.stdout) is not None,
            "symbol_policy",
        )
    with tempfile.TemporaryDirectory(prefix="octetrail-release-test-") as temporary_name:
        temporary = Path(temporary_name)
        oracles = []
        for v in ("1.9.6", "1.9.8"):
            env = temporary / ("oracle-" + v)
            run(interpreters[0], "-I", "-m", "venv", "--without-pip", env)
            python = env / "bin/python"
            run(
                sys.executable,
                "-I",
                "-m",
                "pip",
                "--isolated",
                "--python",
                python,
                "install",
                "--index-url",
                "https://pypi.org/simple",
                "--require-hashes",
                "--only-binary=:all:",
                "-r",
                ROOT / f"tools/oracle-{v}.txt",
            )
            oracles.append(python)
        for index, executable in enumerate(interpreters):
            env = temporary / f"candidate-{index}"
            run(executable, "-I", "-m", "venv", "--without-pip", env)
            python = env / "bin/python"
            run(
                sys.executable,
                "-I",
                "-m",
                "pip",
                "--isolated",
                "--python",
                python,
                "install",
                "--no-index",
                "--no-deps",
                directory / names["linux-x86_64"],
            )
            run(sys.executable, "-I", "-m", "pip", "--isolated", "--python", python, "check")
            run(
                python,
                "-B",
                "-I",
                "-m",
                "unittest",
                "discover",
                "-s",
                ROOT / "tests/python",
                "-v",
                cwd=temporary,
            )
            run(
                sys.executable,
                "-I",
                "tools/wheel_differential.py",
                "--python",
                python,
                "--oracle-196",
                oracles[0],
                "--oracle-198",
                oracles[1],
            )
    require(validate_dist(directory, ROOT, version) == hashes, "dist_changed_during_checks")
    text = manifest_text(hashes)
    manifest.write_text(text)
    write_outputs({"manifest": hashlib.sha256(text.encode()).hexdigest()})
    print(f"{len(hashes)} release files passed release checks")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("gate", "check", "verify"))
    parser.add_argument("--interpreter", action="append", default=[])
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    parser.add_argument("--manifest", type=Path, default=ROOT / "SHA256SUMS")
    args = parser.parse_args()
    if args.command == "gate":
        gate()
    elif args.command == "check":
        check()
    else:
        verify(args.dist, args.interpreter, args.manifest)


if __name__ == "__main__":
    main()
