"""Credential-free release gates and isolated Linux wheel build/test checks."""

import argparse
import ast
import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
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


def expected_names(version):
    require(bool(VERSION.fullmatch(version)), "version_format")
    return {
        cp: f"octetrail-{version}-{cp}-{cp}-manylinux_2_34_x86_64.whl" for cp in ("cp312", "cp313")
    }


def validate_wheels(directory, root, version):
    names = expected_names(version)
    require({p.name for p in directory.iterdir()} == set(names.values()), "wheel_inventory")
    legal = [root / "LICENSE", root / "NOTICE"]
    legal += [p for p in (root / "licenses").rglob("*") if p.is_file()]
    hashes = {}
    for cp, name in names.items():
        path = directory / name
        require(path.is_file() and not path.is_symlink(), "wheel_type")
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
            require(wheel.get_all("Tag") == [f"{cp}-{cp}-manylinux_2_34_x86_64"], "wheel_tag")
            for source in legal:
                require(
                    archive.read(prefix + "licenses/" + source.relative_to(root).as_posix())
                    == source.read_bytes(),
                    "wheel_legal_bytes",
                )
        hashes[cp] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def build(interpreters):
    version = source_version(ROOT)
    require(importlib.metadata.version("maturin") == "1.16.0", "maturin_version")
    require(len(interpreters) == 2, "interpreter_count")
    for executable, expected in zip(interpreters, ((3, 12), (3, 13)), strict=True):
        result = run(
            executable,
            "-I",
            "-c",
            "import sys;print(*sys.version_info[:2])",
            capture_output=True,
            text=True,
        )
        require(tuple(map(int, result.stdout.split())) == expected, "interpreter_version")
    output = ROOT / "dist"
    require(not output.exists() or not any(output.iterdir()), "output_not_empty")
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
    run(
        sys.executable,
        "-I",
        "tools/build_wheels.py",
        "--offline",
        "--interpreter",
        interpreters[0],
        "--interpreter",
        interpreters[1],
        "--out",
        output,
    )
    names = expected_names(version)
    wheels = [output / n for n in names.values()]
    hashes = validate_wheels(output, ROOT, version)
    run(sys.executable, "-I", "tools/check_wheel.py", *wheels)
    run(sys.executable, "-I", "-m", "twine", "check", "--strict", *wheels)
    for wheel in wheels:
        audit = run(
            sys.executable, "-I", "-m", "auditwheel", "show", wheel, capture_output=True, text=True
        )
        print(audit.stdout)
        require('platform tag: "manylinux_2_34_x86_64"' in audit.stdout, "symbol_policy")
    with tempfile.TemporaryDirectory(prefix="octetrail-release-test-") as directory:
        temporary = Path(directory)
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
        for cp, executable in zip(names, interpreters, strict=True):
            env = temporary / cp
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
                output / names[cp],
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
    require(validate_wheels(output, ROOT, version) == hashes, "wheel_changed_during_checks")
    write_outputs(hashes)
    print("two exact wheel files passed release checks")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("gate", "build"))
    parser.add_argument("--interpreter", action="append", default=[])
    args = parser.parse_args()
    if args.command == "gate":
        gate()
    else:
        build(args.interpreter)


if __name__ == "__main__":
    main()
