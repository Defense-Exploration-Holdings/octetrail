# Wheel builds and releases

The [release workflow](../.github/workflows/release.yml) runs on pull requests,
pushes to `main`, `v*` tags and manual dispatch. Every run builds and tests the
same files a release would publish. Only a protected version tag in this
repository can publish them.

## What is built

| File | Platform | Tested on |
| --- | --- | --- |
| `octetrail-X.Y.Z-cp310-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` | Linux x86-64, glibc 2.17+ | Ubuntu 24.04, CPython 3.10 and 3.14 |
| `octetrail-X.Y.Z-cp310-abi3-manylinux2014_aarch64.manylinux_2_17_aarch64.whl` | Linux arm64, glibc 2.17+ | Ubuntu 24.04 arm64, CPython 3.10 and 3.14 |
| `octetrail-X.Y.Z-cp310-abi3-musllinux_1_2_x86_64.whl` | Linux x86-64, musl 1.2+ | Alpine (python:3.10-alpine, python:3.14-alpine) |
| `octetrail-X.Y.Z-cp310-abi3-musllinux_1_2_aarch64.whl` | Linux arm64, musl 1.2+ | Alpine arm64, same images |
| `octetrail-X.Y.Z-cp310-abi3-macosx_10_12_x86_64.whl` | macOS 10.12+ on Intel | macOS 15 Intel, CPython 3.10 and 3.14 |
| `octetrail-X.Y.Z-cp310-abi3-macosx_11_0_arm64.whl` | macOS 11+ on Apple silicon | macOS 15, CPython 3.10 and 3.14 |
| `octetrail-X.Y.Z-cp310-abi3-win_amd64.whl` | Windows x64 | Windows Server 2025, CPython 3.10 and 3.14 |
| `octetrail-X.Y.Z-cp310-abi3-win_arm64.whl` | Windows arm64 | Windows 11 arm64, CPython 3.11 and 3.14 |
| `octetrail-X.Y.Z.tar.gz` | source distribution | built into a wheel from the unpacked archive and tested on CPython 3.14 |

The wheels use the CPython stable ABI (abi3) from 3.10, so one wheel per
platform works on CPython 3.10 and every later version. Free-threaded CPython
builds and PyPy are not covered by abi3 wheels; they can build from the source
distribution, which needs Rust 1.85 or later.

Linux wheels are linked with zig against the manylinux2014 and musllinux_1_2
baselines. `auditwheel` checks the glibc wheels' symbol policy. Every wheel is
also checked for its file records, package namespace, metadata, license files
and the absence of build-machine paths.

## Jobs

1. `gate` decides, without credentials, whether this run may publish.
2. `check` runs `cargo fmt`, Clippy, the Rust tests, Ruff and the release
   tooling tests.
3. `wheels` builds one wheel per platform with `tools/build_wheels.py` and runs
   the Python test suite against the installed wheel on that platform.
4. `sdist` builds the source distribution, builds a wheel from it and tests it.
5. `build` collects all nine files, checks the exact file list and every file's
   metadata, runs `twine check --strict`, compares the Linux x86-64 wheel with
   the two pinned dpkt references on CPython 3.10 and 3.14, and writes
   `SHA256SUMS`. Its artifact holds exactly those files.
6. `release` and `pypi` publish that artifact (see below).

All jobs except `release` and `pypi` have read-only repository permissions.

## Cutting a release

Set the same version in `pyproject.toml`, both Cargo manifests,
`python/octetrail/__init__.py` and `Cargo.lock`, add release notes, merge, and
push a `vX.Y.Z` tag on that commit of `main`. Only stable `X.Y.Z` versions are
accepted.

A run can publish only when all of these hold: it is the first attempt of an
initial, unforced push of a protected `v*` tag in
`Defense-Exploration-Holdings/octetrail`; the tag matches every version
declaration; the tag and checkout are the same commit; that commit is on `main`;
and every build job succeeded. Pull requests, branches, forks, manual runs and
complete reruns cannot publish.

## GitHub Release

The `release` job runs when the repository variable `WHEEL_RELEASES_ENABLED` is
`true`, in the `github-release` environment, with `contents: write` and no
checkout or project code. It downloads the `build` artifact by its ID from the
same run, checks `SHA256SUMS` against the digest reported by `build` and every
file against `SHA256SUMS`, and then:

- refuses to continue if a published release or someone else's draft exists for
  the tag, or if the tag no longer points at the built commit on `main`;
- creates a draft, uploads the nine files and `SHA256SUMS`, checks every
  uploaded asset's name, size and digest, and publishes the draft.

It never deletes, replaces or overwrites an asset. If the job fails after the
draft exists, rerun only the failed `release` job while the artifact is still
retained (seven days). It resumes only a draft created by the same run and
artifact, uploads only missing assets, and checks the complete set before
publishing. Anything else stops the job for manual review.

## PyPI

The `pypi` job runs when `PYPI_PUBLISHING_ENABLED` is `true`, in the `pypi`
environment, with only `id-token: write` (Trusted Publishing, no stored token).
It applies the same file checks and then uploads the nine files with the pinned
`pypa/gh-action-pypi-publish` action, with attestations and metadata checks on
and existing files treated as errors.

The Trusted Publisher on PyPI uses owner `Defense-Exploration-Holdings`,
repository `octetrail`, workflow `release.yml` and environment `pypi`.

## Repository settings

These are configured on GitHub, not in this repository:

1. Protect `main` against force pushes and deletion.
2. Protect `v*` tags: restrict who can create them and block updates and
   deletion, so eligible tags report `ref_protected`.
3. Give the `github-release` and `pypi` environments required reviewers and
   limit them to `v*` tags.
4. Keep the default `GITHUB_TOKEN` permission read-only.
