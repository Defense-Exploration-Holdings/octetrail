# Contributing to OctetRail

Thanks for helping. This file covers what a change needs before it can be merged.

## Before you start

- For a bug, open an issue with the OctetRail version, Python version, platform and
  the smallest capture file or byte string that shows the problem.
- For a security problem, do not open an issue. Follow [SECURITY.md](SECURITY.md).
- For a larger change, such as a new protocol module or a change to the public API,
  open an issue first so the approach can be agreed before you write the code.

## Compatibility with dpkt

OctetRail aims to behave like dpkt 1.9.8: the same parsed fields, the same packed
bytes and the same exception classes for the same input. A change that alters
parsing or packing must say how it compares with dpkt and include a test that
checks the result against the pinned reference (`tools/oracle-1.9.8.txt`). Where
OctetRail deliberately differs, the difference has to be documented in `docs/`.

## Code

- Parsing lives in Rust under `src/`, Python bindings under `bindings/python/`, and
  the dpkt-style Python classes under `python/octetrail/`.
- The Rust code forbids `unsafe`. Keep parsers bounded: no allocation sized by an
  unchecked length field, and no recursion without a limit.
- New dependencies need a reason in the pull request. Python tool requirements are
  hash-pinned in `tools/*.txt`; update the hashes with the version.
- A parser change should come with a fuzz target update if the existing targets in
  [fuzz/](fuzz/README.md) do not reach the new code.

## Checks

Run these before opening a pull request. CI runs them too, and tests the wheels on
Linux, macOS and Windows.

```sh
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
python -m ruff check python tools tests/python
python -m ruff format --check python tools tests/python
```

Build a wheel and run the Python tests from a clean environment as described in
[docs/python-reader.md](docs/python-reader.md), and run the differential for the
area you changed (for example `tools/ipv4_differential.py`).

## Pull requests

- Keep one change per pull request and give it a title that says what it does,
  in the imperative ("Parse TCP options like dpkt").
- Fill in the template: what changes, how it compares with dpkt, and how it was
  tested.
- Update the documentation in `docs/` when behaviour changes.
- Accepted changes are merged into `main` and ship in the next tagged release.

By contributing you agree that your contribution is licensed under the terms in
[LICENSE](LICENSE).
