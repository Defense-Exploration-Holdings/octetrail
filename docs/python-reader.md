# Python reader subset

This guide covers classic pcap. The separate [PCAPNG guide](pcapng-reader.md)
describes the supported Enhanced Packet Block reader.
The separate [classic writer guide](pcap-writer.md) describes output and file
ownership, which differs from the borrowed Reader interface.

The experimental distribution is `octetrail==0.2.0`, with an `octetrail` import.
It neither provides `dpkt` nor satisfies a dependency on `dpkt==1.9.6` or
`dpkt==1.9.8`. No fallback imports upstream dpkt. The native core still has no
third-party runtime dependencies. A separate PyO3 extension adapts Python binary
streams to the core; the Python facade supplies timestamps and convenience APIs.

## Covered interface

```python
from octetrail import pcap

with pcap.open("synthetic.pcap", max_packet_bytes=1024 * 1024) as reader:
    print(reader.snaplen, reader.datalink())
    for timestamp, packet_bytes in reader:
        print(timestamp, len(packet_bytes))
```

`pcap.open(path)` is an OctetRail helper. It opens a local file, owns it, and
closes it on context exit, including when construction fails. The lower-level
`pcap.Reader(fileobj, *, max_packet_bytes=16777216)` borrows a Python binary
stream. It never closes the caller's file. Its context manager closes the parser
only. Explicit `close()` is idempotent and prevents further reads; use a context
manager for prompt resource release. `closed` reports parser closure.

The covered dpkt-style subset is `Reader(fileobj)`, `(timestamp, bytes)` iteration,
`next(reader)`, `reader.next()`, `name`, `snaplen`, `dloff`, `filter`, `fd`,
`fileno()`, `datalink()`, `readpkts()`, `dispatch(cnt, callback, *args)`, `loop()`
and the `NotImplementedError` raised by `setfilter()`. `filter` is initially an
empty string and does not execute a filter. Offsets are compatibility metadata,
not protocol decoding. File descriptor calls delegate to the input, so BytesIO
raises its usual `io.UnsupportedOperation`.

Iteration uses generators sharing one input cursor, including interleaving with
the reader's saved `next()` iterator and callback methods. A positive dispatch
count reads at most that many packets; zero or negative counts consume to EOF.
Callback exceptions propagate after their packet has been consumed. `loop()`
returns None. `readpkts()` collects all remaining records, so callers choosing it
must budget total output memory. The incremental consumer tests use iteration.

Microsecond timestamps are Python floats computed as `seconds + ticks / 1e6`.
Nanosecond timestamps use `seconds + ticks / Decimal("1E9")`. Decimal operations
use the active caller context, including rounding and traps, as the measured
references do. Returned packet data are independent owned bytes. No Rust buffer
view is exposed. The original wire length remains available in the Rust API,
not in the two-item Python iteration result.

## Strict behavior and unsupported paths

- Ordinary pcap 2.4 is supported in both byte orders and both resolutions.
  Reader does not autodetect pcapng; use `octetrail.pcapng.Reader` explicitly,
  or the measured [UniversalReader factory](universal-reader.md).
  Modified pcap, packet objects, protocol decoders, checksums,
  filter execution, header classes and complete DLT/magic
  constant inventories are absent. The [capture provider](capture-compatibility.md)
  lists the sixteen measured exports across both capture modules.
- Only the exception hierarchy `Error`, `UnpackError`, `NeedData` is provided.
  Short global/record headers map to `NeedData`; full error messages are not
  claimed compatible. Unknown magic raises `ValueError("invalid tcpdump header")`.
  Other native validation failures raise ValueError. The extra `pcap.LimitError`
  is a ValueError subclass. Allocation failures map to MemoryError but were not
  injected in tests.
- A truncated payload raises NeedData. Both pinned dpkt versions yield the
  available short bytes instead. Zero snap length, unsupported version, invalid
  timestamp fractions, and captured lengths exceeding snap length or original
  length are rejected. These stricter rules are not an upstream parity claim.
- EOF and native read errors terminate the whole native reader. Seeking,
  appending to a capture after EOF, recovery with a different iterator after a
  read error, and externally moving the cursor are outside this subset. An
  exhausted saved `next()` generator remains exhausted, matching normal use.
- The adapter calls synchronous `read(size)` and accepts bytes only. It supports
  partial non-seekable reads, which dpkt's global-header read does not assemble.
  None, text, bytearray, memoryview and overlong results are unsupported. Original
  Python input exceptions, including OSError and InterruptedError, propagate by
  identity. They are not silently retried by the adapter.
- The per-packet limit controls the native allocation, not process memory. Input
  buffers, Python output copies, callback allocations and retained outputs add
  memory. User-supplied `read` methods can allocate or block independently.
  There is no total byte limit, packet-count limit, timeout, async I/O, reentrancy
  guarantee, GIL-free parsing claim or free-threaded Python support claim.

## Build locally

The tested combination is Rust 1.85.1, PyO3 0.30.1 and maturin 1.16.0. The
[PyO3 build guide](https://pyo3.rs/v0.30.1/building-and-distribution.html) and
[maturin project layout](https://www.maturin.rs/project_layout.html) describe the
extension and mixed-package layout. Exact registry dependencies and checksums
are in Cargo.lock. The build tool and optional Python linter are hash-pinned for
Linux x86_64. Neither is bundled in the wheel.

```sh
python3 -m venv .venv-build
.venv-build/bin/python -m pip install --require-hashes --only-binary=:all: -r tools/build-linux.txt
.venv-build/bin/python -m pip install --require-hashes --only-binary=:all: -r tools/lint-linux.txt
cargo fetch --locked
.venv-build/bin/python tools/build_wheels.py --offline --interpreter python3.12 --interpreter python3.13
python3 tools/check_wheel.py dist/*.whl
```

Pass interpreter paths that actually exist. Each gets its own CPython wheel;
there is no abi3 promise. `--offline` requires the Cargo cache to be populated.
The wrapper never installs or publishes. It remaps compiled source paths, makes
local component paths relative in maturin's SBOM, and regenerates wheel RECORD
hashes. Dependency identities, checksums and license metadata are preserved.
Use this wrapper for reviewable artifacts: a direct backend build can retain
absolute machine paths in generated metadata. Bit-for-bit reproducibility and
source-distribution installation have not been established.

Build outputs are ignored under `dist/` and can be regenerated from source. Only Linux x86_64 with glibc 2.41 was exercised, using CPython 3.12.14 and
3.13.5. Maturin selected `manylinux_2_34_x86_64` after its wheel audit; that tag
is not an execution test on every compatible distribution. Windows, macOS, ARM,
musl, PyPy and other Python versions have not been tested. Metadata limits Python
versions to 3.12 and 3.13.

## Install and test in a fresh environment

Use the wheel matching the chosen interpreter. Do not install over another
project's environment. For example, with CPython 3.12:

```sh
OCTETRAIL_TEST_ENV=$(mktemp -d)
python3.12 -m venv "$OCTETRAIL_TEST_ENV"
"$OCTETRAIL_TEST_ENV/bin/python" -m pip install --no-index --no-deps dist/octetrail-0.2.0-cp312-cp312-manylinux_2_34_x86_64.whl
"$OCTETRAIL_TEST_ENV/bin/python" -I tests/python/test_reader.py
python3 tools/wheel_differential.py --python "$OCTETRAIL_TEST_ENV/bin/python" --oracle-198 "$PWD/.venv-oracle-198/bin/python" --oracle-196 "$PWD/.venv-oracle-196/bin/python"
```

The separate hash-pinned oracle environments are described in the root README.
The wheel environment must contain no dpkt. Probes run with `-I` outside the
source tree, verify native and Python module origins and distribution metadata,
and compare independent benign captures, timestamp types, reader methods and an
incremental consumer. Testing performs no network operation or service startup.

For a Python installation without ensurepip, create its venv with `--without-pip`
and use the build environment's `python -m pip --python ENV/bin/python install`
to install only into that new environment.

```sh
cargo fmt --all --check
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo test --workspace --locked
.venv-build/bin/ruff check python tests/python tools
.venv-build/bin/ruff format --check python tests/python tools
```

Set `PYO3_PYTHON` to the chosen build interpreter if automatic detection selects
another one. The extension disables Rust libtest/doctest targets because it is
tested as an installed Python extension, not an embedded Python executable.
