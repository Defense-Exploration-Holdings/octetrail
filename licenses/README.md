# Dependency license notices

The core has no third-party runtime crate dependencies. The optional Python
extension uses PyO3. This directory retains upstream notices for the resolved
binding dependency graph, including build and target-specific dependencies.
The selected license branches and versions are listed below. Registry source
checksums are pinned in Cargo.lock. No dependency source is vendored here.

| Crate | Upstream expression | Included branch |
| --- | --- | --- |
| `heck 0.5.0` | `MIT OR Apache-2.0` | MIT |
| `libc 0.2.191` | `MIT OR Apache-2.0` | MIT |
| `once_cell 1.21.4` | `MIT OR Apache-2.0` | MIT |
| `portable-atomic 1.15.0` | `Apache-2.0 OR MIT` | MIT |
| `proc-macro2 1.0.107` | `MIT OR Apache-2.0` | MIT |
| `pyo3 0.30.1` | `MIT OR Apache-2.0` | MIT |
| `pyo3-build-config 0.30.1` | `MIT OR Apache-2.0` | MIT |
| `pyo3-ffi 0.30.1` | `MIT OR Apache-2.0` | MIT |
| `pyo3-macros 0.30.1` | `MIT OR Apache-2.0` | MIT |
| `pyo3-macros-backend 0.30.1` | `MIT OR Apache-2.0` | MIT |
| `quote 1.0.47` | `MIT OR Apache-2.0` | MIT |
| `syn 3.0.10` | `MIT OR Apache-2.0` | MIT |
| `target-lexicon 0.13.6` | `Apache-2.0 WITH LLVM-exception` | Apache-2.0 WITH LLVM-exception |
| `unicode-ident 1.0.27` | `(MIT OR Apache-2.0) AND Unicode-3.0` | MIT + Unicode-3.0 |

The full retained notices are in `rust/`. The target-lexicon notice includes its
LLVM exception. The unicode-ident notice includes the additional Unicode terms.
The Python facade's dpkt attribution and BSD license are in `dpkt.txt` and the
root NOTICE. Wheels carry these files in their distribution license metadata.
Maturin is a build tool, not bundled with the wheel.
