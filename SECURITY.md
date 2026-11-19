# Security policy

## Supported versions

Security fixes are made on the latest release. Older releases do not receive
backported fixes.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/Defense-Exploration-Holdings/octetrail/security/advisories/new)
for this repository. Do not open a public issue for a suspected vulnerability.

Include the affected version, a description of the impact and, where possible,
a capture file or byte string that reproduces the problem. You should receive an
acknowledgement within five working days. Once a fix is released, the advisory
is published with credit to the reporter unless they prefer otherwise.

## Scope

OctetRail parses capture files and packet bytes that are often untrusted. In
scope are crashes, panics, unbounded memory or CPU use, out-of-bounds reads and
incorrect results that a crafted input can cause in the Rust library or the
Python package. Resource limits that are documented as caller-configurable
are not vulnerabilities on their own, but a default that can be exceeded with a
small input is.

The Rust code forbids `unsafe`. The libFuzzer targets in [fuzz/](fuzz/README.md)
run weekly in the public repository, 15 minutes per target, and can be run by
hand. They cover the Rust readers and walks; the Python protocol classes are
covered by unit tests and a differential against dpkt instead.
