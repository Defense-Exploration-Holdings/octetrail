# Synthetic literal fixtures

These hex files were assembled directly from capture fields. No parser or
capture writer generated them. They contain arbitrary ordinary user-link bytes,
link type 147, snap length 64, and zero reserved fields. Whitespace is ignored.
No captured traffic or protocol payload is present.

- `little-micro.hex`: little endian, microseconds, version 2.4. Record one is
  seconds 1, fraction 250000, captured length 3, original length 5, bytes `abc`.
  Record two is seconds 2, fraction 0, both lengths 0.
- `big-nano.hex`: big endian, nanoseconds, version 2.4. The record is seconds
  1700000000, fraction 123456789, both lengths 4, bytes `rail`.
- `pcapng-little.hex`: little endian pcapng 1.0, default microsecond resolution,
  unknown section length, interface 0 with link type 147 and snap length 64.
  One Enhanced Packet Block has 1250000 ticks, captured length 3, original length
  5, bytes `abc` and one padding byte. The timestamp is 1.25 seconds.
- `pcapng-big-nano.hex`: big endian pcapng 1.0. Interface 0 has decimal exponent
  9 and signed offset -2 seconds. Its Enhanced Packet Block has 1250000000 ticks,
  four `rail` bytes and no payload padding. The timestamp is -0.75 seconds.
- `pcapng-options-little.hex`: little endian pcapng 1.0, section comment `lab`,
  interface name `if0`, binary resolution 2^-10, offset -2 seconds, link type 147
  and snap length 64. One EPB has 1024 ticks, both lengths 3, `abc` and one zero
  padding byte. Section, interface and packet block lengths are 40, 52 and 36.

Tests also construct captures with an independent Python `struct` encoder.
No upstream or OctetRail writer is used. Expected values are asserted directly
as well as compared with upstream. Fixtures are original project test data.
