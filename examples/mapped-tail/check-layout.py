#!/usr/bin/env python3
"""Require the partial-map geometry; a tiny or fully aligned segment is no test."""
from pathlib import Path
import struct
import sys

image = Path(sys.argv[1]).read_bytes()
assert image[:6] == b'\x7fELF\x02\x01'
phoff = struct.unpack_from('<Q', image, 32)[0]
entsize, count = struct.unpack_from('<HH', image, 54)
segments = [struct.unpack_from('<IIQQQQQQ', image, phoff + i * entsize)
            for i in range(count)]
first = next(p for p in segments if p[0] == 1)
_, flags, offset, address, _, size, memory, _ = first
assert flags == 4 and offset == address == 0 and size == memory
end = (size + 4095) & ~4095
assert 65536 < end < len(image) and end % 65536, (end, len(image))
assert all(p[0] != 1 or p is first or (p[3] & ~4095) >= end for p in segments)
print(f'partial-map fixture: first read-only segment {size} bytes, final run ends at {end}')
