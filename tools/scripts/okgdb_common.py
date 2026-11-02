# What okgdb.py and oklldb.py share: an ok image's segments, its build-id, its
# debug file, and its base from a mapped part.
import os
import struct


def segments(path):
    """The loadable segments of an ELF file: (offset, vaddr, filesz)."""
    with open(path, "rb") as f:
        head = f.read(64)
        if head[:4] != b"\x7fELF" or head[4] != 2:
            return []
        phoff, = struct.unpack_from("<Q", head, 32)
        phnum, = struct.unpack_from("<H", head, 56)
        f.seek(phoff)
        table = f.read(56 * phnum)
    out = []
    for i in range(phnum):
        ptype, _flags, offset, vaddr, _paddr, filesz, _memsz, _align = struct.unpack_from("<IIQQQQQQ", table, 56 * i)
        if ptype == 1:
            out.append((offset, vaddr, filesz))
    return out


def build_id(path):
    """The GNU build-id of an ELF file, in hexadecimal, or None."""
    with open(path, "rb") as f:
        data = f.read()
    phoff, = struct.unpack_from("<Q", data, 32)
    phnum, = struct.unpack_from("<H", data, 56)
    for i in range(phnum):
        ptype, _f, offset, _v, _p, filesz, _m, _a = struct.unpack_from("<IIQQQQQQ", data, phoff + 56 * i)
        if ptype != 4:
            continue
        at = offset
        while at + 12 <= offset + filesz:
            namesz, descsz, ntype = struct.unpack_from("<III", data, at)
            desc = at + 12 + ((namesz + 3) & ~3)
            if namesz == 4 and data[at + 12:at + 15] == b"GNU" and ntype == 3:
                return data[desc:desc + descsz].hex()
            at = desc + ((descsz + 3) & ~3)
    return None


def is_image(path):
    """An ok image carries the OPENKAL notes (SPEC 12.4)."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF" and b"OPENKAL\0" in f.read(1 << 16)
    except OSError:
        return False


def debug_file(path):
    """The file `okld debug-split' wrote for the image, by its build-id, or the image."""
    bid = build_id(path)
    if not bid:
        return path
    places = [os.path.dirname(path)] + [d for d in os.environ.get("OKGDB_DEBUG_DIR", "").split(os.pathsep) if d]
    for d in places:
        candidate = os.path.join(d, ".build-id", bid[:2], bid[2:] + ".debug")
        if os.path.exists(candidate):
            return candidate
    return path


def base_at(path, start, offset):
    """The image's base, from a part mapped at `start' from file offset `offset'."""
    for seg_offset, vaddr, filesz in segments(path):
        if seg_offset <= offset < seg_offset + filesz:
            return start - (vaddr + (offset - seg_offset))
    return None


def base_of(path, start, read):
    """The image's base from a part at `start' whose offset is not known: the
    part is a 64 KiB block of a segment, found by the bytes it holds."""
    probe = read(start, 4096)
    if not probe or not any(probe):
        return None
    with open(path, "rb") as f:
        data = f.read()
    for seg_offset, vaddr, filesz in segments(path):
        first = seg_offset - seg_offset % 65536
        for offset in range(first, seg_offset + filesz, 65536):
            if data[offset:offset + len(probe)] == probe:
                return base_at(path, start, offset) if offset >= seg_offset else start - (vaddr - (seg_offset - offset))
    return None
