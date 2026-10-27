#!/usr/bin/env python3
"""stage.py <out-dir> <images-dir> -- a universal package of images as mcpp
stages it (mcpp SPEC-014 §4.2, §4.5), for `okld bundle --package', and an
archive of the same images without okb.json, as a program that carries them
holds it (zipalign's field 0xD935, and bytes between members).

  <out-dir>/tree/              lib/<arch>/needed.oke, liboktwice.okso, a launcher,
                               a resource, mcpp-package.json
  <out-dir>/carried.zip        needed.oke and liboktwice.okso of this machine's
                               architecture at the root, stored, 64 KiB-aligned
"""
import hashlib, json, os, platform, shutil, struct, sys, zlib

out, images = sys.argv[1], sys.argv[2]
tree = os.path.join(out, "tree")
files = []

def place(rel, data, role, leg=None):
    path = os.path.join(tree, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    files.append({"path": rel, "role": role, "leg": leg, "sha256": hashlib.sha256(data).hexdigest()})

for arch in ("x86_64", "aarch64"):
    for name in ("needed.oke", "liboktwice.okso"):
        with open(os.path.join(images, arch, name), "rb") as f:
            place(f"lib/{arch}/{name}", f.read(), "image", f"{arch}-openkal")
place("bin/needed", b"#!/bin/sh\n", "launcher")
place("share/needed/data.txt", b"a resource\n", "resource")
doc = {
    "schema": 1, "name": "needed", "version": "0.1.0", "platform": "openkal-platform@0.17.2",
    "linkage": "declared", "mode": "vendored", "legs": ["x86_64-openkal", "aarch64-openkal"], "systems": [],
    "launch": {"runner": ["okrun", "{}"],
               "entry": {"x86_64": "lib/x86_64/needed.oke", "aarch64": "lib/aarch64/needed.oke"}},
    "files": files,
}
with open(os.path.join(tree, "mcpp-package.json"), "w") as f:
    json.dump(doc, f, indent=2)

# The carried archive: this machine's images at the root.
arch = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}[platform.machine().lower()]
members = []
for name in ("needed.oke", "liboktwice.okso"):
    with open(os.path.join(images, arch, name), "rb") as f:
        members.append((name, f.read()))
blob, central = bytearray(), bytearray()
for i, (name, data) in enumerate(members):
    n = name.encode()
    if i == 1:
        blob += b"\0" * 3            # bytes between members, which no entry names
    pad = (-(len(blob) + 30 + len(n))) % 65536
    if 0 < pad < 6:
        blob += b"\0" * pad         # too few for a field: bytes before the header
        pad = 0
    extra = b""
    if pad:
        # zipalign's field: id 0xD935, the alignment (2 bytes), zeros.
        extra = struct.pack("<HHH", 0xD935, pad - 4, 0) + b"\0" * (pad - 6)
    crc = zlib.crc32(data) & 0xffffffff
    header = len(blob)
    blob += struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, 0, 0, 0x21, crc, len(data), len(data), len(n), len(extra)) + n + extra
    assert len(blob) % 65536 == 0, (name, len(blob) % 65536)
    blob += data
    central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 20, 20, 0, 0, 0, 0x21, crc, len(data), len(data), len(n), 0, 0, 0, 0, 0, header) + n
cd = len(blob)
blob += central + struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(members), len(members), len(central), cd, 0)
with open(os.path.join(out, "carried.zip"), "wb") as f:
    f.write(blob)
print(f"staged {tree} and {os.path.join(out, 'carried.zip')} ({arch})")
