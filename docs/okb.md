# okb: the universal image bundle, version 1

An okb is one file that holds the images of a program for every architecture it is built
for. An ok image (openkal SPEC clause 12) runs on every system of its architecture that has a
runner; an okb extends that statement to every architecture the okb holds. `okrun app.okb`
selects the images of the machine it runs on and runs the entry.

This document defines version 1. The format belongs to this repository: it is the input of
`okrun` and the output of `okld bundle`, and it is not part of the openkal specification.
A change to it does not change the specification, the implementations, or the C library.

## 1. Container

An okb is a ZIP archive (PKWARE APPNOTE 6.3). Any ZIP tool lists and extracts it. ZIP64
records are permitted and are written when a size, an offset, or the number of members needs
them.

| Rule | Statement |
|---|---|
| C1 | Every member is **stored** (method 0): its bytes in the archive are its content. |
| C2 | The bytes of every image member (a name ending in `.oke` or `.okso`) begin at an offset that is a multiple of **65536** from the start of the archive. 65536 is the image's own segment alignment (`-z max-page-size=65536`, SPEC 12.2), so an image's segments can be mapped where they lie. |
| C3 | No member is encrypted. |
| C4 | A reader finds members through the central directory only. Bytes that no directory entry names may lie between members. |

The writer reaches C2 with a field in the member's local header (header ID `0x6b6f`, the
bytes "ok"): a four-byte alignment (65536) followed by zero bytes. A field has at least eight
bytes; where fewer than eight bytes of padding are needed, the writer places them before the
member's local header instead (C4). The central directory carries no padding field.

## 2. Members

```
okb.json                  the manifest (§3)
okb.sig                   the manifest's signature (§4); optional
x86_64/app.oke            the images of each architecture, in its directory
x86_64/libdep.okso
aarch64/app.oke
aarch64/libdep.okso
```

An architecture's directory is named in the manifest; `okld bundle` names it after the
architecture (`x86_64`, `aarch64`). Version 1 holds images and the two manifest members.
A program's data files are delivered beside the okb (in the package it is part of); a view
of files inside an okb, through the loader, is reserved for a later version, which the
manifest's `okb` number distinguishes.

## 3. The manifest: `okb.json`

A JSON object (RFC 8259) in UTF-8. Names are ASCII.

```json
{
  "okb": 1,
  "name": "app",
  "version": "0.1.0",
  "entry": "app.oke",
  "architectures": {
    "aarch64": { "dir": "aarch64", "entry": "app.oke" },
    "x86_64":  { "dir": "x86_64",  "entry": "app.oke" }
  },
  "files": {
    "aarch64/app.oke":      { "sha256": "…64 hexadecimal digits…", "size": 81920 },
    "aarch64/libdep.okso":  { "sha256": "…", "size": 12288 },
    "x86_64/app.oke":       { "sha256": "…", "size": 77824 },
    "x86_64/libdep.okso":   { "sha256": "…", "size": 12288 }
  }
}
```

| Key | Meaning |
|---|---|
| `okb` | The version of this format the okb is written to. A reader refuses a version above the one it reads. Required. |
| `name`, `version` | The program's name and version. `version` is optional. |
| `entry` | The image entered, by its name within an architecture's directory. An architecture without its own `entry` takes this one. |
| `architectures` | One object per architecture the okb holds, keyed by the architecture's name. `dir` is the directory of its images (default: the architecture's name); `entry` is the image it enters. At least one architecture is required. |
| `files` | One object per member other than `okb.json` and `okb.sig`, keyed by the member's name. `sha256` is the SHA-256 of its content (64 hexadecimal digits); `size` is its length in bytes. |
| `files.<member>.chunks` | Optional (okrun 0.1.8). `size` is a chunk's length in bytes, and `sha256` the SHA-256 of each `size` bytes of the member in order, the last as long as what remains; there are exactly as many as the member's size needs. `okld bundle` writes them for every image, in chunks of 1 MiB. A reader that verifies them need not digest the whole, and can verify them at once on several processors, where one SHA-256 of the whole cannot be shared out; a reader that does not know them verifies `sha256`, as before. |

Unknown keys are ignored, so that a later minor addition does not need a new `okb` number.

## 4. Trust

- Each image carries its own signature note (SPEC 12.4), written by `okld sign` or by
  `okld bundle --sign`.
- `okb.sig`, when present, is 96 bytes: an Ed25519 public key (32 bytes) and the Ed25519
  signature (64 bytes) of the bytes of `okb.json`. The manifest states the digest of every
  other member, so its signature covers the whole okb.
- A runner asked to require signatures (`okrun --require-signature`, or `--trust <key>`)
  applies the requirement to the whole okb: `okb.sig` must be present, hold, and be made by a
  trusted key, and so must the signature of every image it loads from the okb.

## 5. Reading

A reader that runs an okb:

1. reads `okb.json` (stored, its CRC-32 holding) and refuses an `okb` version it does not read;
2. with signatures required, verifies `okb.sig` (§4);
3. selects the architecture of the machine it runs on, and refuses an okb that holds none for
   it, naming the architectures it holds;
4. admits each member it uses: stored (C1), an image's bytes aligned (C2), and its SHA-256 the
   one `files` states --- or, where `files` states its chunks, each chunk's (§3). A member that does not hold is refused; a reader does not decompress,
   realign or copy a member to make it hold;
5. resolves the entry and each image an image needs (DT_NEEDED) in this order:
   1. the architecture's directory, then the archive's root;
   2. beside the okb, then its `lib/<arch>/` and `lib/`;
   3. each directory of `OKRUN_PATH` (the system's list separator: `;` on Windows, `:`
      elsewhere), `<dir>/<arch>/` and then `<dir>/`. A package store such as xlings's is
      reached by naming its directory there.

An archive of images without `okb.json` is read by the same rules, with the member's CRC-32 in
place of its SHA-256 and with the entry named by the caller. This is the shape a program that
carries its images (a self-contained or single-file program) gives `okrun_run_okb_bytes`.

okrun 0.1.2 reads an okb file into memory once and loads each image from its bytes where they
lie in the archive: no member is extracted to disk or decompressed. The loader places each
segment in executable memory as it does for an image file. C2 allows a runner whose
implementation offers a view of a file's pages to map the segments in place instead; openkal
has no such interface in version 0.17.

## 6. Writing

```
okld bundle <out.okb> [--name <n>] [--version <v>] [--entry <image>] [--sign <seed-file>] <image>...
okld bundle <out.okb> --package <staged-tree> [--sign <seed-file>]
okld bundle check <file.okb> [--require-signature] [--trust <hex>]...
```

`okld bundle` reads each image, takes its architecture from its ELF header, places it in that
architecture's directory, and writes `okb.json` with the digests; `--sign` signs each image
and the manifest with one key. The archive is deterministic: no time is recorded, and the same
images give the same bytes. The entry defaults to the first `.oke` named.

`--package` takes the images from a universal package that mcpp has staged (mcpp SPEC-014 §4.2,
§4.5), reading `mcpp-package.json` at the root of the tree:

- the images are the files of role `image`, at `lib/<arch>/<file>`;
- each image's architecture, from its ELF header, must be the one its directory names;
- its content must be the `sha256` stated for it;
- each architecture's entry is the file `launch.entry` names for it;
- the okb's name and version are the package's.

Files of every other role (launchers, loaders, resources, metadata) are not members of a
version 1 okb. This is the action of the `okb` package format that openkal-platform's plugin
provides.

`okld bundle check` verifies C1 to C3, the manifest, every digest, every signature (and the
trust asked for), that each architecture's entry is present, that each image is of its
directory's architecture, and that each image follows the convention (SPEC 12.2) with the
exports of the other images of its directory. It prints one line per violation.

## 7. Interfaces

| Interface | Library | Statement |
|---|---|---|
| `okld_zip_each`, `okld_zip_find`, `okld_zip_write` | libokld | The ZIP container, read from memory and written into a given buffer. |
| `okld_okb_read_manifest`, `okld_okb_digest`, `okld_okb_each_file`, `okld_okb_admit` | libokld | The manifest and the admission of a member (§5, step 4). |
| `okrun_run_file`, `okrun_run_bytes` | libokrun | An image or an okb, from a file or from memory. |
| `okrun_run_okb_bytes` | libokrun | An okb, or an archive of images, from memory, with the entry named or taken from `okb.json`. |
| `okrun_run_images` | libokrun | A group of images in memory that resolve one another by name. |

## 8. Versions

| okb | okrun | Change |
|---|---|---|
| 1 | 0.1.2 | This document. |
| 1 | 0.1.3 | `okld bundle --package`: an okb from a package mcpp staged. |
| 1 | 0.1.8 | `files.<member>.chunks`: an image's chunk digests, written by `okld bundle`, verified by okrun on several contexts at once and by `okld bundle check` beside the whole digest. Still okb 1: a reader that does not know the key ignores it. |
