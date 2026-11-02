# openkal-image

The reference loader, runner and tools of the **ok format**: the openkal image format,
openkal SPEC clause 12. One image per architecture runs on every system of that
architecture that has a runner.

| Package | Target | What it is |
|---|---|---|
| `openkal-ld` | `libokld` | The format's definition. A reader of bytes, a checker, a signer (Ed25519) and a loader. Freestanding: no C library, no exceptions. Its users are libokrun, `okld`, and a C library's `dlopen`. |
| `openkal-run` | `libokrun` | The runner's core. It binds an image's names to this process's one openkal implementation, in the image's calling convention, then enters the image. |
| `openkal-tools` | `okrun`, `okld`, `okprof` | `okrun [--require-signature] [--trust <key>] [--debugger] [--prof=<what>[:dir]] image\|okb args...` runs an image or an okb. `okld check \| note \| place \| sign \| keygen \| inspect \| note-source \| bundle \| bundle check` works on images and okbs on a build machine. `okprof record \| report \| diff` measures what an image did across openkal. |
| `openkal-bind` | `mcpp.mcpplibs.openkal_bind` | A build plugin. A library published as an image (`.okso`) and a C header is called from a program of Linux, macOS or Windows through a binding generated from the header ([docs/bind.md](docs/bind.md)). |

`libokld` is the loader at run time and `okld` is the tool on the build machine. They share a
root and differ in role, as `ld.so` and `ld` do.

## An image

```sh
okld note-source > note.S                      # the notes (SPEC 12.4)
clang --target=x86_64-unknown-none-elf -ffreestanding -fPIC -femulated-tls -c app.c note.S
ld.lld -shared -z max-page-size=65536 -z now -z pack-relative-relocs -e ok_main -o app.oke app.o note.o
okld note app.oke                              # the interfaces its imports require
okld place app.oke                             # its writable segments computed for its base
okld check app.oke                             # the convention, every clause
okrun app.oke arguments...
```

`examples/build-image.sh` does all of this, and for AArch64 adds `-ffixed-x18`. Through
mcpp, the target `<arch>-openkal` does it.

## An okb

An okb holds the images of every architecture a program is built for, in one ZIP archive whose
images are stored and aligned to 64 KiB ([docs/okb.md](docs/okb.md)):

```sh
okld bundle app.okb --version 0.1.0 x86_64/app.oke aarch64/app.oke   # okb.json, the images by architecture
okld bundle app.okb --package target/dist/app-0.1.0-openkal         # or from a package mcpp staged
okld bundle check app.okb                                            # stored, aligned, digests, signatures
okrun app.okb arguments...                                           # this machine's architecture's entry
```

The images an image needs are found in the okb, then beside it, in `lib/<arch>/` and `lib/`, and
in `OKRUN_PATH`.

**An image's instructions and read-only data are its file's pages** (0.3.0, openkal 0.21): where
the implementation reports `KAL_EXEC_PROP_FILE`, the loader makes each segment no relocation
writes a part of the file (`kal_exec_map_part`) rather than a copy, for an image file and for an
image stored aligned in an okb; the writable segments are copied. A program then starts as a
program of its system does: a language server's worker made 1 200 page faults where it made
16 000. A relocation that would write a segment that is not writable is refused (SPEC 12.2). A program that carries its images gives their archive to
`okrun_run_okb_bytes`, which runs it from memory and writes nothing to disk.

**A remembered admission reads no byte of the member** (0.3.1): a start of an okb whose member was
compared before, on the same file, admits it by its shape (`okld_okb_admit_layout`: stored, within
the archive, aligned). 0.2.0 and 0.3.0 computed the CRC-32 the archive states there, a pass over the
whole member on every start: 0.1 s of processor time for a 71 MB clangd image, on each of the 176
workers a language server starts for a cold build of 176 modules.

**Over openkal 0.22** (0.3.2): the runner is built over openkal 0.22's implementations, so an image
starts a program with the system's null device at a position (`KAL_SPAWN_NULL_IN`, `_OUT`,
`_ERR`), which the image's C library maps `/dev/null` onto; on Windows an image's workers started
with their output discarded could not start before.

**An image at its base** (0.4.0, openkal 0.23): `okld place` chooses a base from the image's
bytes (a multiple of 4 GiB from 16 TiB), computes each writable segment for it, every relative
relocation applied, and appends the result to the file with a placement note (SPEC 12.4, type 3).
Where the implementation reports `KAL_EXEC_PROP_PLACE`, the loader reserves the image there
(`kal_exec_alloc_at`), takes the stored segments and applies only the relocations that name a
symbol; each 64 KiB of the read-only-after-relocation data that none of those writes is the
file's pages. Where the base is taken, or the image states none, the loader places it anywhere
and relocates it, as before; `OKRUN_PLACE=0` asks for that. The read-only data of all the
processes of one image are then the same pages, as those of a program linked for one address
are: a start of clangd as an image made 606 page faults at its base, 1 047 anywhere. An image
is placed before it is signed, since the signature covers the stored bytes.

## A measurement of an image

The runner binds every name an image calls across openkal and read the image's file, so it
measures what the image did there and names its addresses (openkal SPEC 12.3, 0.20):

```sh
okprof record -o prof -- okrun app.okb arguments...   # or a program that starts an okrun
okprof report prof                                    # calls by interface and by name; counters; phases
okprof diff before after                              # the same names, ordered by how their time moved
```

`okprof record` sets `OKRUN_PROF` (`okrun --prof=` says the same), so every image an okrun
beneath the program runs writes `okprof-<id>.json` when it ends:

| what | measured |
|---|---|
| `calls` | each name the image imports, bound through an entry that counts its calls and their time; an image that is not measured is bound as before and pays nothing |
| `counters` | the counters and phases the program states through `openkal.prof` (`kal_prof_counter`, `kal_prof_mark`); `kal_prof_active` answers zero when nothing measures |
| `perfmap` | `/tmp/perf-<pid>.map` on Linux, where `perf` reads the names of an image's addresses; the runner does not sample, the system's profiler does |

`openkal.debug` (`kal_debug_symbolize`) names an address from the symbol table of the image
that holds it, which the runner reads from the image's file again when it is first asked; the
table is never placed in memory by loading.

**An okb's admission is remembered.** The first start of an okb compares the images it runs
with the digests its manifest states; the comparison is then recorded per user (`okrun/admitted`
in the user's cache directory), keyed by the manifest's SHA-256 and the member, with the file's
identity, length and modification time. A later start of the same file admits the member by its
shape alone; a file replaced or changed is compared again. A language server that starts a
worker per module no longer reads its 146 MB okb at each start.

## A library from a program of any system

`okrun_open_library`, `okrun_symbol` and `okrun_close` load an image into a program of this
system and call its exports in the image's convention. `openkal-bind` generates that binding
from the library's C header and checks the boundary, so that a consumer of the library includes
its header and calls it, on openkal and on every other system alike ([docs/bind.md](docs/bind.md)).

## What CI asserts

- Images are built once, on Linux, for x86_64 and AArch64.
- The same bytes then run on:
  - linux-x86_64 and windows-x86_64 (the x86-64 images);
  - linux-aarch64 and macos-arm64 (the AArch64 images).
- Each run covers arguments, thread-local storage, a callback into the image, and an image
  that another image needs.
- `okrun` refuses an unsigned image when a signature is required, an image with a changed
  byte, and an image signed by an untrusted key.
- An okb of both architectures runs on all four machines, through `okrun` and from memory
  (`okrun_run_okb_bytes`); `okld bundle check` and the ZIP tools accept it; a changed byte
  and an unsigned manifest under `--require-signature` are refused.
- A program of each system calls an image's library through `okrun_open_library`, and through
  the binding `openkal-bind` generates (including a callback); the boundary's refusals hold.
- Once an image is loaded, the runner holds no mapping of its own of the image or the okb it
  came from, only the segments that are the file's pages, and holds its segments once (Linux,
  from the process's mappings).
- An image at its base, the same image placed anywhere (`OKRUN_PLACE=0`) and the image left
  unplaced observe the same memory; placing a placed image changes no byte; a changed byte of
  a stored segment is refused by `okld check`, and a signed image is not placed.
- An okb states its images' chunk digests, which okrun verifies on several contexts and
  `okld bundle check` beside the whole digest; a changed byte is refused by either.
- libokld's SHA-256, CRC-32, ZIP reader and writer (with ZIP64) and manifest reader hold
  against their vectors and refusals.

## License

Apache-2.0
