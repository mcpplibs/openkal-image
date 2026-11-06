# openkal-image

The reference loader, runner and tools of the **ok format**: the openkal image format,
openkal SPEC clause 12. One image per architecture runs on every system of that
architecture that has a runner.

| Package | Target | What it is |
|---|---|---|
| `openkal-ld` | `libokld` | The format's definition. A reader of bytes, a checker, a signer (Ed25519) and a loader. Freestanding: no C library, no exceptions. Its users are libokrun, `okld`, and a C library's `dlopen`. |
| `openkal-run` | `libokrun` | The runner's core. It binds an image's names to this process's one openkal implementation, in the image's calling convention, then enters the image. |
| `openkal-tools` | `okrun`, `okld`, `okprof` | `okrun [--require-signature] [--trust <key>] [--debugger] [--prof=<what>[:dir]] image\|okb args...` runs an image or an okb. `okld check \| note \| place \| touch \| debug-split \| sign \| keygen \| inspect \| note-source \| bundle \| bundle check` works on images and okbs on a build machine. `okprof record \| report \| diff` measures what an image did across openkal. The debugger scripts are in `tools/scripts`. |
| `openkal-bind` | `mcpp.mcpplibs.openkal_bind` | A build plugin. A library published as an image (`.okso`) and a C header is called from a program of Linux, macOS or Windows through a binding generated from the header ([docs/bind.md](docs/bind.md)). |

`libokld` is the loader at run time and `okld` is the tool on the build machine. They share a
root and differ in role, as `ld.so` and `ld` do.

## Observable process units

Version 0.5.0 binds the four declared-unit operations of OpenKal 0.24 through
its generated surface and image calling convention. The runner selects Linux
0.25, macOS 0.22 or Windows 0.20. An image can retain an observation reference;
missing native identity remains `unknown`. The format and the existing import
names remain unchanged.

Version 0.5.1 builds the runner over openkal-macos 0.22.1, whose confinement
rules hold sixteen long grants, and states the kernel layer as compatible ranges
(openkal `^0.24.0`, Linux `^0.25.0`, macOS `^0.22.1`, Windows `^0.20.0`). The
format, the loader and the import names are unchanged.

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
Where the implementation reports `KAL_EXEC_PROP_PLACE`, the loader reserves the image at a base
(`kal_exec_alloc_at`), takes its data for that base and applies only the relocations that name a
symbol; each 64 KiB of the read-only-after-relocation data that none of those writes is the
file's pages, and the range is sealed once relocated (`kal_exec_seal_part`, for good for an image
never unloaded). The read-only data of all the processes of one image are then the same pages, as
those of a program linked for one address are: a start of clangd as an image made 606 page faults
at its base, 1 047 anywhere. An image is placed before it is signed, since the signature covers
the stored bytes.

**A base for each boot.** An image at the base it was sealed with would be at one address on every
machine, which is what address space layout randomisation exists to undo. The runner moves it by
a slide chosen at random once for each user and each boot (a multiple of 64 KiB below 16 TiB), from
the base of its digest; the first start of the boot computes the image's data for that base and
writes it as a prepared copy (`<digest>-<base>.okseg`, SPEC 12.4, type 5) in a directory only the
user writes (`OKRUN_CACHE`, else `$XDG_RUNTIME_DIR/okrun`, else the user's cache directory's
`okrun/placed`), and every later start maps it. A new boot is told by the wall clock less the
monotonic one, and removes what was prepared for the last. `OKRUN_PLACE=sealed` keeps the sealed
base, and `OKRUN_PLACE=0` places the image anywhere and relocates it.

**The pages a start touches** (type 4): `okprof record --what touch` records, through the
implementation (`kal_prof_touch_*`, openkal 0.23), the order in which a start first executes the
pages of an image; `okld touch <image> <report>...` writes them into the image's touch note, and
`okprof report --order` writes the image's functions in that order for a link to lay them out by.
A loader reads the noted pages in with their part (`KAL_EXEC_MAP_PREFETCH`) where the program's
resource preference spends memory for time: always for performance, never for economy, and where
a quarter of the machine's memory is available when balanced.

**A snapshot of the initialisers** ([docs/snapshot.md](docs/snapshot.md)): the runner runs an
image's initialisers once in a boot, with memory and the implementation's facts alone, and keeps
the image's data and the memory they obtained as a prepared copy; every later start maps it and
enters the image's C library to take what the start supplies. A start whose facts, processors,
resource preference or named values the initialisers read differ from those the snapshot was
made under does not use it, and an initialiser that asks for anything else of the start is
refused a snapshot. openkal-musl 0.27.0 takes part. `OKRUN_SNAPSHOT=0` runs the initialisers.

**Over openkal-macos 0.21.2** (0.4.1): the runner on macOS is built over an implementation whose
sleep suspends the context and whose monotonic granularity is the same at every start. Under 0.21.0
the wait it suspends with failed at once for a word whose page was not yet present, and an image's
sleep on macOS was a spin of the processor for its whole length; the granularity was measured at
each start, and a snapshot compared among the implementation's facts was declined when it differed.
0.4.2 is built over openkal-macos 0.21.3, whose answers to an initialiser that runs before its own are
the loader's record of the arguments and the environment.

**Touched images on Windows** (0.4.4): if the environment accepts an initial file mapping and
refuses a later run of the same segment, the loader copies only the refused run. Already mapped
read-only pages remain intact. A copied executable run is published separately; refusal to publish
rejects the load. This corrects a startup access violation in profiled images with a short tail.

**Unit memory observation on Linux** (0.4.5): the runner uses openkal-linux 0.24.2,
which avoids opening RSS records for unrelated process groups. Complete group charges,
refused-query fallback, immediate observation and the supervised sampling intervals remain.

**Profiling environment** (0.4.5): `okprof record` forwards environment values, including
empty values, and sets the requested `OKRUN_PROF` value for the child.

**Read-only confinement on Linux** (0.4.3): the runner is built over openkal-linux 0.24.1. It
claims confinement only with Landlock ABI 3 or later, whose policy can prevent file truncation in
a read-only grant. Earlier ABIs refuse a confinement request before starting a program. The
implementation's ABI probe cache uses atomic accesses during concurrent first queries.

## What a start spends

A program's resource preference (openkal 0.23: balanced, performance, economy) decides what
the runner spends ahead of it; balanced is taken as economy where memory available falls below
15 % of the machine's, or the cache's volume below 1 GiB free (mcpp design 2026-11-03 part 4 §16):

| point | performance | balanced | economy | single setting |
| --- | --- | --- | --- | --- |
| the data for this boot's base | kept in the cache | kept in the cache | computed for each start, written nowhere | `OKRUN_PLACE` |
| a snapshot of the initialisers | made; the snapshots bound at 2 GiB | made; bound at 512 MiB, the least recently used removed | used where one exists, not made | `OKRUN_SNAPSHOT` |
| what is read ahead | the touched pages and the data | the touched pages | nothing | `OKRUN_PREFETCH=0\|touch\|all` |

A compressed okb (okb 2, `okld bundle --compress`; `mcpp pack --pkg-format okb --compress gzip`)
is the economy form of a package: kept small on disk, its images expanded into the user's cache
(`okrun/expanded`) when it first runs and mapped from there afterwards.

`okrun cache` lists what the runner keeps for this machine, `okrun cache gc` removes what was
prepared for another boot, and `okrun cache gc --all` everything, remembered admissions,
digests and expanded images included. A measurement's report states what the runner chose at
each point (`runner`: the placement's data, the snapshot, what was read ahead, an expansion).

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
| `perfmap` | `/tmp/perf-<pid>.map` on Linux, where `perf` reads the names of an image's addresses |
| `phases` | the moments of a start --- admitted, loaded, its snapshot entered, initialised, main returned, exit --- with the time and the page faults to each (0.4) |
| `samples[=hz]` | where the processor time goes, sampled by the implementation (`kal_prof_sample_*`, openkal 0.23) and named from the image's symbols; `okprof report --flame` folds the stacks, `--format=trace` lays phases and samples on one timeline for Perfetto (0.4) |
| `touch` | the order of the first execution of each page of an image's instructions (0.4) |
| `names` | `okprof record` grants the program its directories recorded (`KAL_DIR_RECORDED`, openkal 0.23); `okprof report --names` counts, by directory, the names read, written, listed and found absent (0.4) |

`openkal.debug` (`kal_debug_symbolize`) names an address from the symbol table of the image
that holds it, which the runner reads from the image's file again when it is first asked; the
table is never placed in memory by loading.

**An okb's admission is remembered.** The first start of an okb compares the images it runs
with the digests its manifest states; the comparison is then recorded per user (`okrun/admitted`
in the user's cache directory), keyed by the manifest's SHA-256 and the member, with the file's
identity, length and modification time. A later start of the same file admits the member by its
shape alone; a file replaced or changed is compared again. A language server that starts a
worker per module no longer reads its 146 MB okb at each start.

## A debugger

An image's instructions and read-only data are its file's pages, so a debugger finds the image
and its base in the process's mappings, and in a core's. `tools/scripts/okgdb.py` (`ok-symbols`,
gdb) and `tools/scripts/oklldb.py` (lldb) read them and load the image's symbols at its base.
`okrun --debugger` announces a debugger object through the GDB JIT interface.
Source debugging requires embedded DWARF and retained debug relocations
(`--emit-relocs` at link time). The loader inflates zlib debug sections only in
that object; the executable image stays unchanged. An image with source debug
information but no retained debug relocations is refused in debugger mode.
Ordinary execution is available independently. The checked source-debugger
combination is Linux x86-64 with the GDB and LLDB bundled in CLion 2026.1.5.2;
other native debugger combinations are not qualified by the runner matrix.
See [source debugging](docs/debugging.md) for commands and input limits.

`okld debug-split` keeps what only a debugger reads apart from the image, as
`.build-id/xx/rest.debug` named by its build-id, where the scripts look for it. A fault the
implementation reports names the frames from the image's symbols (`kal_debug_symbolize`).

## A library from a program of any system

`okrun_open_library`, `okrun_symbol` and `okrun_close` load an image into a program of this
system and call its exports in the image's convention. `openkal-bind` generates that binding
from the library's C header and checks the boundary, so that a consumer of the library includes
its header and calls it, on openkal and on every other system alike ([docs/bind.md](docs/bind.md)).

## What CI asserts

- Linux sanitizer controls check debugger-object metadata bounds and allocation
  ownership, and dependency-reference rollback after failed debugger registration.
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
- An image at this boot's base, at its sealed base (`OKRUN_PLACE=sealed`), anywhere
  (`OKRUN_PLACE=0`) and left unplaced observes the same memory; two starts of a boot choose one
  base; placing a placed image changes no byte; a changed byte of a stored segment is refused by
  `okld check`, and a signed image is not placed.
- A snapshot is made once, a start uses it, a start whose named value differs and
  `OKRUN_SNAPSHOT=0` do not, and an image whose initialiser asks for the time is refused one,
  the marker naming the call.
- A compressed okb is checked by `okld bundle check`, runs on all four machines, expanding its
  image once into the cache, and a changed byte of it is refused; an economy start writes
  nothing to the runner's cache; `okrun cache` lists and removes what it keeps.
- An okb states its images' chunk digests, which okrun verifies on several contexts and
  `okld bundle check` beside the whole digest; a changed byte is refused by either.
- libokld's SHA-256, CRC-32, ZIP reader and writer (with ZIP64) and manifest reader hold
  against their vectors and refusals.

## License

Apache-2.0

## Symbols in a packaged debugger runner

A debugger locates the runner's JIT registration function and descriptor by
native symbols. A custom runner or carrier packaged with mcpp retains these
symbols with `--no-strip` or `[pack] strip = false`. The image's debug profile
controls its source information independently.

The precompiled-tools workflow preserves native symbols for okrun and checks
the unpacked Linux x86-64 package with nm, GDB and LLDB source stepping. Other
hosts retain their native execution smoke checks. A corrective binary candidate
uses an `asset_revision` filename suffix; its source tag and package version do
not change. The workflow refuses existing asset names and never replaces them.
