# openkal-image

The reference loader, runner and tools of the **ok format**: the openkal image format,
openkal SPEC clause 12. One image per architecture runs on every system of that
architecture that has a runner.

| Package | Target | What it is |
|---|---|---|
| `openkal-ld` | `libokld` | The format's definition. A reader of bytes, a checker, a signer (Ed25519) and a loader. Freestanding: no C library, no exceptions. Its users are libokrun, `okld`, and a C library's `dlopen`. |
| `openkal-run` | `libokrun` | The runner's core. It binds an image's names to this process's one openkal implementation, in the image's calling convention, then enters the image. |
| `openkal-tools` | `okrun`, `okld` | `okrun [--require-signature] [--trust <key>] [--debugger] image\|okb args...` runs an image or an okb. `okld check \| note \| sign \| keygen \| inspect \| note-source \| bundle \| bundle check` works on images and okbs on a build machine. |
| `openkal-bind` | `mcpp.mcpplibs.openkal_bind` | A build plugin. A library published as an image (`.okso`) and a C header is called from a program of Linux, macOS or Windows through a binding generated from the header ([docs/bind.md](docs/bind.md)). |

`libokld` is the loader at run time and `okld` is the tool on the build machine. They share a
root and differ in role, as `ld.so` and `ld` do.

## An image

```sh
okld note-source > note.S                      # the two notes (SPEC 12.4)
clang --target=x86_64-unknown-none-elf -ffreestanding -fPIC -femulated-tls -c app.c note.S
ld.lld -shared -z max-page-size=65536 -z now -e ok_main -o app.oke app.o note.o
okld note app.oke                              # the interfaces its imports require
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
okld bundle check app.okb                                            # stored, aligned, digests, signatures
okrun app.okb arguments...                                           # this machine's architecture's entry
```

The images an image needs are found in the okb, then beside it, in `lib/<arch>/` and `lib/`, and
in `OKRUN_PATH`. A program that carries its images gives their archive to
`okrun_run_okb_bytes`, which runs it from memory and writes nothing to disk.

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
- libokld's SHA-256, CRC-32, ZIP reader and writer (with ZIP64) and manifest reader hold
  against their vectors and refusals.

## License

Apache-2.0
