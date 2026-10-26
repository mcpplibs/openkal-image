# openkal-image

The reference loader, runner and tools of the **ok format**: the openkal image format,
openkal SPEC clause 12. One image per architecture runs on every system of that
architecture that has a runner.

| Package | Target | What it is |
|---|---|---|
| `openkal-ld` | `libokld` | The format's definition. A reader of bytes, a checker, a signer (Ed25519) and a loader. Freestanding: no C library, no exceptions. Its users are libokrun, `okld`, and a C library's `dlopen`. |
| `openkal-run` | `libokrun` | The runner's core. It binds an image's names to this process's one openkal implementation, in the image's calling convention, then enters the image. |
| `openkal-tools` | `okrun`, `okld` | `okrun [--require-signature] [--trust <key>] [--debugger] image args...` runs an image. `okld check \| note \| sign \| keygen \| inspect \| note-source` works on images on a build machine. |

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

## What CI asserts

- Images are built once, on Linux, for x86_64 and AArch64.
- The same bytes then run on:
  - linux-x86_64 and windows-x86_64 (the x86-64 images);
  - linux-aarch64 and macos-arm64 (the AArch64 images).
- Each run covers arguments, thread-local storage, a callback into the image, and an image
  that another image needs.
- `okrun` refuses an unsigned image when a signature is required, an image with a changed
  byte, and an image signed by an untrusted key.

## License

Apache-2.0
