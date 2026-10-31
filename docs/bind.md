# openkal-bind: an image's library called from a program of any system

A library can be published once, as an ok image (`lib<name>.okso`) for each architecture and a
C header. A program built for openkal links the image as it links any shared library. A
program built for Linux, macOS or Windows calls the same image through a binding that the
build plugin `mcpplibs.openkal-bind` generates from the header. The consumer depends on the
library and includes its header; it neither knows nor states which of the two it is.

## Use

The library's package states the header and the image, and calls the plugin from its
`build.mcpp`:

```toml
[package]
name    = "mathlib"
version = "0.1.0"

[targets.mathlib]
kind = "lib"

[build]
sources      = []
include_dirs = ["include"]

[target.'cfg(not(os = "openkal"))'.dependencies]
openkal-run = "0.1.8"

[build-dependencies]
openkal-bind = "0.1.8"
```

```cpp
import mcpp;
import mcpp.mcpplibs.openkal_bind;

int main() {
    return mcpp::mcpplibs::openkal_bind::bind({
        .header = "include/mathlib.h",
        .image  = "lib/{arch}/libmathlib.okso",
    });
}
```

`examples/bind/` is this library and a program that uses it.

## What the plugin does

| Target | Statement |
|---|---|
| `<arch>-openkal` | The image is linked as it is (its path on the link line) and placed beside the program. |
| any other x86-64 or AArch64 target | The plugin reads the header with clang, checks the boundary (below), and generates a C source in the build program's output directory. The source defines each function of the header under its own name. The first call opens the image through libokrun (`okrun_open_library`); every call forwards through a pointer in the image's calling convention: System V on x86-64 whatever the system's, the procedure call standard on AArch64. The compiler converts the call. The image is placed beside the program. |

The header is read as the image reads it: C17, for `<arch>-unknown-none-elf`, with the
compiler's freestanding headers only (`<stdint.h>`, `<stddef.h>`, `<stdbool.h>`, ...). The
declarations of the package's own files are bound; those of the compiler's headers are not.

The image is found at run time beside the program, then in its `lib/<arch>/` and `lib/`, then
in each directory of `OKRUN_PATH` (docs/okb.md §5).

## The boundary

The plugin refuses the build, naming each declaration and its reason, when the interface
cannot cross between an image and a program of the system:

| Rule | Reason |
|---|---|
| The header is C. | A C++ declaration has no convention the binding can forward. clang's error is the refusal. |
| No `long`, `unsigned long`, `long double`, `wchar_t`, `wint_t`, `off_t` or `clock_t`, as written or through a typedef or a structure field of the header. | An image is LP64. A Windows program is LLP64: these types differ in size between the two sides. `int64_t`, `int32_t`, `size_t` and `intptr_t` have one size on both. |
| Functions only. | An image's variables are not reachable from the program. An interface exports a function that returns the value. |
| Every function has a prototype and is not variadic. | A call with unknown or variable arguments cannot be converted. |
| Every function is exported by the image. | Its ELF dynamic symbols are read at build time. |
| A callback (a function pointer a function takes) has a prototype, is not variadic, and does not return a function pointer. | On x86-64 Windows the binding gives the image a System V entry that calls the program's function. There is a pool of sixteen such entries per callback type, and the pool is reused for a function that is passed again. A function pointer that the image returns, or that lies inside a structure, is not converted there, and is refused. |
| On macOS, a callback has no parameter narrower than 32 bits. | An image does not widen such an argument, and macOS expects its caller to. |

Two rules belong to the library and are not checked:

- memory is released by the side that allocated it, so an interface creates and destroys in
  pairs;
- no exception crosses the boundary.

## Where clang comes from

clang is taken from the first of the following that is present (SPEC-007 R6.5). The plugin
records the source with `mcpp::decision`.

1. the build program's choice (`.clang`);
2. `OPENKAL_BIND_CLANG`;
3. the toolchain's C compiler, when it is clang;
4. the payload `xim:llvm@23.1.3`, declared `provision = "on-request"`, installed only when
   the plugin asks for it.

On x86-64 Windows, MSVC's compiler cannot call the System V convention and is refused; the
llvm toolchain's clang converts the call.

## Versions

| openkal-bind | Statement |
|---|---|
| 0.1.2 | This document. Released with openkal-run 0.1.2, whose library interface it calls. |
| 0.1.3 | No change of its own; released with the archive. |
| 0.1.4 | No change of its own; released with the archive, whose runner starts programs in a directory it may search but not read (openkal-linux 0.18.3). |
| 0.1.5 | No change of its own; released with the archive, whose runner maps an image or okb file rather than reading it whole, and binds `openkal.map` for images (openkal 0.18). |
| 0.1.6 | No change of its own; released with the archive, whose runner releases the file it ran once the image is loaded, and whose loader digests on the processor's SHA-256 instructions and writes each segment once. |
| 0.1.7 | No change of its own; released with the archive, whose loader also digests on ARMv8's SHA-256 instructions on Linux where the processor states them. |
| 0.1.8 | No change of its own; released with the archive, built against openkal 0.19.0 (the runner binds `kal_task_cores` and `kal_task_set_priority`), whose okb carries chunk digests the runner verifies on several contexts at once. |
