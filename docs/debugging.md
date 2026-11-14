# Source debugging

This page describes source breakpoints and variables in an image launched by
`okrun --debugger` with `openkal-ld` 0.5.0 or later. Remote board debug servers
and external debug-sidecar loading are separate interfaces.

## Build and start

Compile the image with DWARF debug information (`-g`) and retain its debug
relocations at link time (`--emit-relocs`). Retain the `.rela.debug_*` sections
when further processing the linked ELF. The normal requirements-note, placement
and format checks still apply.

For GDB:

```text
gdb --args okrun --debugger app.oke
(gdb) set breakpoint pending on
(gdb) break ok_main
(gdb) run
```

For LLDB:

```text
lldb -- okrun --debugger app.oke
(lldb) settings set plugin.jit-loader.gdb.enable on
(lldb) breakpoint set --name ok_main
(lldb) run
```

The debugger resolves the pending breakpoint when the image is registered.
Source-line breakpoints, local variables, stepping and normal exit are
verified on Linux x86-64 with the GDB and LLDB bundled in CLion 2026.1.5.2.
The runtime matrix for Windows, macOS and Linux AArch64 does not establish
native source-debugger compatibility on those systems.

## Image requirements and limits

The debugger-object builder accepts little-endian ELF64 metadata for x86-64
and AArch64, and ELF32 metadata for i386 (0.6.3). An i386 image's retained
link relocations are REL: their addend is the word at the place, which the link
has resolved, so the object holds each `R_386_32` and `R_386_PC32` word less the
symbol's value (and, for `R_386_PC32`, plus the place), and the debugger adds
its own. The image's run-time relocations (`.rela.dyn`, `.rela.plt`) are data in
the object. Embedded debug sections may use ELF zlib compression
(`SHF_COMPRESSED`); the loader expands them in the debugger object. The
executable image and its persistent compressed bytes remain unchanged.

An image containing `.debug_info` or `.debug_line` needs retained debug
relocations. Debugger mode refuses an image that lacks them. Ordinary runs
remain available. An image without source debug information can still expose
its retained defined symbols.

GNU legacy `.zdebug_*` sections, zstd-compressed debug sections and native
TLS symbols are unsupported in this debugger view. A stripped image's
external debug sidecar is not automatically loaded by the JIT path.
`okld debug-split` and the scripts in `tools/scripts` retain their separate
build-id-based interface for symbols outside the image.
