# JIT source debugging: diagnosis and implementation requirements

Status: checked loader implementation and focused controls completed; producer and adapter integration remain in progress.
Related: mcpp issue 885, mcpp-ide PR 4, openkal-image PR 29.

This record concerns a host debugger reading an OpenKal image's source locations and
variables. It does not define a remote board debugger or replace a platform's named
debug-server runner.

## Reproduction and controls

A small C++ program is built by public mcpp 2026.11.5.1 with openkal-platform 0.23.7.
Its exact `run --target x86_64-openkal --print-launch` descriptor starts okrun 0.4.4.
The program sets `answer` to 40, adds two, writes a completion marker and exits. The
debuggers are the GDB and LLDB included in the official CLion 2026.1.5.2 Linux SDK.
No user debugger configuration is edited. All source paths and logs stay in private evidence.

| Control | Observed result |
|---|---|
| Original launch descriptor | No image JIT registration; source breakpoint remains pending |
| Add only okrun `--debugger` | Registration occurs, but the source breakpoint targets an unmapped low address |
| Retain link relocations with `--emit-relocs`, original loader | Same low-address failure |
| Convert the JIT copy to ET_REL with section-relative symbol/relocation values, retain link relocations | GDB stops at the source breakpoint, shows 40, steps to 42 and completes |
| Same loader prototype, original image without retained relocations | Same low-address failure |
| Prototype and retained relocations, compressed debug sections, LLDB | `.debug_info` decompression reports `Z_DATA_ERROR` |
| Same LLDB case with only debug compression disabled at link time | Source breakpoint, values 40/42, step and normal completion pass |

The loader control recompiles only `load.cpp` and relinks the existing matched runner
objects. The program control relinks its existing objects. Neither rebuilds LLVM.
These are CLI debugger controls, not a completed IDE GUI or multi-host qualification.

## Root cause and ownership

The current `announce` changes ELF program addresses, allocated-section addresses and
defined symbol values. It does not relocate linked DWARF addresses. The debugger therefore
finds symbols at the placed image but source locations at the image's former low addresses.
The existing claim that every address in the debugger copy has been moved is too broad.

The prototype retains relocation information and presents an ET_REL debugger object with
section-relative symbols and relocations. The debugger can then relocate debug information
using the allocated sections' actual addresses. GDB's registration interface expects the
registered object to describe actual runtime addresses; see the
[GDB JIT interface](https://sourceware.org/gdb/current/onlinedocs/gdb.html/JIT-Interface.html).

The final implementation belongs to the image loader and producer. The platform supplies
the appropriate link policy. IDE adapters select a debugger launch through the backend's
shared contract. The core build system does not identify okrun by filename or append an
OpenKal-specific option. Ordinary execution need not allocate debugger symbol files.

## Requirements before adoption

- Validate ELF bounds and arithmetic, symbol section indices, absolute/undefined symbols,
  relocation target sections and offsets. The current prototype is not this validation.
- Preserve correct symbol values for ordinary functions, section symbols and any supported
  special symbol kinds. A simple symbol breakpoint and a source breakpoint are separate checks.
- Handle compressed debug sections in the debugger view, or establish an explicit producer
  requirement through both GDB and LLDB controls. Changing the persistent release payload to
  uncompressed solely to avoid a debugger issue has not been adopted.
- Preserve allocation failure cleanup, registration/unregistration lifetime and multiple loaded
  images. The original payload bytes remain unchanged by debugger-view construction.
- Define the old-image behavior when debug information exists without retained relocations.
  It must not silently offer incorrect source addresses. Images without source debug information
  may still provide symbol-level debugging.
- Verify ordinary and split DWARF, compressed/uncompressed sections, a dependent image,
  stop/resume and a debug-enabled custom build profile. Release payload size and ordinary-run
  behavior remain explicit checks.
- Exercise the final packaged adapter and runner in both stable CLion versions, with the
  appropriate host debugger. Linux GDB/LLDB controls do not prove native Windows/macOS GUI behavior.

## Launch contract and release dependency

The current CLion adapter calls the ordinary `run/launch` method for debugging. The shared
backend's `debug/configuration` also starts from the ordinary launch. Both assume that a
runner automatically announces image symbols, whereas okrun requires `--debugger`.

Existing named runners and structured platform information should be examined before adding
a new build-language field. A debugger-controlled program is distinct from a board's debug
server; reusing the arbitrary runner name `debug` without that distinction is not valid.
Debugger-specific setup belongs to the adapter and should not require global user config edits.

The implementation must avoid a new mandatory core API that makes publishing the new platform
depend on the core release that itself requires that platform. This dependency constraint does
not justify dropping custom-profile coverage or hardcoding OpenKal in the core.

Image PR 29 is held for this work; the already qualified base API/backend release group and
index publication proceed independently. The final correction is to be integrated into the
same image PR after focused controls and review.

Evidence: `<evidence-root>/mcpp-885-runner-debug-preflight/diagnosis-verified.json` and the
adjacent original, retained-relocation and debugger logs. No private logs are included here.

## 2026-11-06 implementation and control update

The private debugger-view builder now checks ELF64 metadata, section/symbol/relocation
bounds, arithmetic and relocation write widths for x86_64 and AArch64. It retains the
original section addresses while constructing the section-relative debugger copy.
ELF zlib debug sections are inflated only in that copy, with output size and Adler32
checks. The persistent payload remains compressed. A debug image lacking retained
source relocations is explicitly refused; ordinary execution remains available.

The checked-v3 runner passed both bundled GDB and LLDB source breakpoints, variable
values 40 then 42, step and successful exit using the compressed fixture. The old
no-relocation image is refused before its application work in debugger mode and still
runs normally. Only the loader translation units and existing runner objects were
compiled or linked. This is not final packaged IDE or native multi-host qualification.

The private builder passed 64 sanitizer-backed component cases, including 1048
truncated prefixes, compressed-data corruption, relocation boundaries, allocation
failures and repeated allocation/release. An additional unaligned-input probe exposed
undefined behavior in metadata reference alignment. The builder now explicitly
refuses unaligned input and unaligned allocator storage before typed accesses; the
allocator failure path releases the exact original allocation once. This does not
claim to settle the existing public loader's arbitrary-pointer alignment contract.

The new announcement failure branch also releases the dependency references acquired
by that load. Nine actual Linux x86_64 loader controls passed with ASAN, UBSAN and
LSan: real dependent ELF images, execution, source-debug refusal, debug-copy and JIT
entry allocation failures, pre-existing owners, a shared dependency DAG and repeated
failures. Removing only the new rollback loop reproduced residual dependency/JIT
state, including the case where visible module counts initially concealed an extra
reference. Other pre-existing loader failure exits are outside these controls.

Evidence is under `<evidence-root>/mcpp-885-jit-builder-contract-tests/`, its `loader/`
subdirectory and `<evidence-root>/mcpp-885-runner-debug-preflight/checked-jit-v3/`.

## 2026-11-06 producer experiment without a new core API

Retaining relocations need not depend on the name of a build profile. A tested route
links with `--emit-relocs` and uses the selected LLVM toolchain's existing objcopy
before the normal note/place/check seal. Its removal patterns exclude debug and
dynamic relocation sections:

```text
--remove-section=.rela.*
--remove-section=!.rela.debug_*
--remove-section=!.rela.dyn
--remove-section=!.rela.plt
```

The negated removal patterns matter. An earlier control using `--keep-section`
alongside a removal pattern did not retain the debug relocations and was rejected
before sealing. Standard `.rela.*` non-debug sections are pruned; a nonstandard
`.rela__lcxx_override` section remains, so this control does not claim to remove
every non-debug static relocation section.

Using the same fixture objects, this route retained seven debug relocation sections.
All 25 allocated sections kept their addresses, sizes and flags. Their bytes were
unchanged except permitted dynamic-symbol section-index renumbering; dynamic symbol
names, values, sizes, bindings, types and referenced section names were equivalent.
Normal note/place/check succeeded, followed by the same actual GDB and LLDB
40-to-42 controls. The sealed fixture was 8297032 bytes. Evidence is under
`<evidence-root>/mcpp-885-debug-relocation-prune/`.

The existing build-program `toolchain_dir()` and `seal()` outlets can name the
resolved toolchain's objcopy and the ordered seal steps. This avoids an added
mandatory core API and its core/platform publication cycle. Integration still needs
a public-mcpp platform consumer check, default and custom debug profiles, a no-debug
release size check, and the debugger-launch contract. External debug sidecars and
native Windows/macOS debugger behavior remain unqualified.
