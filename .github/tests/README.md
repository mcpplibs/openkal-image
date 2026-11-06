# Debugger contract controls

The Linux `images` job runs `check-debugger-contract.py` with its existing
LLVM toolchain. The script builds the current libokld sources once with
address and undefined-behavior instrumentation, then runs both test programs
with leak detection enabled. The compressed fixture is a fixed RFC 1950
stream; no system zlib or additional SDK is needed.

`debug-image-builder.cpp` checks malformed and truncated ELF metadata,
compressed-data validation, relocation widths and boundaries, placement
arithmetic, allocation ownership and alignment. It preserves the input bytes.

`debug-image-loader.cpp` uses real freestanding ELF dependencies and actual
mapped execution. It checks ordinary and debugger-enabled runs, announcement
refusal, copy/registration allocation failures, fresh and preloaded owners,
shared/transitive dependencies and repeated failed loads. The source fixtures
are under `debug-loader`; the script builds them in a temporary directory.

These Linux controls do not qualify other existing loader failure exits or
native debugger frontends on every runner host.
