// The image's calling convention (SPEC clause 12.2): System V on x86-64 and the
// procedure call standard on AArch64, whatever the host's. The one place the
// architecture appears in this library.
#pragma once

#if defined(__x86_64__)
#define OKRUN_IMAGE_ABI __attribute__((sysv_abi))
#else
#define OKRUN_IMAGE_ABI
#endif
