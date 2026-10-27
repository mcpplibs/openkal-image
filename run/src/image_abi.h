// The image's calling convention (SPEC clause 12.2): System V on x86-64 and the
// procedure call standard on AArch64, whatever the host's; and the name of the
// architecture, as an okb names its directory (docs/okb.md). The one place the
// architecture appears in this library.
#pragma once

#if defined(__x86_64__)
#define OKRUN_IMAGE_ABI __attribute__((sysv_abi))
inline constexpr char okrun_arch[] = "x86_64";
#elif defined(__aarch64__)
#define OKRUN_IMAGE_ABI
inline constexpr char okrun_arch[] = "aarch64";
#else
#define OKRUN_IMAGE_ABI
inline constexpr char okrun_arch[] = "";
#endif
