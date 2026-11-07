// The image's calling convention (SPEC clause 12.2): System V on x86-64 and the
// procedure call standard on AArch64, whatever the host's; and the name of the
// architecture, as an okb names its directory (docs/okb.md). The one place the
// architecture appears in this library.
#pragma once

// THE CONVENTION'S FLOATING-POINT STATE (SPEC 12.2, 0.5.3) is part of the
// convention: on x86-64 the x87 control word 0x037F (extended precision, every
// exception masked) and MXCSR 0x1F80, on AArch64 FPCR zero. `okrun_fp_enter'
// establishes it and returns the state it found, which `okrun_fp_leave'
// restores; each writes only a word that differs. A thread of Windows begins
// with the x87 at double precision (0x027F), under which a C library that
// computes in long double reads decimal numbers otherwise.
#if defined(__x86_64__)
#define OKRUN_IMAGE_ABI __attribute__((sysv_abi))
inline constexpr char okrun_arch[] = "x86_64";
inline unsigned long long okrun_fp_enter() {
    unsigned short x87 = 0;
    unsigned mxcsr = 0;
    __asm__ volatile("fnstcw %0\n\tstmxcsr %1" : "=m"(x87), "=m"(mxcsr));
    const unsigned short image_x87 = 0x037F;
    const unsigned image_mxcsr = 0x1F80;
    if (x87 != image_x87) __asm__ volatile("fldcw %0" : : "m"(image_x87));
    if ((mxcsr & 0xFFC0) != image_mxcsr) __asm__ volatile("ldmxcsr %0" : : "m"(image_mxcsr));
    return static_cast<unsigned long long>(mxcsr) << 16 | x87;
}
inline void okrun_fp_leave(unsigned long long state) {
    const unsigned short x87 = static_cast<unsigned short>(state & 0xFFFF);
    const unsigned mxcsr = static_cast<unsigned>(state >> 16);
    unsigned short now_x87 = 0;
    unsigned now_mxcsr = 0;
    __asm__ volatile("fnstcw %0\n\tstmxcsr %1" : "=m"(now_x87), "=m"(now_mxcsr));
    if (now_x87 != x87) __asm__ volatile("fldcw %0" : : "m"(x87));
    if ((now_mxcsr & 0xFFC0) != (mxcsr & 0xFFC0)) __asm__ volatile("ldmxcsr %0" : : "m"(mxcsr));
}
#elif defined(__aarch64__)
#define OKRUN_IMAGE_ABI
inline constexpr char okrun_arch[] = "aarch64";
inline unsigned long long okrun_fp_enter() {
    unsigned long long fpcr = 0;
    __asm__ volatile("mrs %0, fpcr" : "=r"(fpcr));
    if (fpcr != 0) __asm__ volatile("msr fpcr, %0" : : "r"(0ULL));
    return fpcr;
}
inline void okrun_fp_leave(unsigned long long state) {
    unsigned long long fpcr = 0;
    __asm__ volatile("mrs %0, fpcr" : "=r"(fpcr));
    if (fpcr != state) __asm__ volatile("msr fpcr, %0" : : "r"(state));
}
#else
#define OKRUN_IMAGE_ABI
inline constexpr char okrun_arch[] = "";
inline unsigned long long okrun_fp_enter() { return 0; }
inline void okrun_fp_leave(unsigned long long) {}
#endif
