// A private ELF view for debuggers; it never changes the executable image.
#pragma once
#include <okld.h>

namespace okld {
bool debugger_image(const void* bytes, okld_size size, okld_u64 base,
                    const okld_host* host, void** out, okld_size* out_size,
                    okld_why* why);
}
