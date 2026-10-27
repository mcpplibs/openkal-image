#pragma once

namespace okrun {

struct binding { const char* name; void* address; };

struct image_state {
    int                argc = 0;
    const char* const* argv = nullptr;
    const char*        name = nullptr;
    bool               carried = false;   // okrun_options::carried
    // An image was entered. Before it is (a library loaded into a program of
    // this system), its arguments and name are the program's own.
    bool               started = false;
};
image_state& state();

const binding* bindings(unsigned long& count);
const binding* space_bindings(unsigned long& count);

inline bool same(const char* a, const char* b) {
    for (;; ++a, ++b) { if (*a != *b) return false; if (!*a) return true; }
}

}  // namespace okrun
