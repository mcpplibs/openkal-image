// openkal.space, bound where the implementation provides it (the manifest
// selects this unit for those systems). A started context begins at an address
// in a copy of the space, not by a call, so the entry is passed as it is: the
// systems that provide the interface share the image's convention.
#include <openkal.h>
#include "image_abi.h"
#include "runner.h"

namespace okrun {

namespace {
template <auto F> struct present;
template <class R, class... A, R (*F)(A...)>
struct present<F> { OKRUN_IMAGE_ABI static R call(A... a) { return F(a...); } };

#define OKRUN_BIND(n)     { #n, reinterpret_cast<void*>(&present<&::n>::call) },
#define OKRUN_OWN(n)      OKRUN_BIND(n)
#define OKRUN_CALLBACK(n) OKRUN_BIND(n)
const binding g_space[] = {
#include "surface_space.inc"
};
}  // namespace

const binding* space_bindings(unsigned long& count) {
    count = sizeof g_space / sizeof g_space[0];
    return g_space;
}

}  // namespace okrun
