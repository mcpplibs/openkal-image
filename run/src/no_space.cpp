// openkal.space is not provided here: the manifest selects this unit instead
// of bindings_space.cpp, and an image that requires the interface is refused
// at load, naming it (SPEC 12.4).
#include "runner.h"

namespace okrun {
const binding* space_bindings(unsigned long& count) { count = 0; return nullptr; }
}  // namespace okrun
