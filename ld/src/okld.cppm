// openkal.ld --- libokld's C interface, reached by import. The header is the
// one statement of it; this module exports what it declares.
module;
#include <okld.h>

export module openkal.ld;

export using ::okld_u64;
export using ::okld_u32;
export using ::okld_size;
export using ::okld_info;
export using ::okld_why;
export using ::okld_host;
export using ::okld_module;
export using ::okld_name_test;
export using ::okld_report;
export using ::okld_read;
export using ::okld_check;
export using ::okld_imports;
export using ::okld_exports;
export using ::okld_interface_of;
export using ::okld_set_requirements;
export using ::okld_sign;
export using ::okld_verify;
export using ::okld_public_key;
export using ::okld_load;
export using ::okld_initialise;
export using ::okld_finalise;
export using ::okld_symbol;
export using ::okld_entry;
export using ::okld_base;
export using ::okld_name;
export using ::okld_unload;
export using ::okld_iterate;
export using ::okld_containing;

export namespace okld {
inline constexpr okld_u32 format_major = OKLD_FORMAT_MAJOR;
inline constexpr okld_u32 format_minor = OKLD_FORMAT_MINOR;
}
