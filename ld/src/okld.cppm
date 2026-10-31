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
export using ::okld_required_imports;
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
export using ::okld_sign_message;
export using ::okld_verify_message;
export using ::okld_sha256;
export using ::okld_crc32;
export using ::okld_zip_member;
export using ::okld_zip_each;
export using ::okld_zip_find;
export using ::okld_zip_input;
export using ::okld_zip_write;
export using ::okld_okb_arch;
export using ::okld_okb_manifest;
export using ::okld_okb_read_manifest;
export using ::okld_okb_digest;
export using ::okld_okb_each_file;
export using ::okld_okb_is_image;
export using ::okld_okb_admit;
export using ::okld_okb_chunks;
export using ::okld_okb_admit_chunked;
export using ::okld_parallel;
export using ::okld_okb_arch_of;

export namespace okld {
inline constexpr okld_u32 format_major = OKLD_FORMAT_MAJOR;
inline constexpr okld_u32 format_minor = OKLD_FORMAT_MINOR;
inline constexpr okld_u32 okb_version = OKLD_OKB_VERSION;
inline constexpr okld_u32 okb_alignment = OKLD_OKB_ALIGNMENT;
inline constexpr okld_u32 okb_chunk = OKLD_OKB_CHUNK;
}
