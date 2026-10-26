/* libokld --- the ok format (openkal image format, SPEC clause 12): its
 * definition, a reader that only reads bytes, and a loader.
 *
 * The C ABI is the interface; the module `openkal.ld' exports the same names.
 * Prefix `okld_'. Freestanding: no C library, no exceptions, no run-time type
 * information --- it is linked into a runner that carries no C library of its
 * own, and into a C library (`dlopen') that is itself being built. */
#ifndef OKLD_H
#define OKLD_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long long okld_u64;
typedef unsigned int       okld_u32;
typedef __SIZE_TYPE__      okld_size;

/* The version of clause 12 this library reads and writes. An image of a
 * higher major version is refused. */
#define OKLD_FORMAT_MAJOR 1u
#define OKLD_FORMAT_MINOR 0u

/* What a reading reports about an image. Every field is filled by
 * `okld_read'; nothing is mapped. */
struct okld_info {
    okld_u32 machine;            /* ELF e_machine: 62 x86-64, 183 AArch64 */
    okld_u32 format_major;       /* from the requirements note; 0 if absent */
    okld_u32 format_minor;
    okld_u32 has_requirements;   /* the note of type 1 is present */
    okld_u64 interfaces;         /* KAL_IFACE_* positions required */
    okld_u32 signed_;            /* the note of type 2 is present and not zero */
    okld_u32 reserved;
    okld_u64 span;               /* bytes of address space the image occupies */
    okld_u64 entry;              /* the entry, relative to where it is placed */
    okld_size needed_count;      /* DT_NEEDED entries */
};

/* Why something was refused: a sentence, and the clause it violates. */
struct okld_why {
    char text[256];
};

/* Reads an image's bytes. Returns 0, or a negative value with `why' filled. */
int okld_read(const void* bytes, okld_size size, struct okld_info* out, struct okld_why* why);

/* The checks of clause 12.2 over an image's bytes, every one; returns how many
 * did not hold, calling `report' with each. A name the image imports is
 * acceptable when it begins with `kal_' and `known_kal' says it is one (null:
 * any `kal_' name), or when `exported_elsewhere' says another image exports it
 * (null: none does). */
typedef int  (*okld_name_test)(const char* name, void* ctx);
typedef void (*okld_report)(const char* sentence, void* ctx);
int okld_check(const void* bytes, okld_size size, okld_name_test known_kal,
               okld_name_test exported_elsewhere, okld_report report, void* ctx);

/* The names an image imports, and the names it exports, one call each. */
void okld_imports(const void* bytes, okld_size size, void (*each)(const char* name, void* ctx), void* ctx);
/* The names an image requires: its imports less its weak ones. A weak import
 * is bound when the implementation or a needed image provides it and is zero
 * otherwise, so it requires no interface (SPEC 12.4); the requirements note is
 * derived from these. */
void okld_required_imports(const void* bytes, okld_size size, void (*each)(const char* name, void* ctx), void* ctx);
void okld_exports(const void* bytes, okld_size size, void (*each)(const char* name, void* ctx), void* ctx);

/* The `KAL_IFACE_*' positions a set of imported names requires: each `kal_'
 * name belongs to the interface its prefix names. */
okld_u64 okld_interface_of(const char* kal_name);

/* --- the requirements and the signature (clause 12.4) ------------------- */

/* Writes the requirements note's descriptor in place: `interfaces', and the
 * format version this library writes. The section must already be there with
 * room (it is laid down when the image is linked). */
int okld_set_requirements(void* bytes, okld_size size, okld_u64 interfaces, struct okld_why* why);

/* Signs in place: the signature note's 96 bytes become the public key and the
 * Ed25519 signature over the file with those 96 bytes read as zero. */
int okld_sign(void* bytes, okld_size size, const unsigned char seed[32], struct okld_why* why);

/* Verifies the signature note. Returns 1 when it is present, not zero, and
 * correct; 0 when absent or zero; negative when present and wrong. The key is
 * written to `key' when present. */
int okld_verify(const void* bytes, okld_size size, unsigned char key[32]);

void okld_public_key(const unsigned char seed[32], unsigned char key[32]);

/* --- loading -------------------------------------------------------------- */

/* What the loader asks of whoever holds the implementation. A runner fills it
 * from openkal.exec and its binding of names; a C library's `dlopen' fills it
 * from the same interface beneath itself. */
struct okld_host {
    void*     (*reserve)(okld_size bytes, void* ctx);                         /* kal_exec_alloc */
    int       (*publish)(void* region, okld_size offset, okld_size size, void* ctx); /* kal_exec_publish_part */
    void      (*release)(void* region, okld_size bytes, void* ctx);           /* kal_exec_free */
    okld_size (*granularity)(void* ctx);                                      /* kal_exec_granularity */
    /* The address a name is bound to, or null. Asked for every name the image
     * imports, before any other image is searched. */
    void*     (*resolve)(const char* name, void* ctx);
    /* The bytes of an image another needs (DT_NEEDED); null when there is
     * none. `release_bytes' is given them back. */
    const void* (*find_needed)(const char* name, okld_size* size, void* ctx);
    void      (*release_bytes)(const void* bytes, okld_size size, void* ctx);
    /* Ordinary memory for the loader's own records (kal_alloc, kal_free). */
    void*     (*alloc)(okld_size bytes, void* ctx);
    void      (*free)(void* p, okld_size bytes, void* ctx);
    /* Non-zero: each image is announced to a debugger through the GDB JIT
     * interface (`__jit_debug_register_code'), with its addresses where it was
     * placed, so that gdb and lldb show its symbols and its source. */
    int       debugger;
    void* ctx;
};

struct okld_module;

/* Maps, relocates and publishes an image and, first, every image it needs.
 * Initialisers are not run: `okld_initialise' runs them, so that a caller can
 * do what it must between. */
int  okld_load(const void* bytes, okld_size size, const char* name,
               const struct okld_host* host, struct okld_module** out, struct okld_why* why);
/* Runs the initialisers of the module and of the modules it needs, needed ones
 * first, each once. `call' enters a function of the image in the image's
 * convention (the runner supplies it; see okrun). */
void okld_initialise(struct okld_module* m, void (*call)(void* fn, void* ctx), void* ctx);
void okld_finalise(struct okld_module* m, void (*call)(void* fn, void* ctx), void* ctx);

void*        okld_symbol(struct okld_module* m, const char* name);  /* an exported name */
void*        okld_entry(struct okld_module* m);
void*        okld_base(struct okld_module* m);
const char*  okld_name(struct okld_module* m);
void         okld_unload(struct okld_module* m);

/* Every module loaded in this process, for `dl_iterate_phdr': its base, its
 * program headers and their count, and its name. Stops when `each' returns
 * non-zero, and returns that. */
int okld_iterate(int (*each)(void* base, const void* phdr, okld_u32 phnum, const char* name, void* ctx), void* ctx);

/* The module whose range holds an address, for `dladdr'. */
struct okld_module* okld_containing(const void* address);

#ifdef __cplusplus
}
#endif
#endif /* OKLD_H */
