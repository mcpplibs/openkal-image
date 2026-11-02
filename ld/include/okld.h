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
#define OKLD_FORMAT_MINOR 1u

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

/* What an image's placement holds (SPEC 12.4, type 3): each stored segment is
 * its file bytes with every relative relocation applied for the base, and no
 * other word differs. A pass over every relative relocation and every stored
 * byte, asked when an image is sealed (`okld check'); okld_check, which the
 * loader asks on every load, holds only that the placement describes the image.
 * Returns how many did not hold, calling `report' with each; 0 for an image
 * that states no placement. Version 0.4. */
int okld_check_placement(const void* bytes, okld_size size, okld_report report, void* ctx);

/* The names an image imports, and the names it exports, one call each. */
void okld_imports(const void* bytes, okld_size size, void (*each)(const char* name, void* ctx), void* ctx);
/* The names an image requires: its imports less its weak ones. A weak import
 * is bound when the implementation or a needed image provides it and is zero
 * otherwise, so it requires no interface (SPEC 12.4); the requirements note is
 * derived from these. */
void okld_required_imports(const void* bytes, okld_size size, void (*each)(const char* name, void* ctx), void* ctx);
void okld_exports(const void* bytes, okld_size size, void (*each)(const char* name, void* ctx), void* ctx);

/* THE SYMBOLS OF AN IMAGE'S CODE AND DATA (0.2): every function and object
 * symbol its symbol table states (the section table's `.symtab', else its
 * dynamic symbols), as `value' (an address of the image, unrelocated: add the
 * module's base), `size' and name, in the table's order. The table lies in the
 * file and is never placed in memory by loading, which is why a program that
 * names an address in itself asks the party holding the file (openkal.debug,
 * SPEC 12.3). Returns how many were given. */
okld_u64 okld_symbols(const void* bytes, okld_size size,
                      void (*each)(okld_u64 value, okld_u64 symbol_size, const char* name, void* ctx),
                      void* ctx);

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

/* Ed25519 over a message that is not an image: the okb manifest's signature
 * (docs/okb.md). `okld_verify_message' returns 1 when the signature holds and
 * a negative value otherwise. */
void okld_sign_message(const unsigned char seed[32], const void* msg, okld_size size,
                       unsigned char signature[64]);
int  okld_verify_message(const unsigned char key[32], const void* msg, okld_size size,
                         const unsigned char signature[64]);

/* --- digests ------------------------------------------------------------- */

void     okld_sha256(const void* bytes, okld_size size, unsigned char out[32]);
/* The CRC-32 of ZIP (ISO 3309), continued from `crc' (0 to begin). */
okld_u32 okld_crc32(okld_u32 crc, const void* bytes, okld_size size);

/* --- ZIP archives and okb v1 (docs/okb.md) -------------------------------- */

#define OKLD_OKB_VERSION   1u
#define OKLD_OKB_ALIGNMENT 65536u

/* A member of a ZIP archive that lies in memory. `name' points into the
 * archive and is not terminated. `data' is the offset of its bytes, found
 * through its local header. */
struct okld_zip_member {
    const char* name;
    okld_size   name_len;
    okld_u64    header;     /* offset of the local header */
    okld_u64    data;       /* offset of the bytes */
    okld_u64    size;       /* bytes as stored */
    okld_u64    original;   /* bytes as extracted */
    okld_u32    method;     /* 0: stored */
    okld_u32    crc32;
};

/* Each member, in the central directory's order; `each' returns non-zero to
 * stop, and that value is returned. Returns 0 when every member was given, or
 * a negative value with `why' filled when the archive is malformed. ZIP64 is
 * read. */
int okld_zip_each(const void* archive, okld_u64 size,
                  int (*each)(const struct okld_zip_member* member, void* ctx), void* ctx,
                  struct okld_why* why);
/* The member of a name: 0 found, 1 absent, negative when malformed. */
int okld_zip_find(const void* archive, okld_u64 size, const char* name,
                  struct okld_zip_member* out, struct okld_why* why);

/* A member to write: stored; when `align' is not zero its bytes begin at a
 * multiple of the archive's alignment. */
struct okld_zip_input {
    const char* name;
    const void* bytes;
    okld_u64    size;
    int         align;
};
/* Writes a ZIP archive of the members, in order, into `out' and returns its
 * size; when `out' is null or `cap' is smaller, writes nothing and returns
 * the size it needs. Deterministic: no time is read. The padding is a field
 * of the member's local header (id 0x6b6f: the alignment, then zeros), or,
 * where fewer than eight bytes are wanted, bytes between members. ZIP64 is
 * written when a size, an offset or the count needs it. */
okld_u64 okld_zip_write(const struct okld_zip_input* members, okld_size count, okld_u32 alignment,
                        void* out, okld_u64 cap);

/* An architecture of the manifest: its name (`x86_64', `aarch64'), the
 * directory of its images, and the image it enters. */
struct okld_okb_arch {
    char name[16];
    char dir[64];
    char entry[128];
};
/* What `okb.json' states. An architecture without `dir' takes its name, and
 * one without `entry' takes the bundle's. */
struct okld_okb_manifest {
    okld_u32             okb;            /* the version of okb */
    char                 name[128];
    char                 version[64];
    char                 entry[128];
    struct okld_okb_arch archs[8];
    okld_u32             arch_count;
};
int okld_okb_read_manifest(const void* json, okld_size size, struct okld_okb_manifest* out,
                      struct okld_why* why);
/* The SHA-256 the manifest states for a member (`files.<member>.sha256'):
 * 1 found, 0 absent, negative when the manifest cannot be read. */
int okld_okb_digest(const void* json, okld_size size, const char* member, unsigned char out[32]);
/* Each member the manifest states a file for (`files.<member>'), in order;
 * `each' returns non-zero to stop, and that value is returned. Negative when
 * the manifest cannot be read. */
int okld_okb_each_file(const void* json, okld_size size,
                       int (*each)(const char* name, okld_size name_len, void* ctx), void* ctx);
/* Whether a member is an image (`.oke', `.okso'), whose bytes are aligned. */
int okld_okb_is_image(const char* name, okld_size name_len);
/* A member admitted for use: stored, an image's bytes at a multiple of
 * OKLD_OKB_ALIGNMENT, and its content the one `json' states (its SHA-256),
 * or, with no manifest, the one its CRC-32 states. 0, or negative with `why'
 * filled. Nothing is copied. */
int okld_okb_admit(const void* archive, okld_u64 size, const struct okld_zip_member* member,
                   const void* json, okld_size json_size, struct okld_why* why);
/* A member admitted by its shape alone: stored, within the archive, and an
 * image's bytes at a multiple of OKLD_OKB_ALIGNMENT. Its content is not read:
 * for a member whose content was compared before, on the same file (okrun's
 * remembered admission). 0, or negative with `why' filled. */
int okld_okb_admit_layout(okld_u64 size, const struct okld_zip_member* member, struct okld_why* why);
/* THE CHUNK DIGESTS okb.json may state for a member (`files.<member>.chunks',
 * docs/okb.md, version 0.1.8): the SHA-256 of each `size' bytes of it in
 * order, the last as long as what remains. 1 when they are stated, each given
 * to `each' (which returns non-zero to stop), and `*chunk_size' set; 0 when
 * not; negative when the manifest cannot be read. */
int okld_okb_chunks(const void* json, okld_size json_size, const char* member, okld_u64* chunk_size,
                    int (*each)(okld_u64 index, const unsigned char digest[32], void* ctx), void* ctx);
/* Jobs run by the caller's means, all of them, before it returns: job(i, ctx)
 * for each i below `count'. A loader has no threads of its own; a runner
 * gives it its own (okrun: openkal tasks). */
typedef void (*okld_parallel)(void (*job)(okld_u64 index, void* ctx), okld_u64 count, void* ctx, void* host);
/* okld_okb_admit, but where the manifest states the member's chunk digests
 * they are what is verified, as `parallel' runs them (null: one after
 * another), instead of the SHA-256 of the whole: a member's admission is as
 * fast as the processors together, where SHA-256 of one stream is not. With
 * no chunks stated it is okld_okb_admit. */
int okld_okb_admit_chunked(const void* archive, okld_u64 size, const struct okld_zip_member* member,
                           const void* json, okld_size json_size, okld_parallel parallel, void* host,
                           struct okld_why* why);
/* The chunk size `okld bundle' writes. */
#define OKLD_OKB_CHUNK 1048576u
/* The architecture's name for an ELF machine (62, 183), or null. */
const char* okld_okb_arch_of(okld_u32 machine);

/* --- loading -------------------------------------------------------------- */

/* What the loader asks of whoever holds the implementation. A runner fills it
 * from openkal.exec and its binding of names; a C library's `dlopen' fills it
 * from the same interface beneath itself. The loader keeps the pointer for the
 * life of every module loaded with it and calls through it again when the
 * module is unloaded, so the structure outlives them (a static one, in
 * practice). */
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
    /* Makes part of the region the bytes of the file the image was read from,
     * rather than a copy of them (kal_exec_map_part, openkal 0.21): `size'
     * bytes from `bytes' + `from', at `offset' in the region, as `how' says
     * (OKLD_MAP_*; 0 read, as it was 0 in version 0.3, and 1 executed). `from'
     * is a multiple of 65536 (KAL_MAP_ALIGNMENT) and `offset' and `size' of
     * the granularity. Zero when it did; anything else, and the loader copies
     * the bytes, as it does where this is null --- for bytes that are not a file
     * of their own, or an implementation that does not report
     * KAL_EXEC_PROP_FILE (or, for OKLD_MAP_WRITE, openkal 0.23). Version 0.3. */
    int       (*map)(void* region, okld_size offset, okld_size size, const void* bytes, okld_size from,
                     int how, void* ctx);
    /* Non-zero: each image is announced to a debugger through the GDB JIT
     * interface (`__jit_debug_register_code'), with its addresses where it was
     * placed, so that gdb and lldb show its symbols and its source. */
    int       debugger;
    void* ctx;
    /* Reserves the region at `at' (kal_exec_alloc_at, openkal 0.23): `at', or
     * null with nothing reserved, as it is where the implementation does not
     * report KAL_EXEC_PROP_PLACE. An image that states a placement (SPEC 12.4,
     * type 3) is placed at its base when this answers, and its relative
     * relocations are not applied; null, or refused, and the image is reserved
     * anywhere and relocated. Version 0.4. */
    void*     (*reserve_at)(void* at, okld_size bytes, void* ctx);
    /* Makes a part read-only once its relocations are applied
     * (kal_exec_seal_part, openkal 0.23): the image's read-only-after-
     * relocation range, for good where `forever' is non-zero. Null, and the
     * range stays writable, as it was before version 0.4. */
    int       (*seal)(void* region, okld_size offset, okld_size size, int forever, void* ctx);
    /* Non-zero: the modules loaded with this host are never unloaded --- a
     * runner's entry image and those it needs --- so their read-only-after-
     * relocation range is sealed for good. Version 0.4. */
    int       permanent;
    /* Non-zero: the pages an image states it touches when it starts (SPEC
     * 12.4, type 4) are read in as their part is mapped (OKLD_MAP_PREFETCH);
     * zero spends no memory ahead of the program. A runner sets it by the
     * program's resource preference. Version 0.4. */
    int       prefetch;
};

/* What `okld_host::map' is asked. Version 0.4. */
#define OKLD_MAP_EXECUTE  1   /* executed (KAL_EXEC_MAP_EXECUTE) */
#define OKLD_MAP_PREFETCH 2   /* read in now (KAL_EXEC_MAP_PREFETCH) */
#define OKLD_MAP_WRITE    4   /* written, privately (KAL_EXEC_MAP_WRITE) */

struct okld_module;

/* --- placement (SPEC 12.4, type 3; openkal 0.23) ---------------------------- */

/* The entries the placement note a sealed image carries has room for. */
#define OKLD_PLACEMENT_MAX 8u

/* The base `okld_place' chooses for an image when it is given none: from the
 * SHA-256 of its bytes, a multiple of 4 GiB from 16 TiB to below 32 TiB, where
 * no system places a program's own memory and each image of a process is likely
 * to have its own. */
okld_u64 okld_place_base(const void* image, okld_size size);

/* The image placed at `base' (0: okld_place_base): its bytes, each writable
 * loadable segment computed for `base' --- its file bytes with every relative
 * relocation, RELA's and RELR's, applied --- appended at a file offset congruent
 * to its address modulo 65536, and the placement note filled. A placement the
 * image carries already is replaced. Writes into `out' when `cap' holds it and
 * returns the size, as okld_zip_write does; 0 with `why' filled when the image
 * has no placement note to fill, more writable segments than the note has room
 * for, or a base that is not a multiple of 65536. */
okld_u64 okld_place(const void* image, okld_size size, okld_u64 base, void* out, okld_u64 cap,
                    struct okld_why* why);

/* What the placement note of an image states: its base and the number of its
 * entries (0 when it states none). */
int okld_placement(const void* image, okld_size size, okld_u64* base, okld_u32* count);

/* --- the touch note (SPEC 12.4, type 4) ------------------------------------- */

/* The ranges a touch note has room for: `okld note-source' lays down this many. */
#define OKLD_TOUCH_MAX 512u

/* Writes the touch note in place: `count' ranges, each two okld_u32 --- the
 * first 65536-byte block of the range in the file and the number of blocks ---
 * in the order the image first touches them when it starts. 0, or negative
 * with `why' filled: no note to write into, more ranges than it holds, or a
 * signed image (the signature is over these bytes: note, then sign). */
int okld_touch(void* image, okld_size size, const okld_u32* ranges, okld_u32 count, struct okld_why* why);
/* The ranges the touch note states, up to `cap' (pairs into `out'); returns
 * how many it states. */
okld_u32 okld_touches(const void* image, okld_size size, okld_u32* out, okld_u32 cap);

/* --- a loader's prepared copy (SPEC 12.4, type 5) ---------------------------- */

/* A FILE A LOADER WRITES FOR ITSELF AND DOES NOT DISTRIBUTE: a note of type 5
 * at its start, then blocks of bytes at multiples of 65536 that are, at their
 * addresses, what the image's writable segments hold --- computed for another
 * base than the one the image was sealed with (a runner's base of this boot),
 * or, with OKLD_PREPARED_SNAPSHOT, the image's state after its initialisers
 * ran, with the memory they obtained (the arena, after the image's span). The
 * loader takes the image's code from the image and these blocks for its data,
 * mapping each block it can and copying the rest. */
#define OKLD_PREPARED_SNAPSHOT 1u
/* The blocks a prepared copy holds at most. */
#define OKLD_PREPARED_MAX 256u

struct okld_prepared_block {
    okld_u64 address;     /* where the bytes go */
    okld_u64 offset;      /* where they are in the prepared file */
    okld_u64 size;
};

struct okld_prepared_info {
    okld_u32 version;     /* 1 */
    okld_u32 flags;       /* OKLD_PREPARED_* */
    okld_u64 base;        /* the image's base */
    unsigned char digest[32];   /* the image, by the runner's name for it (SHA-256) */
    okld_u32 count;       /* blocks, at most OKLD_PREPARED_MAX */
    okld_u32 facts;       /* snapshot: a word of what the environment answered the
                             initialisers, which a start compares with its own */
    okld_u64 asked;       /* snapshot: which of a start's own answers the initialisers
                             asked for (the runner's positions), folded into `facts' */
    okld_u64 kept;        /* the runner's own bytes kept with the copy: their offset in
                             the file (0: none), after the blocks */
    okld_u64 kept_size;   /* and their size */
    okld_u64 arena;       /* snapshot: the arena's address, after the image's span */
    okld_u64 arena_size;  /* snapshot: the bytes of it the state reaches */
    okld_u64 context;     /* snapshot: the word of the context the initialisers ran on */
    okld_u64 start;       /* snapshot: the second phase's entry, relative to the base */
    okld_u64 state;       /* snapshot: `__okm_snapshot_arena', relative to the base */
};

/* The image's writable segments computed for `base': their file bytes with
 * every relative relocation applied. `digest' is the name the caller gives
 * the image. Writes into `out' when `cap' holds it and returns the size, as
 * okld_place does; 0 with `why' filled when the image has no writable segment
 * or the base is not a multiple of 65536. */
okld_u64 okld_prepare(const void* image, okld_size size, okld_u64 base, const unsigned char digest[32],
                      void* out, okld_u64 cap, struct okld_why* why);
/* Writes a prepared file of `info' and `blocks', each block's bytes from
 * `source(address)' --- the whole of a snapshot's --- and `kept_size' bytes of
 * the runner's own from `kept' after them, as okld_prepare does. */
okld_u64 okld_prepare_blocks(const struct okld_prepared_info* info, const struct okld_prepared_block* blocks,
                             const void* (*source)(okld_u64 address, okld_u64 size, void* ctx), void* ctx,
                             const void* kept, okld_u64 kept_size, void* out, okld_u64 cap);
/* Reads a prepared file's note: 0, or negative when it is not one. Its blocks,
 * up to `cap', into `blocks'. */
int okld_prepared(const void* prepared, okld_size size, struct okld_prepared_info* info,
                  struct okld_prepared_block* blocks, okld_u32 cap);

/* Maps, relocates and publishes an image and, first, every image it needs.
 * Initialisers are not run: `okld_initialise' runs them, so that a caller can
 * do what it must between. The loader keeps no pointer into `bytes', nor into
 * the bytes `find_needed' gives it: each may be released once the call returns
 * (version 0.1.6; a runner releases the file it ran). */
int  okld_load(const void* bytes, okld_size size, const char* name,
               const struct okld_host* host, struct okld_module** out, struct okld_why* why);
/* okld_load, the image's data taken from a prepared copy (type 5) of it: at the
 * copy's base, which the host reserves (reserve_at) or the load is refused;
 * with a snapshot, its arena reserved after the span, its initialisers
 * counted as run, and of its relocations only those naming an import applied
 * again --- what the initialisers wrote over the rest is the snapshot's. A
 * snapshot of an image that needs another is refused: the images it needs
 * would start without theirs. The copy is a file of its own: `okld_host::map'
 * is given its bytes. Its digest and its facts are not compared with the
 * image's and the environment's: the caller named both. Version 0.4. */
int  okld_load_prepared(const void* bytes, okld_size size, const char* name, const struct okld_host* host,
                        const void* prepared, okld_size prepared_size, struct okld_module** out,
                        struct okld_why* why);
/* EACH WORD A RELOCATION OF THE MODULE WRITES WITH THE ADDRESS OF A NAME IT
 * IMPORTS --- a symbol it does not define --- and the value the loader writes
 * there now: the words a load of the module's snapshot writes again, for the
 * process it is loaded into, and the only words of a snapshot that may hold
 * an address the runner gave. Stops when `each' returns non-zero, and returns
 * that. Version 0.4. */
int okld_bound_imports(struct okld_module* m, int (*each)(void* slot, okld_u64 value, const char* name, void* ctx),
                       void* ctx);

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
