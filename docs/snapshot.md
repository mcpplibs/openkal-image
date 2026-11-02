# A snapshot of an image's initialisers

An image's initialisers --- its C library's start, a C++ program's static constructors --- compute
the same memory at every start of the same image on the same machine. A snapshot keeps that
memory: the runner runs the initialisers once in a boot and writes the image's data and the
memory they obtained to a prepared copy (SPEC 12.4, type 5, flag `OKLD_PREPARED_SNAPSHOT`).
Every later start maps the copy, runs no initialiser, and enters the image's C library to take
what the start itself supplies. The snapshot is the runner's and the user's; it is not
distributed, and nothing in the image as published describes it.

## When one is made and used

A runner that places an image at this boot's base (`OKRUN_PLACE` unset: the image states a
placement and the implementation reports `KAL_EXEC_PROP_PLACE`) looks for
`<digest>-<base>.oksnap` in its cache directory (`OKRUN_CACHE`, else `$XDG_RUNTIME_DIR/okrun`,
else the user's cache directory's `okrun/placed`). It uses the file when its note states the
image's digest, the base, and the word of facts this implementation gives (below).

When there is none, and the image's C library takes part (it exports `__okrun_snapshot`), the
runner creates `<digest>-<base>.sealing` exclusively and starts the program again as it was
started --- its own image, its arguments, its named values --- with `OKRUN_SNAPSHOT=start` and
the null device for its streams. That runner starts another with `OKRUN_SNAPSHOT=make` and ends
at once, so that the first waits only for it and the one making the snapshot outlives no
parent. The first goes on to start the image as it would have. The marker records the outcome
(`made`, or `refused:` and the reason), and no other start of the boot asks again; a new boot
removes the markers with the copies. A program started for economy (openkal 0.23,
`KAL_RESOURCES_ECONOMY`) uses a snapshot and does not have one made.

`OKRUN_SNAPSHOT=0` neither uses nor makes one.

## What the initialisers are given while it is made

The runner making a snapshot loads the image at the base and binds its imports to
`run/src/seal.cpp`:

| names | answer |
| --- | --- |
| `kal_alloc`, `kal_free`, `kal_region_*` | memory of the arena; nothing is given back |
| `kal_memory_granularity`, `kal_exec_granularity`, every `*_props` without an argument, `kal_version`, `kal_interfaces`, `kal_time_monotonic_granularity`, `kal_timeout_granularity`, `kal_fs_max_name`, `kal_env_system` | the implementation's own answer: a fact |
| `kal_task_current` | one fixed word, the context the initialisers run on |
| `kal_task_yield` | nothing to yield to |
| `kal_prof_active` | zero |
| every other name | refused: the runner ends without a snapshot, and the marker names the call |

The facts are what the implementation states of itself. They are folded into one word, which
the copy records and a start compares with its own: a snapshot made under another
implementation, another version of it or another machine's granularity is not used.

**The arena** lies beside a boundary of 256 MiB after the image's span. A region, and any memory
aligned to 64 KiB or more, is placed at or above the boundary, aligned from the address itself
as asked --- an allocator that finds a region's metadata by masking an address (mimalloc aligns
its regions to 256 MiB) needs the alignment of the address, not of an offset. Other memory is
placed below the boundary, downward, while it does not reach the image, and above the regions
otherwise. The arena is one range, and its addresses are asked of the environment as it grows
(`kal_exec_alloc_at`).

## The C library's part

An image's C library takes part by exporting two names:

```c
struct okrun_snapshot_record {   /* __okrun_snapshot */
    kal_u64 arena;     /* the arena's address */
    kal_u64 size;      /* its bytes */
    kal_u32 phase;     /* 1: the initialisers run for a snapshot; 2: a start from one */
    kal_u32 reserved;
    kal_u64 context;   /* the word of the context the initialisers ran on */
};
void __okrun_snapshot_start(void);
```

**Phase 1.** The runner sets `phase` to 1 before the initialisers run. The C library brings up
its memory and nothing else: no named value, no stream, no randomness, no clock. A named value
read while the phase lasts (`getenv`) is asked of the start, which is refused. After the
initialisers the runner calls `__okrun_snapshot_start`, and the C library reports, by the same
means, what they did that a snapshot cannot hold --- a named value set by one, which the start's
own would replace.

**Phase 2.** A start from the snapshot writes the record (`phase` 2, the arena, the context) and
calls `__okrun_snapshot_start` before the image's entry. The C library makes the snapshot's
context record its own context's, takes the arguments, the named values, the streams, the
directories, randomness and the stack's guard, and lets its allocator draw its own randomness
again. Memory within the arena is never given back to the environment, which did not give it:
it is the runner's mapping of the copy.

openkal-musl 0.27.0 takes part (`port/src/okm_start.c`).

## The copy

The note's descriptor (`okld_prepared_info`) states the base, the image's digest, the facts, the
arena and its size, the context word, and the offsets from the base of `__okrun_snapshot_start`
and of `__okrun_snapshot`. Its blocks are the 64 KiB blocks of the image's writable segments and
of the arena that hold anything but zeros, joined where at most two blocks of zeros lie between,
at file offsets congruent to their addresses modulo 65536; a block lies within one segment or
within the arena.

`okld_load_prepared` reserves the span at the base and the arena after it, maps each block
privately (`KAL_EXEC_MAP_WRITE`, read in with the image where the runner reads ahead), and
applies again only the relocations that name an import --- the words the initialisers may not
have changed, bound now to this process's implementation. The image's initialisers are counted
as run. A snapshot of an image that needs another image is refused: that image would start
without its own.

## The proof

Before it writes the copy, the runner holds that the snapshot holds nothing of its own process:

1. every relocation that names an import still holds what the loader wrote there
   (`okld_bound_imports`): an initialiser that wrote over a binding is refused;
2. no other word of the image's data or of the arena is the address of a binding: a function
   pointer to an import kept elsewhere would, in a start from the snapshot, be the address of a
   refusal of the runner that made it.

The bindings are the only addresses of the runner's process the initialisers are given. An
address of the stack they keep is of frames that have returned, as it is after any start; the
bytes a copy of a value carries beyond what it holds (a short string's unused characters) are
often such addresses, so they are not examined.

## What differs from a start without one

- Options an allocator reads from the named values while the C library starts (`MIMALLOC_*`)
  are read after the snapshot's memory exists, and those it read while the initialisers ran do
  not take effect; `OKRUN_SNAPSHOT=0` runs the initialisers at the start.
- A program whose initialisers read the named values other than through `getenv` (`environ`
  itself) reads them empty while the snapshot is made, and no refusal reports it.
- The allocator's per-heap secrets are drawn once a boot, when the snapshot is made, not once a
  start.
