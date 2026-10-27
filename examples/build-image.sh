#!/usr/bin/env bash
# build-image.sh <arch> <out> <sources...> [-- <link arguments>] -- an ok image
# (or, named *.okso, an image another needs) from freestanding C,
# with the compiler and linker any LLVM carries (SPEC 12.2): no operating
# system in the triple, position-independent, emulated thread-local storage,
# x18 left alone on AArch64, segments aligned to 64 KiB, the two notes linked
# in, and the requirements written by `okld note'.
set -euo pipefail
arch="$1"; out="$2"; shift 2
sources=(); link=()
while [ $# -gt 0 ]; do
  if [ "$1" = -- ]; then shift; link=("$@"); break; fi
  sources+=("$1"); shift
done
: "${CLANG:=clang}" "${LLD:=ld.lld}" "${OKLD:=okld}"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
extra=()
[ "$arch" = aarch64 ] && extra=(-ffixed-x18 -mno-outline-atomics)
"$OKLD" note-source > "$work/note.S"
objs=()
for src in "${sources[@]}" "$work/note.S"; do
  o="$work/$(basename "$src").o"
  "$CLANG" --no-default-config --target="$arch-unknown-none-elf" -ffreestanding -nostdlibinc -fPIC -fvisibility=hidden -femulated-tls \
    -fasynchronous-unwind-tables -Xclang -fstack-clash-protection \
    -fno-stack-protector -fno-builtin -O2 "${extra[@]}" -c "$src" -o "$o"
  objs+=("$o")
done
entry=(-e ok_main)
case "$out" in *.okso) entry=(-soname "$(basename "$out")") ;; esac
"$LLD" -shared -z max-page-size=65536 -z now -z noexecstack --hash-style=both "${entry[@]}" \
  -o "$out" "${objs[@]}" "${link[@]}"
"$OKLD" note "$out"
with=()
for l in "${link[@]}"; do case "$l" in *.okso) with+=(--with "$l") ;; esac; done
"$OKLD" check "$out" "${with[@]}"
