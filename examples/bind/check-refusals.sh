#!/usr/bin/env bash
# check-refusals.sh --- the boundary mcpplibs.openkal-bind refuses (docs/bind.md).
#
# Each case adds one declaration to a copy of mathlib's interface and builds the
# program over it: the build must fail, and say why. The reasons are the
# plugin's; this script only reads them.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The repository's directory as the system spells it: a manifest names it, and
# mcpp on Windows reads a drive, not the shell's `/d/...'.
repo="$(cd "$here/../.." && { pwd -W 2> /dev/null || pwd; })"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

refused() {   # refused <case> <expected words> <declarations...>
    local name="$1" want="$2"; shift 2
    local d="$work/$name"
    mkdir -p "$d"
    cp -R "$here/mathlib" "$d/mathlib"
    cp -R "$here/app" "$d/app"
    rm -rf "$d/mathlib/target" "$d/app/target"
    sed -e "s|\.\./\.\./\.\./run|$repo/run|" -e "s|\.\./\.\./\.\./bind|$repo/bind|" \
        "$here/mathlib/mcpp.toml" > "$d/mathlib/mcpp.toml"
    sed -e "s|include/mathlib.h|include/variant.h|" "$here/mathlib/build.mcpp" > "$d/mathlib/build.mcpp"
    { echo '#include "mathlib.h"'; printf '%s\n' "$@"; } > "$d/mathlib/include/variant.h"
    if (cd "$d/app" && mcpp build) > "$d/build.log" 2>&1; then
        echo "  FAIL  $name: the build succeeded"
        failures=$((failures + 1))
    elif grep -q -- "$want" "$d/build.log"; then
        echo "  ok    $name: refused, naming $want"
    else
        echo "  FAIL  $name: refused for another reason:"
        sed 's/^/        /' "$d/build.log" | tail -20
        failures=$((failures + 1))
    fi
}

refused long          "\`long'"               'long mathlib_long(long v);'
refused variadic      "variadic"              'int32_t mathlib_format(const char* format, ...);'
refused unprototyped  "has no prototype"      'int32_t mathlib_legacy();'
refused old-callback  "without a prototype"   'typedef void (*mathlib_old)(); void mathlib_register(mathlib_old f);'
refused not-exported  "is not exported"       'int32_t mathlib_missing(void);'
refused variable      "the variable"          'extern int32_t mathlib_version;'
refused wide          "wchar_t"               'size_t mathlib_wide(const wchar_t* text);'
refused field         "in the field"          'struct mathlib_span { long begin, end; };' 'int32_t mathlib_span_size(struct mathlib_span s);'
refused not-c         "not a C interface"     'namespace mathlib { int32_t f(void); }'

[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
echo "every case is refused, and says why"
