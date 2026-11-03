# okgdb.py --- the symbols of the ok images a program has mapped, for gdb.
#
#   (gdb) source okgdb.py
#   (gdb) ok-symbols            # a running program, or a core file
#
# An image's instructions and read-only data are the pages of its file
# (openkal 0.21, kal_exec_map_part), so the program's mappings --- and a core
# file's, which records them --- name each image and where it lies: the
# address of a part, less the part's address in the image, is the image's
# base. Each image is given to gdb with its symbols at that base; where
# `okld debug-split' took its debug information away, the debug file is found
# by the image's build-id beside the image (`.build-id/xx/rest.debug') or in
# OKGDB_DEBUG_DIR, as debuginfod lays one out.
#
# An image the runner copied rather than mapped (a system without
# KAL_EXEC_PROP_FILE, or `okrun --debugger') is announced through the GDB JIT
# interface instead, which gdb reads without this file.
import os
import re
import sys

import gdb

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import okgdb_common as common  # noqa: E402


def _mappings():
    """(start, file offset, path) of each mapping of a file, from gdb's own report."""
    text = gdb.execute("info proc mappings", to_string=True)
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(?:\S+\s+)?(/.*)$", line)
        if m:
            out.append((int(m.group(1), 16), int(m.group(4), 16), m.group(5).strip()))
    return out


class OkSymbols(gdb.Command):
    """Load the symbols of every ok image the program has mapped, at its base."""

    def __init__(self):
        super().__init__("ok-symbols", gdb.COMMAND_FILES)

    def invoke(self, arg, from_tty):
        bases = {}
        for start, offset, path in _mappings():
            if path in bases or not os.path.exists(path) or not common.is_image(path):
                continue
            base = common.base_at(path, start, offset)
            if base is not None:
                bases[path] = base
        if not bases:
            print("ok-symbols: no ok image is mapped (one the runner copied is announced through the JIT interface)")
            return
        for path, base in sorted(bases.items()):
            symbols = common.debug_file(path)
            gdb.execute("add-symbol-file %s -o 0x%x" % (symbols, base), to_string=True)
            print("ok-symbols: %s at 0x%x%s" % (path, base, "" if symbols == path else " (" + symbols + ")"))


OkSymbols()
