# oklldb.py --- the symbols of the ok images a program has mapped, for lldb.
#
#   (lldb) command script import oklldb.py
#   (lldb) ok-symbols
#
# As okgdb.py: each mapped part of an image names the image's file and, with
# the part's place in the image, its base; each image is added as a module and
# loaded with that slide. A debug file `okld debug-split' wrote is found by the
# build-id beside the image or in OKGDB_DEBUG_DIR. lldb reads an image the
# runner copied through the GDB JIT interface
# (`settings set plugin.jit-loader.gdb.enable on').
import os
import sys

import lldb

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import okgdb_common as common  # noqa: E402


def ok_symbols(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    regions = process.GetMemoryRegions()
    bases = {}
    info = lldb.SBMemoryRegionInfo()
    for i in range(regions.GetSize()):
        if not regions.GetMemoryRegionAtIndex(i, info):
            continue
        path = info.GetName()
        if not path or path in bases or not os.path.exists(path) or not common.is_image(path):
            continue
        # lldb does not report a region's offset in its file: the image's first
        # mapped part is matched against its segments by the bytes it holds.
        start = info.GetRegionBase()
        base = common.base_of(path, start, lambda at, n: process.ReadMemory(at, n, lldb.SBError()))
        if base is not None:
            bases[path] = base
    if not bases:
        result.AppendMessage("ok-symbols: no ok image is mapped (one the runner copied is announced through the JIT interface)")
        return
    for path, base in sorted(bases.items()):
        symbols = common.debug_file(path)
        debugger.HandleCommand("target modules add %s" % symbols)
        debugger.HandleCommand("target modules load --file %s --slide 0x%x" % (os.path.basename(symbols), base))
        result.AppendMessage("ok-symbols: %s at 0x%x" % (path, base))


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f oklldb.ok_symbols ok-symbols")
