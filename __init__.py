from binaryninja import *
from .ui import init_ui
from .arch_hook import X86RopHook
from .model import ROPChain
from . import widget


def create_rop_cave(bv: BinaryView):
    # We hook here and not before, because binja keeps crashing and I couldn't even open files anymore
    if not X86RopHook.LOADED:
        X86RopHook.LOADED = True
        X86RopHook(Architecture['x86']).register()
        X86RopHook(Architecture['x86_64']).register()

    # Start our rop segment on the next free page
    max_addr = 0
    for segment in bv.segments:
        max_addr = max(max_addr, segment.end + 1)
    # Skip one and align to 0x1000
    max_addr += 0x1fff
    max_addr &= ~0xfff

    segment_start = max_addr
    segment_length = 0x1000

    bv.begin_undo_actions()

    # Our fake rop page needs to be mapped to the file for ... reasons
    # If we try to use an existing part of the file we will overwrite it when we edit stuff
    # So instead, create new bytes at the end of the file and use that
    file_start = bv.file.raw.end
    bv.file.raw.insert(file_start, b'\x00' * segment_length)
    # Segment + Section
    bv.add_user_segment(segment_start, segment_length,
                        file_start, segment_length,
                        SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable)
    bv.add_user_section("rop cave", segment_start, segment_length, SectionSemantics.ReadOnlyCodeSectionSemantics)

    chain = ROPChain(bv, bv.get_segment_at(segment_start), 50, bv.arch)
    chain.update_segment()
    rop_widget = widget.get_dockwidget(bv, "ROPChain")
    rop_widget.setState(chain)

    print(f"Code cave at {hex(segment_start)}")

    # Create our rop function at the start of the segment so we get that juicy analysis data
    bv.create_user_function(segment_start)
    bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, segment_start, "rop", "rop"))
    bv.get_function_at(segment_start).reanalyze()

    bv.commit_undo_actions()

    # And open it!
    bv.navigate(f"Graph:{bv.view_type}", segment_start)


init_ui()
PluginCommand.register("ROP\\Create ROP Function", "Make some space for your ROP", create_rop_cave)
