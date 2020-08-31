from binaryninja import *


class ROPChain(BinaryDataNotification):

    def __init__(self, bv: BinaryView, segment: Segment, length: int, arch: Architecture):
        BinaryDataNotification.__init__(self)
        self.bv = bv
        self.segment = segment
        self.chain = [0x0] * length
        self.arch = arch
        self.listeners = []
        self.bv.register_notification(self)

    def __getitem__(self, item):
        return self.chain[item]

    def __setitem__(self, key, value):
        self.chain[key] = value

        for listener in self.listeners:
            listener(key, value)

    def data_written(self, view: BinaryView, offset, length):
        view.add_analysis_completion_event(lambda: self.read_segment())

    def add_listener(self, listener):
        self.listeners.append(listener)

    def address_at_index(self, index):
        return self.segment.start + 5 * index

    def update_segment(self):
        self.bv.write(self.segment.start, self.get_assembly())

    def read_segment(self):
        func: Function = self.bv.get_function_at(self.segment.start)
        if func is None:
            return

        gadgets = []
        il = func.low_level_il
        for inst in il.instructions:
            if inst.operation != LowLevelILOperation.LLIL_PUSH:
                break
            op = inst.operands[0]
            if op.operation == LowLevelILOperation.LLIL_CONST:
                gadgets.append(op.value.value)
            elif op.operation == LowLevelILOperation.LLIL_ZX:
                gadgets.append(op.value.value)
            else:
                break

        self.chain = gadgets

        for listener in self.listeners:
            listener(None, None)

    def get_assembly(self):
        asm = b""

        for gadget in self.chain:
            asm += self.arch.assemble(f"push 0x{gadget:0x}", 0).ljust(5, b'\x90')

        asm += self.arch.assemble(f"ret", 0) * len(self.chain)

        return asm


def format_addr(bv: BinaryView, addr):
    disasm = disasm_at_addr(bv, addr)
    if len(disasm) > 0:
        return disasm

    return f"{addr:x}".rjust(bv.arch.address_size * 2, '0')

def disasm_at_addr(bv: BinaryView, addr):
    if bv.start >= addr or addr > bv.end:
        return ""

    if not bv.get_segment_at(addr).executable:
        return ""

    stop_on = ['retn', 'int', 'syscall']

    ops = []
    done = False
    while not done and len(ops) < 3:
        data = bv.read(addr, bv.arch.max_instr_length)
        text = bv.arch.get_instruction_text(data, addr)
        info = bv.arch.get_instruction_info(data, addr)

        if text is None:
            return ""
        tokens, length = text
        if tokens is None:
            return ""

        if len(info.branches) > 0 and not tokens[0].text == "retn":
            done = True
        for search in stop_on:
            if tokens[0].text == search:
                done = True

        line = ''.join(token.text for token in tokens)

        ops.append(line)
        addr += length

    return re.sub(r'\s+', ' ', " ; ".join(ops))
