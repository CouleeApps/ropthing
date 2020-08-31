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
