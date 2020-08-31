from binaryninja import *


class X86RopHook(ArchitectureHook):

    LOADED = False

    def __init__(self, base_arch):
        super(X86RopHook, self).__init__(base_arch)

    def get_instruction_info(self, data, addr):
        # Call the original implementation's method by calling the superclass
        info = super(X86RopHook, self).get_instruction_info(data, addr)
        if info is None:
            return None

        # I think you have to do this to work around getters and setters
        branches = info.branches

        # Make sure our returns aren't actually returns otherwise the analysis might stop!
        for b in branches:
            if b.type == BranchType.FunctionReturn:
                b.type = BranchType.UnresolvedBranch

        info.branches = branches

        return info

    def get_instruction_low_level_il(self, data, addr, il: LowLevelILFunction):
        # Tried using the other arch functions and binja kept crashing in completely
        # unexpected ways, so this is the best I got
        is_ret = data[0] == 0xc3

        if is_ret:
            aas = il.arch.address_size
            reg = "esp" if aas == 4 else "rsp"

            # Apparently jmp(pop) does not actually mutate esp
            # I'm really not sure why but LLIL just doesn't want to do it
            # Instead I manually specified the mechanics of a pop here
            il.append(il.set_reg(aas, reg,
                                 il.add(aas,
                                        il.reg(aas, reg),
                                        il.const(aas, aas))))
            il.append(il.jump(il.load(aas,
                                      il.sub(aas,
                                             il.reg(aas, reg),
                                             il.const(aas, aas)))))
            return 1
        else:
            return super(X86RopHook, self).get_instruction_low_level_il(data, addr, il)

