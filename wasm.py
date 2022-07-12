from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType, LowLevelILOperation
from binaryninja.lowlevelil import LowLevelILLabel

from .parser import Instruction
from .parser import u32, u64, s32, s64, f32, f64, LocalIdx
from .symbolic import WasmInfo


# binary ninja text helpers
def tI(x): return InstructionTextToken(InstructionTextTokenType.InstructionToken, x)
def tR(x): return InstructionTextToken(InstructionTextTokenType.RegisterToken, x)
def tS(x): return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, x)
def tM(x): return InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, x)
def tE(x): return InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, x)
def tA(x,d): return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, x, d)
def tT(x): return InstructionTextToken(InstructionTextTokenType.TextToken, x)
def tN(x,d): return InstructionTextToken(InstructionTextTokenType.IntegerToken, x, d)



TEXT_HANDLERS = {
    'br': lambda x,addr: [tT('br'), tS(' '), (tA(hex(WasmInfo.JUMP_TARGETS[addr]), WasmInfo.JUMP_TARGETS[addr]) if addr in WasmInfo.JUMP_TARGETS else tS('?'))],
    'br_if': lambda x,addr: [tT('br_if'), tS(' '), (tA(hex(WasmInfo.JUMP_TARGETS[addr]), WasmInfo.JUMP_TARGETS[addr]) if addr in WasmInfo.JUMP_TARGETS else tS('?'))],
    'call': lambda x,addr: [tT('call'), tS(' '), (tA(hex(WasmInfo.FUNC_ADDRESS[x.args[0].value]), WasmInfo.FUNC_ADDRESS[x.args[0].value]) if x.args[0].value in WasmInfo.FUNC_ADDRESS else tS('?'))]
}

def text_for_instruction(x,addr):

    if x.name in TEXT_HANDLERS:
        # print([hex(x) for x in WasmInfo.JUMP_TARGETS], hex(addr))
        return TEXT_HANDLERS[x.name](x,addr)

    t = []
    t.append(tI(x.name))

    for i in range(len(x.args)):
        if i == 0:
            t.append(tS(' '))
        else:
            t.append(tS(', '))

        a = x.args[i]
        if type(a) in [u32, u64, s32, s64]:
            t.append(tA(repr(a.value), a.value))
        elif type(a) is LocalIdx:
            t.append(tR('$l%d' % a.value))

    return t

def il_branch(il, cond, tdest, fdest):

    t_target = LowLevelILLabel()
    f_target = LowLevelILLabel()
    
    il.append(il.if_expr(cond, t_target, f_target))

    il.mark_label(t_target)
    il.append(il.jump(tdest))

    il.mark_label(f_target)
    # il.append(il.jump(fdest))


def il_jump(il, dest, is_call=False):

    if is_call:
        il.append(il.call(dest))
    else:
        t = None
        if dest in il and il[dest].operation == LowLevelILOperation.LLIL_CONST:
            t = il.get_label_for_address(Architecture['wasm'], il[dest].constant)

        indirect = False
        if t is None:
            t = LowLevelILLabel()
            indirect = True

        il.append(il.goto(t))

        if indirect:
            il.mark_label(t)
            il.append(il.jump(dest))

        # # lookup label 
        # t = None
        # if dest in il and il[dest].operation == LowLevelILOperation.LLIL_CONST:
        #     t = il.get_label_for_address(Architecture['wasm'], il[dest].constant)

        # # if the label doesn't exist, create a new one
        # indirect = False
        # if t is None:
        #     t = LowLevelILLabel()
        #     indirect = True

        # # if it doesn't exist, create and jump
        # if indirect:
        #     il.mark_label(t)
        #     il.append(il.jump(dest))
        # else:
        #     # just goto label
        #     il.append(il.goto(t))

def if_block(x, il, addr, invert=False):
    print(f'if block at 0x{addr:x}')
    tdest = il.const(8, addr + x._size)
    fdest = il.const(8, WasmInfo.JUMP_TARGETS[addr])

    cond = il.reg(8, 's%d' % (WasmInfo.STACK_OFFSET[addr]-1))

    il_branch(il, il.not_expr(8, cond) if invert else cond, fdest, tdest)

def do_call(x, il, addr):
    fidx = x.args[0].value

    # transfer stack args
    num_in, num_out = WasmInfo.FUNC_TYPE[fidx]

    for i in range(num_in):
        stack_reg = WasmInfo.STACK_OFFSET[addr] - num_in + i
        arg_reg = i
        set_both(il, f'a{arg_reg}', get_32(il, f's{stack_reg}'), get_64(il, f's{stack_reg}'))

    # perform call
    # if fidx in WasmInfo.FUNC_ADDRESS:
    il.append(il.call(il.const(8, WasmInfo.FUNC_ADDRESS[x.args[0].value])))

    # transfer return args
    for i in range(num_out):
        stack_reg = WasmInfo.STACK_OFFSET[addr] - num_in + i
        arg_reg = i
        set_both(il, f's{stack_reg}', get_32(il, f'a{arg_reg}'), get_64(il, f'a{arg_reg}'))

def set_32(il, reg, val):
    il.append(il.set_reg(4, 'z_temp', val))
    il.append(il.set_reg(8, 'temp', il.zero_extend(8, val)))
    il.append(il.set_reg(4, f'z_{reg}', il.reg(4, 'z_temp')))
    il.append(il.set_reg(8, reg, il.reg(8, 'temp')))

def set_64(il, reg, val):
    il.append(il.set_reg(4, 'z_temp', il.low_part(4, val)))
    il.append(il.set_reg(8, 'temp', val))
    il.append(il.set_reg(4, f'z_{reg}', il.reg(4, 'z_temp')))
    il.append(il.set_reg(8, reg, il.reg(8, 'temp')))

def set_both(il, reg, v1, v2):
    il.append(il.set_reg(4, 'z_temp', v1))
    il.append(il.set_reg(8, 'temp', v2))
    il.append(il.set_reg(4, f'z_{reg}', il.reg(4, 'z_temp')))
    il.append(il.set_reg(8, reg, il.reg(8, 'temp')))

def get_32(il, reg):
    return il.reg(4, f'z_{reg}')

def get_64(il, reg):
    return il.reg(8, reg)

def op_void__i32(val, addr, il):
    set_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr]), val)

def op_void__i64(val, addr, il):
    set_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr]), val)

def op_void__multi(v1, v2, addr, il):
    set_both(il, 's%d' % (WasmInfo.STACK_OFFSET[addr]), v1, v2)

def op_i64__void(func, addr, il):
    func(get_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1)))

def op_multi__void(func, addr, il):
    func(
        get_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1)),
        get_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1)))

def op_i32_i32__void(func, addr, il):
    b = get_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1))
    a = get_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 2))
    il.append(func(a,b))

def op_i64_i32__void(func, addr, il):
    b = get_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1))
    a = get_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 2))
    il.append(func(a,b))

def op_i64_i64__void(func, addr, il):
    b = get_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1))
    a = get_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 2))
    il.append(func(a,b))

def op_i32__i32(func, addr, il):
    a = get_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1))
    v = func(a)
    set_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1), v)

def op_i32__i64(func, addr, il):
    a = get_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1))
    v = func(a)
    set_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1), v)

def op_i64__i32(func, addr, il):
    a = get_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1))
    v = func(a)
    set_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1), v)

def op_i64__i64(func, addr, il):
    a = get_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1))
    v = func(a)
    set_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1), v)

def op_i32_i32__i32(func, addr, il):
    b = get_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1))
    a = get_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 2))
    v = func(a,b)
    set_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 2), v)

def op_i64_i64__i64(func, addr, il):
    b = get_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 1))
    a = get_64(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 2))
    v = func(a,b)
    set_32(il, 's%d' % (WasmInfo.STACK_OFFSET[addr] - 2), v)



MAP_IL = {
    # Parametric
    # 'drop': lambda x,il: pop_sp(il)

    'return': lambda x,a,il: il.append(il.nop()),
    'block': lambda x,a,il: il.append(il.nop()),
    'loop': lambda x,a,il: il.append(il.nop()),

    # Variable
    'local.get': lambda x,a,il: op_void__multi(get_32(il, 'l%d' % x.args[0].value), get_64(il, 'l%d' % x.args[0].value), a, il),
    'local.set': lambda x,a,il: op_multi__void(lambda v1,v2: set_both(il, 'l%d' % x.args[0].value, v1, v2), a, il),
    'local.tee': lambda x,a,il: op_multi__void(lambda v1,v2: set_both(il, 'l%d' % x.args[0].value, v1, v2), a, il),
    'global.get': lambda x,a,il: op_void__multi(get_32(il, 'g%d' % x.args[0].value), get_64(il, 'g%d' % x.args[0].value), a, il),
    'global.set': lambda x,a,il: op_multi__void(lambda v1,v2: set_both(il, 'g%d' % x.args[0].value, v1, v2), a, il),

    # Memory
    # 'i32.load': lambda x,a,il: op_i64__i32(lambda v: il.load(4, il.add(8, v, il.const(8, x.args[1].value))), a, il),
    'i32.load': lambda x,a,il: op_i32__i32(lambda v: il.load(4, il.add(4, v, il.const(4, x.args[1].value))), a, il),
    'i64.load': lambda x,a,il: op_i32__i64(lambda v: il.load(8, il.add(4, v, il.const(4, x.args[1].value))), a, il),
    # 'f32.load': lambda x,a,il: 0,
    # 'f64.load': lambda x,a,il: 0,
    'i32.load8_s': lambda x,a,il: op_i32__i32(lambda v: il.sign_extend(4, il.load(1, il.add(4, v, il.const(4, x.args[1].value)))), a, il),
    'i32.load8_u': lambda x,a,il: op_i32__i32(lambda v: il.zero_extend(4, il.load(1, il.add(4, v, il.const(4, x.args[1].value)))), a, il),
    'i32.load16_s': lambda x,a,il: op_i32__i32(lambda v: il.sign_extend(4, il.load(2, il.add(4, v, il.const(4, x.args[1].value)))), a, il),
    'i32.load16_u': lambda x,a,il: op_i32__i32(lambda v: il.zero_extend(4, il.load(2, il.add(4, v, il.const(4, x.args[1].value)))), a, il),
    'i64.load8_s': lambda x,a,il: op_i32__i64(lambda v: il.sign_extend(8, il.load(1, il.add(4, v, il.const(4, x.args[1].value)))), a, il),
    'i64.load8_u': lambda x,a,il: op_i32__i64(lambda v: il.zero_extend(8, il.load(1, il.add(4, v, il.const(4, x.args[1].value)))), a, il),
    'i64.load16_s': lambda x,a,il: op_i32__i64(lambda v: il.sign_extend(8, il.load(2, il.add(4, v, il.const(4, x.args[1].value)))), a, il),
    'i64.load16_u': lambda x,a,il: op_i32__i64(lambda v: il.zero_extend(8, il.load(2, il.add(4, v, il.const(4, x.args[1].value)))), a, il),
    'i64.load32_s': lambda x,a,il: op_i32__i64(lambda v: il.sign_extend(8, il.load(4, il.add(4, v, il.const(4, x.args[1].value)))), a, il),
    'i64.load32_u': lambda x,a,il: op_i32__i64(lambda v: il.zero_extend(8, il.load(4, il.add(4, v, il.const(4, x.args[1].value)))), a, il),

    'i32.store': lambda x,a,il: op_i32_i32__void(lambda a,b: il.append(il.store(4, il.add(4, a, il.const(4, x.args[1].value)), b)), a, il),
    'i32.store8': lambda x,a,il: op_i32_i32__void(lambda a,b: il.append(il.store(1, il.add(8, a, il.const(4, x.args[1].value)), il.low_part(1, b))), a, il),
    # 'i32.store': lambda x,il: op2_void(lambda a,b: [il.store(4, il.add(4, a, il.const(4, x.args[1].value)), b)], il),

    # # Numeric
    'i32.const': lambda x,a,il: op_void__i32(il.const(4, x.args[0].value), a, il),
    'i64.const': lambda x,a,il: op_void__i64(il.const(8, x.args[0].value), a, il),

    'i32.eqz': lambda x,a,il: op_i64__i32(lambda a: il.compare_equal(4,a,il.const(4,0)), a, il),
    'i32.eq': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.compare_equal(4,a,b), a, il),
    'i32.ne': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.compare_not_equal(4,a,b), a, il),
    'i32.lt_s': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.compare_signed_less_than(4,a,b), a, il),
    'i32.lt_u': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.compare_unsigned_less_than(4,a,b), a, il),
    'i32.gt_s': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.compare_signed_greater_than(4,a,b), a, il),
    'i32.gt_u': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.compare_unsigned_greater_than(4,a,b), a, il),
    'i32.le_s': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.compare_signed_less_equal(4,a,b), a, il),
    'i32.le_u': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.compare_unsigned_less_equal(4,a,b), a, il),
    'i32.ge_s': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.compare_signed_greater_equal(4,a,b), a, il),
    'i32.ge_u': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.compare_unsigned_greater_equal(4,a,b), a, il),

    'i32.add': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.add(4,a,b), a, il),
    'i32.sub': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.sub(4,a,b), a, il),
    'i32.mul': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.mult(4,a,b), a, il),
    'i32.div_s': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.div_signed(4,a,b), a, il),
    'i32.div_u': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.div_unsigned(4,a,b), a, il),
    'i32.rem_s': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.mod_signed(4,a,b), a, il),
    'i32.rem_u': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.mod_unsigned(4,a,b), a, il),
    'i32.and': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.and_expr(4,a,b), a, il),
    'i32.or': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.or_expr(4,a,b), a, il),
    'i32.xor': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.xor_expr(4,a,b), a, il),
    'i32.shl': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.shift_left(4,a,b), a, il),
    'i32.shr_s': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.arith_shift_right(4,a,b), a, il),
    'i32.shr_u': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.logical_shift_right(4,a,b), a, il),
    'i32.rotl': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.rotate_left(4,a,b), a, il),
    'i32.rotr': lambda x,a,il: op_i32_i32__i32(lambda a,b: il.rotate_right(4,a,b), a, il),
    
}


def il_for_instruction(x, il, addr):
    if addr in WasmInfo.FUNC_START:
        fidx = WasmInfo.FUNC_START[addr]
        print('start',addr,fidx)

        # transfer arguments
        num_in, _ = WasmInfo.FUNC_TYPE[fidx]
        for i in range(num_in):
            set_both(il, f'l{i}', get_32(il, f'a{i}'), get_64(il, f'a{i}'))

        il.append(il.set_reg(4, 'z_g0', il.reg(4, 'sp')))

    if x.name == 'end':
        if addr in WasmInfo.JUMP_TARGETS:
            # loop back
            il_jump(il, il.const(8, WasmInfo.JUMP_TARGETS[addr]))
        elif addr in WasmInfo.FUNC_END:
            # transfer args
            fidx = WasmInfo.FUNC_END[addr]
            print('end',addr,fidx)

            # transfer arguments
            _, num_out = WasmInfo.FUNC_TYPE[fidx]
            for i in range(num_out):
                set_both(il, f'a{i}', get_32(il, f's{i}'), get_64(il, f's{i}'))
                
            # return
            il.append(il.ret(il.reg(4, 'sp')))

        return

    if not addr in WasmInfo.STACK_OFFSET:
        return

    if x.name == 'if':
        if_block(x, il, addr, invert=True)
    elif x.name == 'br':
        il_jump(il, il.const(8, WasmInfo.JUMP_TARGETS[addr]))
    elif x.name == 'br_if':
        if_block(x, il, addr, invert=False)
    elif x.name == 'call':
        do_call(x, il, addr)
    elif x.name in MAP_IL:
        MAP_IL[x.name](x, addr, il)
    else:
        print(f'Warning: no il for {x.name}')


REGS = []
REGS += ['l%d' % i for i in range(1000)]
REGS += ['s%d' % i for i in range(1000)]
REGS += ['g%d' % i for i in range(100)]
REGS += ['a%d' % i for i in range(100)] # argument transfer

ALL_REGS = { r: RegisterInfo(r, 8) for r in REGS }
for k in REGS:
    ALL_REGS[f'z_{k}'] = RegisterInfo(f'z_{k}', 4)

ALL_REGS['sp'] = RegisterInfo('sp', 4)

ALL_REGS['temp'] = RegisterInfo('temp', 8)
ALL_REGS['z_temp'] = RegisterInfo('z_temp', 4)

class WASM(Architecture):
    name = 'wasm'
    address_size = 4
    max_instr_length = 20

    regs = ALL_REGS
    stack_pointer = 'sp'

    def __init__(self):
        super(WASM, self).__init__()

    def get_instruction_info(self, data, addr):
        x = None
        try:
            x = Instruction(bytearray(data), 0, include_nested=False)
        except:
            info = InstructionInfo()
            info.length = 1
            return info

        info = InstructionInfo()
        info.length = x._size

        if x.name == 'br':
            if addr in WasmInfo.JUMP_TARGETS:
                info.add_branch(BranchType.UnconditionalBranch, WasmInfo.JUMP_TARGETS[addr])
            else:
                print(f'Warning: missing jump target for 0x{addr:x}')
        elif x.name == 'br_if':
            if addr in WasmInfo.JUMP_TARGETS:
                info.add_branch(BranchType.TrueBranch, WasmInfo.JUMP_TARGETS[addr]) 
                info.add_branch(BranchType.FalseBranch, addr + x._size)
            else:
                print(f'Warning: missing jump target for 0x{addr:x}')
        # elif x.name == 'if':
        #     info.add_branch(BranchType.FalseBranch, WasmInfo.JUMP_TARGETS[addr]) 
        #     info.add_branch(BranchType.TrueBranch, addr + x._size)
        elif x.name == 'end':
            if addr in WasmInfo.JUMP_TARGETS:
                # loop back
                info.add_branch(BranchType.UnconditionalBranch, WasmInfo.JUMP_TARGETS[addr])
            elif addr in WasmInfo.FUNC_END:
                # return
                info.add_branch(BranchType.FunctionReturn)

        return info
            
    def get_instruction_text(self, data, addr):
        try:
            x = Instruction(bytearray(data), 0, include_nested=False)
            return text_for_instruction(x,addr), x._size
        except:
            return [tT('?')],1

    def get_instruction_low_level_il(self, data, addr, il):
        x = None
        try:
            x = Instruction(bytearray(data), 0, include_nested=False)
        except:
            return 1

        il_for_instruction(x, il, addr)
        return x._size

