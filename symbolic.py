

EXEC_BASE = 0x100000000

STACK_SHIFT = {
    'call': 1,
    'call_indirect': 1,
    'br_if': -1,

    'drop': -1,
    'select': -2,

    # Variable
    'local.get': 1,
    'local.set': -1,
    'local.tee': 0,
    'global.get': 1,
    'global.set': -1,

    # Memory
    # All loads are zero
    'i32.store': -2,
    'i64.store': -2,
    'f32.store': -2,
    'f64.store': -2,
    'i32.store8': -2,
    'i32.store16': -2,
    'i64.store8': -2,
    'i64.store16': -2,
    'i64.store32': -2,
    'memory.size': 1,
    'memory.grow': -1,

    # Numeric
    'i32.const': 1,
    'i64.const': 1,
    'f32.const': 1,
    'f64.const': 1,

    'i32.eqz': 0,
    'i32.eq': -1,
    'i32.ne': -1,
    'i32.lt_s': -1,
    'i32.lt_u': -1,
    'i32.gt_s': -1,
    'i32.gt_u': -1,
    'i32.le_s': -1,
    'i32.le_u': -1,
    'i32.ge_s': -1,
    'i32.ge_u': -1,

    'i64.eqz': -1,
    'i64.eq': -1,
    'i64.ne': -1,
    'i64.lt_s': -1,
    'i64.lt_u': -1,
    'i64.gt_s': -1,
    'i64.gt_u': -1,
    'i64.le_s': -1,
    'i64.le_u': -1,
    'i64.ge_s': -1,
    'i64.ge_u': -1,

    'f32.eq': -1,
    'f32.ne': -1,
    'f32.lt': -1,
    'f32.gt': -1,
    'f32.le': -1,
    'f32.ge': -1,

    'f64.eq': -1,
    'f64.ne': -1,
    'f64.lt': -1,
    'f64.gt': -1,
    'f64.le': -1,
    'f64.ge': -1,

    'i32.clz': 0,
    'i32.ctz': 0,
    'i32.popcnt': 0,
    'i32.add': -1,
    'i32.sub': -1,
    'i32.mul': -1,
    'i32.div_s': -1,
    'i32.div_u': -1,
    'i32.rem_s': -1,
    'i32.rem_u': -1,
    'i32.and': -1,
    'i32.or': -1,
    'i32.xor': -1,
    'i32.shl': -1,
    'i32.shr_s': -1,
    'i32.shr_u': -1,
    'i32.rotl': -1,
    'i32.rotr': -1,

    'i64.clz': 0,
    'i64.ctz': 0,
    'i64.popcnt': 0,
    'i64.add': -1,
    'i64.sub': -1,
    'i64.mul': -1,
    'i64.div_s': -1,
    'i64.div_u': -1,
    'i64.rem_s': -1,
    'i64.rem_u': -1,
    'i64.and': -1,
    'i64.or': -1,
    'i64.xor': -1,
    'i64.shl': -1,
    'i64.shr_s': -1,
    'i64.shr_u': -1,
    'i64.rotl': -1,
    'i64.rotr': -1,

    'f32.abs': 0,
    'f32.neg': 0,
    'f32.ceil': 0,
    'f32.floor': 0,
    'f32.trunc': 0,
    'f32.nearest': 0,
    'f32.sqrt': 0,
    'f32.add': -1,
    'f32.sub': -1,
    'f32.mul': -1,
    'f32.div': -1,
    'f32.min': -1,
    'f32.max': -1,
    'f32.copysign': -1,

    'f64.abs': 0,
    'f64.neg': 0,
    'f64.ceil': 0,
    'f64.floor': 0,
    'f64.trunc': 0,
    'f64.nearest': 0,
    'f64.sqrt': 0,
    'f64.add': -1,
    'f64.sub': -1,
    'f64.mul': -1,
    'f64.div': -1,
    'f64.min': -1,
    'f64.max': -1,
    'f64.copysign': -1,

    # Conversion ops are zero
}


class WasmInfo(object):

    STACK_OFFSET = {} # addr -> stack offset
    JUMP_TARGETS = {} # addr -> addr

    FUNC_START = {} # addr -> fidx
    FUNC_END = {} # addr -> fidx
    FUNC_ADDRESS = {} # fidx -> addr
    FUNC_TYPE = {} # fidx -> (#inputs, #outputs)

    wp = None

    @staticmethod
    def update(wp):
        '''Update information with a WASMParser object.'''
        WasmInfo.wp = wp
        WasmInfo.update_all()

    @staticmethod
    def update_all():
        # save function types

        # Index start for code section.
        f_code_base = len(WasmInfo.wp.import_section.imports) if WasmInfo.wp.import_section is not None else 0

        # Add import section references.
        if WasmInfo.wp.import_section is not None:
            for i in range(len(WasmInfo.wp.import_section.imports)):
                imp = WasmInfo.wp.import_section.imports[i]

                # TODO: other import_desc_type formats?
                if imp.import_desc_type == 0:
                    typ = WasmInfo.wp.type_section.function_types[imp.import_desc.value]
                    WasmInfo.FUNC_TYPE[i] = (len(typ.inputs), len(typ.outputs))

                # Imported address definition.
                WasmInfo.FUNC_ADDRESS[i] = EXEC_BASE + imp._file_index
                
        # Add type information for defined funcs.
        for i in range(len(WasmInfo.wp.function_section.type_indices)):
            typ = WasmInfo.wp.type_section.function_types[WasmInfo.wp.function_section.type_indices[i].value]
            WasmInfo.FUNC_TYPE[f_code_base + i] = (len(typ.inputs), len(typ.outputs))

        # Add code segment information.
        if WasmInfo.wp.code_section is not None:
            for i in range(len(WasmInfo.wp.code_section.code_entries)):
                code = WasmInfo.wp.code_section.code_entries[i]

                idx = code.code._file_index
                expr = code.code.expr

                WasmInfo.populate_jump_targets(expr, idx)
                WasmInfo.populate_stack(expr, idx)

                WasmInfo.FUNC_START[EXEC_BASE + idx] = f_code_base + i
                WasmInfo.FUNC_END[EXEC_BASE + idx + expr._size - 1] = f_code_base + i
                WasmInfo.FUNC_ADDRESS[f_code_base + i] = EXEC_BASE + idx

        for k in WasmInfo.JUMP_TARGETS:
            print(f'jump 0x{k:x} -> 0x{WasmInfo.JUMP_TARGETS[k]:x}')


    @staticmethod
    def populate_stack(expr, start, stack_offset=0):
        '''Trace expression and compute stack offsets.'''
        s = stack_offset
        i = start

        for op in expr.ops:
            WasmInfo.STACK_OFFSET[EXEC_BASE + i] = s

            if op.name == 'block':
                WasmInfo.populate_stack(op.args[1], i + op.args_idx[1], s)
            elif op.name == 'loop':
                WasmInfo.populate_stack(op.args[1], i + op.args_idx[1], s)
            elif op.name == 'if':
                WasmInfo.populate_stack(op.args[1], i + op.expr_true_offset, s - 1)
                s -= 1
            elif op.name == 'call':
                fidx = op.args[0].value
                print(op)
                print(fidx, op.args)
                if fidx in WasmInfo.FUNC_TYPE:
                    num_in, num_out = WasmInfo.FUNC_TYPE[fidx]
                    s -= num_in
                    s += num_out
            elif op.name in STACK_SHIFT:
                s += STACK_SHIFT[op.name]
            else:
                print(f'Warning: unknown stack shift for {op.name}')

            i += op._size

    @staticmethod
    def populate_jump_targets(expr, start, stack=[]):
        '''recursively find jump targets for an expression'''
        i = start
        for op in expr.ops:
            # print(hex(i + EXEC_BASE),' '*len(stack),op.name)

            if op.name == 'block':
                WasmInfo.populate_jump_targets(op.args[1], i + op.args_idx[1], stack + [i + op._size])
            elif op.name == 'loop':
                WasmInfo.populate_jump_targets(op.args[1], i + op.args_idx[1], stack + [i])

                # add end condition loopback
                WasmInfo.JUMP_TARGETS[EXEC_BASE + i + op._size - 1] = EXEC_BASE + i
            elif op.name == 'if':
                WasmInfo.populate_jump_targets(op.args[1], i + op.expr_true_offset, stack + [i + op._size])

                target = i + op._size
                WasmInfo.JUMP_TARGETS[EXEC_BASE + i] = target + EXEC_BASE
            elif op.name in ['br', 'br_if']:
                nest = op.args[0].value
                target = stack[-nest-1]

                # branch targets
                WasmInfo.JUMP_TARGETS[i + EXEC_BASE] = target + EXEC_BASE

            i += op._size


