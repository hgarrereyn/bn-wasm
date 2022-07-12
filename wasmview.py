from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag, SymbolType
from binaryninja.types import Symbol, Type, FunctionParameter

from .parser import WASMParser
from .symbolic import EXEC_BASE, WasmInfo


class WASMView(BinaryView):
    name = 'WASM'
    long_name = 'Web Assembly'

    @classmethod
    def is_valid_for_data(self, data):
        header = data.read(0,0x8)
        return header[:4] == b'\x00asm' and header[4:8] == b'\x01\x00\x00\x00'

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['wasm'].standalone_platform
        self.data = data

    def _fix_function(self, addr, num_in, num_out):
        '''fix function signature'''
        print('fix',addr)
        funcs = self.get_functions_at(addr)
        if len(funcs) == 0:
            print('none')
            return
        func = funcs[0]
        print(func)

        arch = Architecture['wasm']
        args = [FunctionParameter(Type.int(4)) for _ in range(num_in)]
        ty = Type.function(Type.int(4), args, calling_convention=arch.calling_conventions['default'])
        
        func.function_type = ty
        print(func)

        # func.clobbered_regs = (
        #     ['a%d' % i for i in range(num_in)] + ['z_a%d' % i for i in range(num_in)]
        # )
        func.clobbered_regs = []
        func.return_regs = ['a%d' % i for i in range(num_out)]

    def init(self):
        # initialize parser
        wasm_bytes = bytearray(self.data[:])
        wp = WASMParser(wasm_bytes)
        self.wp = wp

        # update global information
        WasmInfo.update(wp)

        # add sections to view
        export_ref = wp.export_section

        export_func = {ex.export_desc.value: ex.name for ex in export_ref.exports if ex.export_desc_type == 0}
        export_table = {ex.export_desc.value: ex.name for ex in export_ref.exports if ex.export_desc_type == 1}
        export_mem = {ex.export_desc.value: ex.name for ex in export_ref.exports if ex.export_desc_type == 2}
        export_global = {ex.export_desc.value: ex.name for ex in export_ref.exports if ex.export_desc_type == 3}

        # add data sections
        if wp.data_section is not None:
            for data in wp.data_section.data_entries:
                # fetch constant value
                data_offset = data.expr.ops[0].args[0].value
                self.add_auto_segment(data_offset, data._file_len, data._file_index, data._file_len, SegmentFlag.SegmentReadable)

        # add functions as executable sections
        f_idx = 0

        if wp.import_section is not None:
            for imp in wp.import_section.imports:
                print(repr(imp))

                imp_name = '%s.%s' % (imp.module, imp.name)

                addr = EXEC_BASE + imp._file_index

                self.define_auto_symbol(
                    Symbol(SymbolType.ImportedFunctionSymbol, addr, imp_name))
                self.add_function(addr)
                if f_idx in WasmInfo.FUNC_TYPE:
                    self._fix_function(addr, *WasmInfo.FUNC_TYPE[f_idx])

                f_idx += 1

        self.add_auto_segment(
            EXEC_BASE,
            len(wasm_bytes),
            0, 
            len(wasm_bytes), 
            SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

        if wp.function_section is not None:
            for i in range(len(wp.function_section.type_indices)):
                typ = wp.type_section.function_types[wp.function_section.type_indices[i].value]
                code = wp.code_section.code_entries[i]

                # f_id = '$f%d' % f_idx
                # if f_idx in export_func:
                #     f_id = '$%s (export "%s")' % (export_func[f_idx], export_func[f_idx])

                # w_param = ' '.join(['(param $p%d %s)' % (i, repr(typ.inputs[i])) for i in range(len(typ.inputs))])
                # w_result = ' '.join(['(result %s)' % (repr(typ.outputs[i])) for i in range(len(typ.outputs))])

                # arr_typ = []
                # if len(typ.inputs) > 0:
                #     arr_typ.append(w_param)
                # if len(typ.outputs) > 0:
                #     arr_typ.append(w_result)

                # w_typ = ' '.join(arr_typ)

                # w_locals = ' '.join(['(local $l%d %s)' % (i, repr(code.code.func_locals[i])) for i in range(len(code.code.func_locals))])

                # print(f_id)
                # print(code.code._file_index, code.code._file_len)

                func_name = 'f%d' % f_idx
                if f_idx in export_func:
                    func_name = export_func[f_idx]

                # self.add_auto_segment(
                #     EXEC_BASE + code.code._file_index, 
                #     code.code._file_len, 
                #     code.code._file_index, 
                #     code.code._file_len, 
                #     SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

                self.add_function(EXEC_BASE + code.code._file_index)
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, EXEC_BASE + code.code._file_index, func_name))
                self._fix_function(EXEC_BASE + code.code._file_index, *WasmInfo.FUNC_TYPE[f_idx])

                f_idx += 1

        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0
