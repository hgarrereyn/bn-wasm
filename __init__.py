import binaryninja
from binaryninja import CallingConvention

from .symbolic import WasmInfo

class DefaultCallingConvention(CallingConvention):
    name = "Default"
    int_arg_regs = ['z_a%d' % i for i in range(100)]
    int_return_reg = 'z_a0'
    # caller_saved_regs= ['l%d' % i for i in range(1000)] + ['s%d' % i for i in range(1000)]
    # high_int_return_reg = ''

from .wasm import WASM
WASM.register()

from .wasmview import WASMView
WASMView.register()

arch = binaryninja.architecture.Architecture['wasm']
arch.register_calling_convention(DefaultCallingConvention(arch, 'default'))

arch.WasmInfo = WasmInfo
