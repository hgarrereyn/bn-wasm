from struct import unpack, pack

##########################
# Base Class Definitions #
##########################

class BaseObject(object):
    '''
    Represents some parser element defined on the bytearray.

    Initialize with a reference to the bytearray and a start index.

    `self.size` references the private `self._size` and should contain the
    encoded size of this object in bytes.
    '''

    def __init__(self, dat, start):
        self.dat = dat
        self.start = start

    @property
    def size(self):
        if hasattr(self, '_size'):
            return self._size
        else:
            raise NotImplementedError()

###################
# Utility methods #
###################

# [5.2.2]
def decode_LEB128(dat, start):
    '''
    Decodes a variable length integer according to the LEB128 format

    Returns (value, end)
    '''
    val = 0

    i = start
    while dat[i] & 0x80:
        val += (dat[i] & 0x7f) << ((i - start) * 7)
        i += 1
    val += (dat[i] & 0x7f) << ((i - start) * 7)
    i += 1

    return (val, i)

# [5.2.2]
def decode_signed_LEB128(dat, start, bitwidth):
    '''
    Decodes a signed variable length integer according to 
    the LEB128 format

    Returns (value, end)
    '''
    val = 0
    i = start
    shift = 0

    while True:
        val |= (dat[i] & 0x7F) << (shift)
        if (dat[i] & 0x80 == 0):
            break
        shift += 7
        i += 1

    if ((shift) < bitwidth and (val >> (shift)) & 0x40):
        val |= (~0 << (shift+7))
    return (val, i+1)

# [5.2.2]
class u32(BaseObject):
    '''Represents an instance of an unsigned 32 bit integer in LEB128 format'''
    def __init__(self, dat, start):
        (val, i) = decode_LEB128(dat, start)
        self.value = val
        self._size = i - start

        assert self._size <= 5

    def __repr__(self):
        return '%d' % self.value

# [5.2.2]
class u64(BaseObject):
    '''Represents an instance of an unsigned 64 bit integer in LEB128 format'''
    def __init__(self, dat, start):
        (val, i) = decode_LEB128(dat, start)
        self.value = val
        self._size = i - start

        assert self._size <= 10

    def __repr__(self):
        return '%d' % self.value

# [5.2.2]
class s32(BaseObject):
    '''Represents an instance of a signed 32 bit integer in LEB128 format'''
    def __init__(self, dat, start):
        (val, i) = decode_signed_LEB128(dat, start, 32)
        self.value = val
        self._size = i - start
        assert self._size <= 5
        
    def __repr__(self):
        return '%d' % self.value

# [5.2.2]
class s64(BaseObject):
    '''Represents an instance of a signed 64 bit integer in LEB128 format'''
    def __init__(self, dat, start):
        (val, i) = decode_signed_LEB128(dat, start, 64)
        self.value = val
        self._size = i - start
        assert self._size <= 10
        
    def __repr__(self):
        return '%d' % self.value

# [5.2.3]
class f32(BaseObject):
    '''Represents an instance of a 32 bit floating point number'''
    def __init__(self, dat, start):
        dat_str = pack("BBBB", dat[start+3], dat[start+2], 
                       dat[start+1], dat[start])
        self.value = unpack("f", dat_str)[0]
        self._size = 4

    def __repr__(self):
        return '%f' % self.value

# [5.2.3]
class f64(BaseObject): 
    '''Represents an instance of a 64 bit floating point number'''
    def __init__(self, dat, start):
        dat_str = pack("BBBBBBBB", dat[start+7], 
                       dat[start+6], dat[start+5], 
                       dat[start+4], dat[start+3], 
                       dat[start+2], dat[start+1], 
                       dat[start])
        self.value = unpack("d", dat_str)[0]
        self._size = 8

    def __repr__(self):
        return '%f' % self.value

# [5.1.3]
def vec(dat, start, vec_type):
    '''
    Iterate over a Vec object of a given type.

    Returns ([a,b,c, ...], end)
    '''
    i = start

    (vec_length, i) = decode_LEB128(dat, i)

    result = []

    for vi in range(vec_length):
        elem = vec_type(dat, i)
        result.append(elem)

        i += elem.size

    return (result, i)

# [5.2.4]
def name(dat, start, decode=True):
    '''
    A name is encoded as a vector of bytes

    Returns (name, end)
    '''
    i = start

    (vec_length, i) = decode_LEB128(dat, i)

    assert i + vec_length <= len(dat), "Name out of bounds"

    name = dat[i:i+vec_length]
    if decode:
        name = name.decode('utf-8')

    i += vec_length

    return (name, i)

def name_file_backing(dat, start, decode=True):
    '''
    A name is encoded as a vector of bytes.

    This version returns the index and length of the file-backed
    name byte vector.

    Returns (file_idx, len)
    '''
    i = start

    (vec_length, i) = decode_LEB128(dat, i)

    assert i + vec_length <= len(dat), "Name out of bounds"

    return (i, vec_length)

# [5.3.1]
class ValType(BaseObject):
    '''
    Value types are encoded with a single byte to represent one of the four (current) wasm types
    '''
    @property
    def size(self):
        return 1

    def __repr__(self):
        return self.__class__.__name__

class i32_t(ValType):
    def __repr__(self): 
        return 'i32'

class i64_t(ValType):
    def __repr__(self): 
        return 'i64'

class f32_t(ValType):
    def __repr__(self): 
        return 'f32'

class f64_t(ValType):
    def __repr__(self): 
        return 'f64'

# defined as a result type
# see [5.3.2]
class EmptyValType(ValType): pass

# [5.3.2]
class ResultType(ValType): pass

VALUE_TYPES = {
    0x7F: i32_t,
    0x7E: i64_t,
    0x7D: f32_t,
    0x7C: f64_t,
    0x40: EmptyValType
}

def parse_value_type(dat, i):
    '''Utility method to parse a single-byte value type'''
    vtype = dat[i]
    assert vtype in VALUE_TYPES, "Unknown value type: %d" % vtype
    return VALUE_TYPES[vtype](dat, i)

# [5.5.1]
class Index(BaseObject):
    def __init__(self, dat, start):
        (v, i) = decode_LEB128(dat, start)
        self.value = v
        self._size = i - start

    def __repr__(self):
        return '%s(%d)' % (self.__class__.__name__, self.value)

class TypeIdx(Index): pass
class FuncIdx(Index): pass
class TableIdx(Index): pass
class MemIdx(Index): pass
class GlobalIdx(Index): pass
class LocalIdx(Index): pass
class LabelIdx(Index): pass

# [5.3.3]
class FuncType(BaseObject):
    '''Defines a function signature'''

    def __init__(self, dat, start):
        assert dat[start] == 0x60, "Expected function type to start with 0x60"

        i = start + 1

        (inp, i) = vec(dat, i, parse_value_type)
        (out, i) = vec(dat, i, parse_value_type)

        self.inputs = inp
        self.outputs = out

        self._size = i - start

    def __repr__(self):
        param = '(param %s)' % ' '.join(map(repr, self.inputs))
        result = '(result %s)' % ' '.join(map(repr, self.outputs))

        if len(self.inputs) > 0 and len(self.outputs) > 0:
            return '(func %s %s)' % (param, result)
        elif len(self.inputs) > 0:
            return '(func %s)' % (param)
        elif len(self.outputs) > 0:
            return '(func %s)' % (result)
        else:
            return '(func)'

# [5.3.4]
class Limits(BaseObject):
    '''Limits contain a minimum and (optional) maximum value'''

    def __init__(self, dat, start):
        i = start

        assert dat[i] == 0x0 or dat[i] == 0x1, "Invalid limit flag"
        has_max = (dat[i] == 1)
        i += 1

        (l_min, i) = decode_LEB128(dat, i)
        
        l_max = None
        if has_max:
            (l_max, i) = decode_LEB128(dat, i)

        self.min = l_min
        self.max = l_max

        self._size = i - start

    def __repr__(self):
        if self.max is None:
            return '%d' % (self.min)
        else:
            return '%d %d' % (self.min, self.max)

# [5.3.5]
class MemType(Limits):
    '''Memory Types simply contain a limit'''
    pass

# [5.3.6]
class TableType(BaseObject):
    '''Table types contain a limit and an element type'''

    def __init__(self, dat, start):
        i = start

        assert dat[i] == 0x70, "Unknown element type: %d" % dat[i]
        i += 1

        self.limits = Limits(dat, i)
        i += self.limits.size

        self._size = i - start

    def __repr__(self):
        return '%s anyfunc' % (repr(self.limits))

# [5.3.7]
class GlobalType(BaseObject):
    '''Global types contain a value type and a mutability flag'''

    def __init__(self, dat, start):
        i = start

        vtype = parse_value_type(dat, i)
        i += 1

        mut = dat[i]
        i += 1

        assert mut == 0 or mut == 1, "Invalid mutability flag: %d" % mut

        self.valtype = vtype
        self.is_mutable = (mut == 1)

        self._size = 2

    def __repr__(self):
        if self.is_mutable:
            return '(mut %s)' % repr(self.valtype)
        else:
            return '%s' % repr(self.valtype)

# [5.5.9]
class Global(BaseObject):
    '''A Global consists of a global type and a constant initialization expression'''

    def __init__(self, dat, start):
        i = start

        self.type = GlobalType(dat, i)
        i += self.type.size

        self.init = Expression(dat, i)
        i += self.init.size

        self._size = i - start

    def __repr__(self):
        return '%s (%s)' % (repr(self.type), ''.join(map(repr, self.init.ops)))

# [5.5.5]
IMPORT_DESC_LOOKUP = {
    0: TypeIdx,
    1: TableType,
    2: MemType,
    3: GlobalType
}

# [5.5.5]
class Import(BaseObject):
    '''An Import contains a `module` and `name` string and an import description type'''
    
    def __init__(self, dat, start):
        i = start

        (mod, i) = name(dat, i)
        (nm, i) = name(dat, i)

        self._file_index = i

        import_desc_type = dat[i]
        assert import_desc_type in IMPORT_DESC_LOOKUP, "Unknown import description type: %d" % import_desc_type
        i += 1

        import_desc = IMPORT_DESC_LOOKUP[import_desc_type](dat, i)
        i += import_desc.size

        self.module = mod
        self.name = nm

        self.import_desc_type = import_desc_type
        self.import_desc = import_desc

        self._size = i - start

    def __repr__(self):
        w_import_desc = ''
        if self.import_desc_type == 0:
            w_import_desc = '(func $%s.%s (type $t%d))' % (self.module, self.name, self.import_desc.value)

        return '(import "%s" "%s" %s)' % (self.module, self.name, w_import_desc)

# [5.5.10]
EXPORT_DESC_LOOKUP = {
    0: FuncIdx,
    1: TableIdx,
    2: MemIdx,
    3: GlobalIdx
}

# [5.5.10]
class Export(BaseObject):
    '''An Export contains a name and export description type'''
    
    def __init__(self, dat, start):
        i = start

        (nm, i) = name(dat, i)

        export_desc_type = dat[i]
        assert export_desc_type in EXPORT_DESC_LOOKUP, "Unknown export description type: %d" % export_desc_type
        i += 1

        export_desc = EXPORT_DESC_LOOKUP[export_desc_type](dat, i)
        i += export_desc.size

        self.name = nm

        self.export_desc_type = export_desc_type
        self.export_desc = export_desc

        self._size = i - start

    def __repr__(self):
        return '(export %s)' % (self.name)

# [5.5.14]
class Data(BaseObject):
    '''
    A Data object contains a memory index (currently must be zero), a constant expression initializer
    to determine the memory offset and a bytevector with data.
    '''

    def __init__(self, dat, start):
        i = start

        self.mem_idx = MemIdx(dat, i)
        i += self.mem_idx.size

        self.expr = Expression(dat, i)
        i += self.expr.size

        data_start = i
        (init, i) = name(dat, i, decode=False)
        (fidx, l) = name_file_backing(dat, data_start, decode=False)

        self._file_index = fidx
        self._file_len = l
        
        self.init = init
        self._size = i - start

    def __repr__(self):
        # slightly hacky conversion
        datastring = repr(self.init)[2:-1].replace('\\x','\\')
        return '(data %d (offset (%s)) "%s")' % (self.mem_idx.value, ''.join(map(repr, self.expr.ops)), datastring)

# [5.5.13]
class Locals(BaseObject):
    '''
    A Local is represented in compressed format by a count (num) and a valtype (valtype), this is decoded as
    `num` locals all with value type `valtype`
    '''

    def __init__(self, dat, start):
        i = start

        self.num = u32(dat, i)
        i += self.num.size

        vtype = parse_value_type(dat, i)
        i += 1

        self.valtype = vtype
        self._size = i - start

# [5.5.13]
class Func(BaseObject):
    '''
    A Func represents the function code for a function. It consists of a list of compressed
    locals followed by the function expression.
    '''

    def __init__(self, dat, start):
        i = start

        (compressed_locals, i)  = vec(dat, i, Locals)
        func_locals = []

        for j in compressed_locals:
            func_locals += ([j.valtype] * j.num.value)
        
        # expression file backing
        self._file_index = i

        self.expr = Expression(dat, i)
        i += self.expr.size

        self._file_len = self.expr.size

        self.func_locals = func_locals
        self._size = i - start

# [5.5.13]
class Code(BaseObject):
    '''A Code object consists of a size, followed by an encoded Func object'''

    def __init__(self, dat, start):
        i = start

        self.code_size = u32(dat, start)
        i += self.code_size.size

        self.code = Func(dat, i)
        i += self.code.size

        self._size = i - start

################
# Instructions #
################

# [5.4]
class Instruction(BaseObject):
    '''Instruction wrapper class to parse instructions.'''

    def __init__(self, dat, start, include_nested=True):
        i = start

        opcode = dat[i]
        assert opcode in OPCODE_MAP, "Unrecognized opcode: 0x%X (at %d)" % (opcode, i)
        i += 1

        name, arg_types = OPCODE_MAP[opcode]
        args = []
        args_idx = []

        for typ in arg_types:
            if type(typ) == int:
                # validate byte
                assert dat[i] == typ, "Invalid sequence for %s" % name
                i += 1
            else:
                if typ is Expression and not include_nested:
                    break
                
                # create instance
                arg_i = typ(dat, i)
                args.append(arg_i)
                args_idx.append(i - start)
                i += arg_i.size

        self.name = name
        self.opcode = opcode
        self.args = args
        self.args_idx = args_idx

        self._size = i - start

    def __repr__(self):
        if len(self.args) > 0:
            return '%s %s' % (self.name, ', '.join(map(repr, self.args)))
        else:
            return '%s' % self.name

# [5.4.1] # 0x4
class IfElseInstruction(Instruction):
    '''Special case handler for the if/else instruction'''

    def __init__(self, dat, start):
        i = start

        self.opcode = 0x4
        self.name = 'if'
        i += 1

        self.blocktype = ResultType(dat, i)
        i += self.blocktype.size

        expr_true = Expression(dat, i)
        self.expr_true_offset = i - start
        i += expr_true.size

        expr_false = None

        if dat[i-1] == 0x5:
            self.name = 'ifelse'

            expr_false = Expression(dat, i)
            i += expr_false.size

        self.args = [self.blocktype, expr_true, expr_false]
        self._size = i - start

# [5.4.1] # 0xE
class BrTableInstruction(Instruction):
    '''Special case handler for the br_table instruction'''

    def __init__(self, dat, start):
        i = start

        self.opcode = 0xE
        self.name = 'br_table'
        i += 1

        (labels, i) = vec(dat, i, LabelIdx)
        
        self.label = LabelIdx(dat, i)
        i += self.label.size

        self.labels = labels
        self.args = [self.labels, self.label]

        self._size = i - start

# [5.4.6]
class Expression(BaseObject):
    '''An Expression contains a sequence of Instructions followed by the end opcode (0xB)'''

    def __init__(self, dat, start):
        i = start

        ops = []
        while i < len(dat):
            if dat[i] == 0xB or dat[i] == 0x5:
                break

            if dat[i] in OPCODE_CUSTOM:
                op = OPCODE_CUSTOM[dat[i]](dat, i)
            else:
                op = Instruction(dat, i)

            ops.append(op)
            i += op.size

        # count the trailing `end` or `else` opcode
        i += 1

        self.ops = ops
        self._size = i - start
    
# Custom handlers for more involved opcodes
OPCODE_CUSTOM = {
    0x4: IfElseInstruction,
    0xE: BrTableInstruction
}

# opcode: (name, arg_types)
OPCODE_MAP = {
    # Control Instructions (5.4.1)
    0x0: ('unreachable', []),
    0x1: ('nop', []),
    0x2: ('block', [ResultType, Expression]),
    0x3: ('loop', [ResultType, Expression]),
    0x4: ('if', [ResultType, Expression]),
    #...
    # 0x5: ('else', []),
    0xB: ('end', []),
    0xC: ('br', [LabelIdx]),
    0xD: ('br_if', [LabelIdx]),
    0xF: ('return', []),
    0x10: ('call', [FuncIdx]),
    0x11: ('call_indirect', [TypeIdx, 0x00]),

    # Parametric Instructions (5.4.2)
    0x1A: ('drop', []),
    0x1B: ('select', []),

    # Variable Instructions (5.4.3)
    0x20: ('local.get', [LocalIdx]),
    0x21: ('local.set', [LocalIdx]),
    0x22: ('local.tee', [LocalIdx]),
    0x23: ('global.get', [GlobalIdx]),
    0x24: ('global.set', [GlobalIdx]),

    # Memory Instructions (5.4.4)
    0x28: ('i32.load', [u32, u32]),
    0x29: ('i64.load', [u32, u32]),
    0x2A: ('f32.load', [u32, u32]),
    0x2B: ('f64.load', [u32, u32]),
    0x2C: ('i32.load8_s', [u32, u32]),
    0x2D: ('i32.load8_u', [u32, u32]),
    0x2E: ('i32.load16_s', [u32, u32]),
    0x2F: ('i32.load16_u', [u32, u32]),
    0x30: ('i64.load8_s', [u32, u32]),
    0x31: ('i64.load8_u', [u32, u32]),
    0x32: ('i64.load16_s', [u32, u32]),
    0x33: ('i64.load16_u', [u32, u32]),
    0x34: ('i64.load32_s', [u32, u32]),
    0x35: ('i64.load32_u', [u32, u32]),
    0x36: ('i32.store', [u32, u32]),
    0x37: ('i64.store', [u32, u32]),
    0x38: ('f32.store', [u32, u32]),
    0x39: ('f64.store', [u32, u32]),
    0x3A: ('i32.store8', [u32, u32]),
    0x3B: ('i32.store16', [u32, u32]),
    0x3C: ('i64.store8', [u32, u32]),
    0x3D: ('i64.store16', [u32, u32]),
    0x3E: ('i64.store32', [u32, u32]),
    0x3F: ('memory.size', [0x0]),
    0x40: ('memory.grow', [0x0]),

    # Numeric Instructions (5.4.5)
    0x41: ('i32.const', [u32]),
    0x42: ('i64.const', [u64]),
    0x43: ('f32.const', [f32]),
    0x44: ('f64.const', [f64]),
    0x45: ('i32.eqz', []),
    0x46: ('i32.eq', []),
    0x47: ('i32.ne', []),
    0x48: ('i32.lt_s', []),
    0x49: ('i32.lt_u', []),
    0x4A: ('i32.gt_s', []),
    0x4B: ('i32.gt_u', []),
    0x4C: ('i32.le_s', []),
    0x4D: ('i32.le_u', []),
    0x4E: ('i32.ge_s', []),
    0x4F: ('i32.ge_u', []),

    0x50: ('i64.eqz', []),
    0x51: ('i64.eq', []),
    0x52: ('i64.ne', []),
    0x53: ('i64.lt_s', []),
    0x54: ('i64.lt_u', []),
    0x55: ('i64.gt_s', []),
    0x56: ('i64.gt_u', []),
    0x57: ('i64.le_s', []),
    0x58: ('i64.le_u', []),
    0x59: ('i64.ge_s', []),
    0x5A: ('i64.ge_u', []),

    0x5B: ('f32.eq', []),
    0x5C: ('f32.ne', []),
    0x5D: ('f32.lt', []),
    0x5E: ('f32.gt', []),
    0x5F: ('f32.le', []),
    0x60: ('f32.ge', []),

    0x61: ('f64.eq', []),
    0x62: ('f64.ne', []),
    0x63: ('f64.lt', []),
    0x64: ('f64.gt', []),
    0x65: ('f64.le', []),
    0x66: ('f64.ge', []),

    0x67: ('i32.clz', []),
    0x68: ('i32.ctz', []),
    0x69: ('i32.popcnt', []),
    0x6A: ('i32.add', []),
    0x6B: ('i32.sub', []),
    0x6C: ('i32.mul', []),
    0x6D: ('i32.div_s', []),
    0x6E: ('i32.div_u', []),
    0x6F: ('i32.rem_s', []),
    0x70: ('i32.rem_u', []),
    0x71: ('i32.and', []),
    0x72: ('i32.or', []),
    0x73: ('i32.xor', []),
    0x74: ('i32.shl', []),
    0x75: ('i32.shr_s', []),
    0x76: ('i32.shr_u', []),
    0x77: ('i32.rotl', []),
    0x78: ('i32.rotr', []),

    0x79: ('i64.clz', []),
    0x7A: ('i64.ctz', []),
    0x7B: ('i64.popcnt', []),
    0x7C: ('i64.add', []),
    0x7D: ('i64.sub', []),
    0x7E: ('i64.mul', []),
    0x7F: ('i64.div_s', []),
    0x80: ('i64.div_u', []),
    0x81: ('i64.rem_s', []),
    0x82: ('i64.rem_u', []),
    0x83: ('i64.and', []),
    0x84: ('i64.or', []),
    0x85: ('i64.xor', []),
    0x86: ('i64.shl', []),
    0x87: ('i64.shr_s', []),
    0x88: ('i64.shr_u', []),
    0x89: ('i64.rotl', []),
    0x8A: ('i64.rotr', []),

    0x8B: ('f32.abs', []),
    0x8C: ('f32.neg', []),
    0x8D: ('f32.ceil', []),
    0x8E: ('f32.floor', []),
    0x8F: ('f32.trunc', []),
    0x90: ('f32.nearest', []),
    0x91: ('f32.sqrt', []),
    0x92: ('f32.add', []),
    0x93: ('f32.sub', []),
    0x94: ('f32.mul', []),
    0x95: ('f32.div', []),
    0x96: ('f32.min', []),
    0x97: ('f32.max', []),
    0x98: ('f32.copysign', []),

    0x99: ('f64.abs', []),
    0x9A: ('f64.neg', []),
    0x9B: ('f64.ceil', []),
    0x9C: ('f64.floor', []),
    0x9D: ('f64.trunc', []),
    0x9E: ('f64.nearest', []),
    0x9F: ('f64.sqrt', []),
    0xA0: ('f64.add', []),
    0xA1: ('f64.sub', []),
    0xA2: ('f64.mul', []),
    0xA3: ('f64.div', []),
    0xA4: ('f64.min', []),
    0xA5: ('f64.max', []),
    0xA6: ('f64.copysign', []),

    0xA7: ('i32.wrap_i64', []),
    0xA8: ('i32.trunc_f32_s', []),
    0xA9: ('i32.trunc_f32_u', []),
    0xAA: ('i32.trunc_f64_s', []),
    0xAB: ('i32.trunc_f64_u', []),
    0xAC: ('i64.extend_i32_s', []),
    0xAD: ('i64.extend_i32_u', []),
    0xAE: ('i64.trunc_f32_s', []),
    0xAF: ('i64.trunc_f32_u', []),
    0xB0: ('i64.trunc_f64_s', []),
    0xB1: ('i64.trunc_f64_u', []),
    0xB2: ('f32.convert_i32_s', []),
    0xB3: ('f32.convert_i32_u', []),
    0xB4: ('f32.convert_i64_s', []),
    0xB5: ('f32.convert_i64_u', []),
    0xB6: ('f32.demote_f64', []),
    0xB7: ('f64.convert_i32_s', []),
    0xB8: ('f64.convert_i32_u', []),
    0xB9: ('f64.convert_i32_s', []),
    0xBA: ('f64.convert_i32_u', []),
    0xBB: ('f64.promote_f32', []),
    0xBC: ('i32.reinterpret_f32', []),
    0xBD: ('i64.reinterpret_f64', []),
    0xBE: ('f32.reinterpret_i32', []),
    0xBF: ('f64.reinterpret_i64', []),
}

#######################
# Section Definitions #
#######################

# [5.5.2]
class Section(object):
    '''A section contains a one-byte id, a size and the actual data'''

    def __init__(self, dat, s_type, size, start):
        self.dat = dat
        self.s_type = s_type
        self.size = size
        self.start = start

    def __repr__(self):
        return '%s(type=%d, size=%d, start=%d)' % (self.__class__.__name__, self.s_type, self.size, self.start)

# [5.5.3]
class CustomSection(Section): 
    pass

# [5.5.4]
class TypeSection(Section): 
    '''
    Contains function type information.

    Iterateable over the `function_types` property.
    '''

    @property
    def function_types(self):
        (types, _) = vec(self.dat, self.start, FuncType)

        return types

# [5.5.5]
class ImportSection(Section): 
    '''
    Contains import information.

    Iterable over the `imports` property.
    '''
    
    @property
    def imports(self):
        (imports, _) = vec(self.dat, self.start, Import)
        return imports

# [5.5.6]
class FunctionSection(Section): 
    '''
    Contains function index to type mappings.

    Iterable over the `type_indices` property.
    '''
    
    @property
    def type_indices(self):
        (indices, _) = vec(self.dat, self.start, TypeIdx)
        return indices

# [5.5.7]
class TableSection(Section): 
    '''
    Contains table information.

    Iterable over the `tables` property.
    '''

    @property
    def tables(self):
        (tables, _) = vec(self.dat, self.start, TableType)
        return tables

# [5.5.8]
class MemorySection(Section): 
    '''
    Contains information about memory segments.

    Iterable over the `memories` property.
    '''
    
    @property
    def memories(self):
        (memories, _) = vec(self.dat, self.start, MemType)
        return memories

# [5.5.9]
class GlobalSection(Section):
    '''
    Contains information about globals.

    Iterable over the `globals` property.
    '''

    @property
    def globals(self):
        (globals, _) = vec(self.dat, self.start, Global)
        return globals

# [5.5.10]
class ExportSection(Section): 
    '''
    Contains information about module exports.

    Iterable over the `exports` property.
    '''

    @property
    def exports(self):
        (exports, _) = vec(self.dat, self.start, Export)
        return exports

# [5.5.11]
class StartSection(Section): 
    '''Not implemented yet'''
    pass

# [5.5.12]
class ElementSection(Section): 
    '''Not implemented yet'''
    pass

# [5.5.13]
class CodeSection(Section): 
    '''
    Contains information about function code.

    Iterable over the `code_entries` property.
    '''

    @property
    def code_entries(self):
        (code_entries, _) = vec(self.dat, self.start, Code)
        return code_entries

# [5.5.14]
class DataSection(Section): 
    '''
    Contains information about data segments.

    Iterable over the `data_entries` property.
    '''

    @property
    def data_entries(self):
        (data_entries, _) = vec(self.dat, self.start, Data)
        return data_entries
    
SECTION_TYPES = {
    0: CustomSection,
    1: TypeSection,
    2: ImportSection,
    3: FunctionSection,
    4: TableSection,
    5: MemorySection,
    6: GlobalSection,
    7: ExportSection,
    8: StartSection,
    9: ElementSection,
    10: CodeSection,
    11: DataSection
}

class WASMParser(object):
    '''
    Main parser class. Initialize with a bytearray containing wasm bytecode.
    '''

    def __init__(self, dat):
        self.dat = dat

        self.custom_sections = []
        self.type_section = None
        self.import_section = None
        self.function_section = None
        self.table_section = None
        self.memory_section = None
        self.global_section = None
        self.export_section = None
        self.start_section = None
        self.element_section = None
        self.code_section = None
        self.data_section = None

        self._load()

    def _load(self):
        # validate header
        magic = self.dat[:4]
        assert magic == b'\x00asm', "Wrong magic value"
        
        version = self.dat[4:8]
        assert version == b'\x01\x00\x00\x00', "Unknown version"

        last_section_type = 0

        i = 8
        while i < len(self.dat):
            # section type
            section_type = self.dat[i]
            i += 1

            # assert section_type > last_section_type or section_type == 0, "Sections out of order!"
            last_section_type = section_type

            # section size
            (section_size, i) = decode_LEB128(self.dat, i)

            # print(section_size)

            if not section_type in SECTION_TYPES:
                print(i, section_type)
                i += section_size
                continue

            assert section_type in SECTION_TYPES, "Unknown section type: %d" % section_type
            section_class = SECTION_TYPES[section_type]

            sec = section_class(self.dat, section_type, section_size, i)
            i += section_size
            
            if type(sec) == TypeSection:
                self.type_section = sec
            elif type(sec) == ImportSection:
                self.import_section = sec
            elif type(sec) == FunctionSection:
                self.function_section = sec
            elif type(sec) == TableSection:
                self.table_section = sec
            elif type(sec) == MemorySection:
                self.memory_section = sec
            elif type(sec) == GlobalSection:
                self.global_section = sec
            elif type(sec) == ExportSection:
                self.export_section = sec
            elif type(sec) == StartSection:
                self.start_section = sec
            elif type(sec) == ElementSection:
                self.element_section = sec
            elif type(sec) == CodeSection:
                self.code_section = sec
            elif type(sec) == DataSection:
                self.data_section = sec
            else:
                self.custom_sections.append(sec)
