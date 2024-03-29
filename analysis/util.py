#!/usr/local/bin/python3

# ----------------------------------------
#   this module doesn't depend on any
#   self-implemented things
# ----------------------------------------

import angr, pyvex
import sys
import copy
from dwarf_vex_map import *
from dwarf_iced_map import *
from z3 import *
import re
from iced_x86 import *

# ----------------------------------------
#
#   common
#
# ----------------------------------------

def find_l_ind(insts:list[Instruction], ip:int):
    ''' find the the first index of insts that insts[index].ip >= ip
    [.. ip, ind ..]
    '''
    l, r = 0, len(insts)
    while l<r:
        mid = int((l+r)/2)
        if insts[mid].ip >= ip:
            r = mid
        else:
            l = mid+1
    return l

# ----------------------------------------
#
#   iced_x86 utility
#
# ----------------------------------------

code_to_str = {Code.__dict__[key]:key for key in Code.__dict__ if isinstance(Code.__dict__[key], int)}
mnemoic_to_str = {Mnemonic.__dict__[key]:key for key in Mnemonic.__dict__ if isinstance(Mnemonic.__dict__[key], int)}
opKind_to_str = {OpKind.__dict__[key]:key for key in OpKind.__dict__ if isinstance(OpKind.__dict__[key], int)}
memorySize_to_str = {MemorySize.__dict__[key]:key for key in MemorySize.__dict__ if isinstance(MemorySize.__dict__[key], int)}
register_to_str = {Register.__dict__[key]:key for key in Register.__dict__ if isinstance(Register.__dict__[key], int)}

memorySize_to_int = { key:8 * ( 1<< ((key-1) if key <= 7 else (key-8)) ) for key in range(1, 15)}

# ----------------------------------------
#
#   dwarf utility
#
# ----------------------------------------

class DwarfType(Enum):
    MEMORY = 0
    REGISTER = 1
    VALUE = 2

''' may substitue `DwarfType`, later
'''
class DetailedDwarfType(Enum):
    INVALID = -1
    MEM_GLOABL = 0
    MEM_CFA = 1
    MEM_SINGLE = 2
    MEM_MULTI = 3

    REG_PARAM = 4
    REG_OTHER = 5

    IMPLICIT = 6

and_mask:dict = {
    8   : 0xff,
    16  : 0xffff,
    32  : 0xffffffff
}

# ----------------------------------------
#
#   vex utility
#
# ----------------------------------------

un_cast_re = re.compile(r"Iop_(F|V)?(?P<srcsize>\d+)(U|S|HI|LO)?to(F|V)?(?P<dstsize>\d+)")
bin_cast_re = re.compile(r"Iop_(F|V)?(?P<srcsize>\d+)(HL)to(F|V)?(?P<dstsize>\d+)")
cmpF_re = re.compile(r"Iop_Cmp(F)(?P<size>\d+)$")
cas_exp_cmp_re = re.compile(r"Iop_(Cas|Exp)Cmp(NE|EQ)(?P<size>\d+)")
''' float conversion, take an extra 32-bit rounding mode arg
'''
f_cast_re = re.compile(r"Iop_(F|I)(?P<srcsize>\d+)(U|S)?to(F|I)(?P<dstsize>\d+)(U|S)?")

def is_useful_reg(regOff:int):
    return 16 <= regOff <= 136 or 224 <= regOff <= 704

def get_reg_ind(regOff:int):
    if 16 <= regOff <= 136:
        return int((regOff-16)/8)
    elif 224 <= regOff <= 704:
        return int((regOff-224)/32)
    else:
        return -1

def get_base_name_vex(regOff:int):
    if not is_useful_reg(regOff):
        return "unuseful"
    if 16 <= regOff <= 136:
        if (regOff - 1) % 8 == 0:
            return vex_reg_names[regOff-1]
        else:
            return vex_reg_names[regOff]
    
    if 224 <= regOff <= 704:
        if regOff % 16 == 8:
            return vex_reg_names[regOff - 8]
        else:
            return vex_reg_names[regOff]

# ----------------------------------------
#
#   Z3 utility
#
# ----------------------------------------

''' function symbols
'''
load8:FuncDeclRef = Function("load8", BitVecSort(64), BitVecSort(8))
load16:FuncDeclRef = Function("load16", BitVecSort(64), BitVecSort(16))
load32:FuncDeclRef = Function("load32", BitVecSort(64), BitVecSort(32))
load64:FuncDeclRef = Function("load64", BitVecSort(64), BitVecSort(64))
load128:FuncDeclRef = Function("load128", BitVecSort(64), BitVecSort(128))

load_funcs:dict = {
    8 : load8,
    16 : load16,
    32 : load32,
    64 : load64,
    128 : load128
}

x = BitVec("addr_x", 64)
loads_cond = ForAll(x, And(load64(x) == SignExt(56, load8(x)),
                          load64(x) == SignExt(48, load16(x)),
                          load64(x) == SignExt(32, load32(x)),
                          load64(x) == Extract(63, 0, load128(x))))

loadu_cond = ForAll(x, And(load64(x) == ZeroExt(56, load8(x)),
                          load64(x) == ZeroExt(48, load16(x)),
                          load64(x) == ZeroExt(32, load32(x)),
                          load64(x) == Extract(63, 0, load128(x))))

def post_format(z3_expr:ExprRef):
    if isinstance(z3_expr, BoolRef):
        return If(z3_expr, BitVecVal(1, 64), BitVecVal(0, 64))
    
    if isinstance(z3_expr, BitVecRef):
        if z3_expr.size() != 64:
            z3_expr = Extract(63, 0, z3_expr) if z3_expr.size() > 64 else ZeroExt(64 - z3_expr.size(), z3_expr)

    return z3_expr

def has_load(exp:BitVecRef) -> bool:
    res:bool = exp.decl().name().startswith("load")
    for child in exp.children():
        res = has_load(child) or res
    return res

def has_offset(exp:BitVecRef) -> bool:
    res:bool = isinstance(exp, BitVecNumRef) and exp.as_long() != 0
    for child in exp.children():
        res = has_offset(child) or res
    return res

def isReg(exp:BitVecRef) -> bool:
    return exp.decl().name() in vex_reg_size_codes

def extract_regs_from_z3(z3Expr:BitVecRef) -> list[BitVecRef]:
    ''' get all register names
    '''
    res = [z3Expr] if isReg(z3Expr) else []
    for child in z3Expr.children():
        res.extend(extract_regs_from_z3(child))
    return res

def is_regs_match(exp1:BitVecRef, exp2:BitVecRef):
    ''' 
    '''
    return True

def guess_reg_type_smaller(z3Expr:BitVecRef) -> dict[str, int]:
    ''' if reg is extracted to small type, record the bit num
    '''
    
    children = z3Expr.children()
    if len(children) == 0:
        return {}
    
    res = {}
    isExtract =  z3Expr.decl().name() == "extract"
    for child in children:
        if isExtract and isReg(child):
            r, l = z3Expr.params()
            res[child.decl().name()] = r-l+1
        res.update(guess_reg_type_smaller(child))
    
    return res
    

def cond_toSmaller_to64(reg:BitVecRef, bit_num:int):
    ''' from bitnum to 64
    '''
    size = (1<<bit_num)
    # return And(reg<BitVecVal(size, 64), reg>=BitVecVal(0, 64))
    return ZeroExt(64-bit_num, Extract(bit_num-1, 0, reg)) == reg

def make_reg_type_conds(z3Expr:BitVecRef) -> list:
    conds = []
    reg_map_smaller = guess_reg_type_smaller(z3Expr)
    z3_regs:list[BitVecRef] = extract_regs_from_z3(z3Expr)
    for z3_reg in z3_regs:
        if z3_reg.size() < 64:
            cond = SignExt(64-z3_reg.size(), z3_reg)==BitVec(z3_reg.decl().name(), 64)
            conds.append(cond)
        
        if z3_reg.decl().name() not in reg_map_smaller:
            continue
        ''' if vex convert reg's size, imply no change in conversion
        '''
        cond = cond_toSmaller_to64(z3_reg, reg_map_smaller[z3_reg.decl().name()])
        conds.append(cond)
    
    return conds

def get_addr(z3Expr:BitVecRef) -> BitVecRef:
    if z3Expr.decl().name().startswith("load"):
        return z3Expr.children()[0]
    return None

def getBinarySize(exp:BitVecRef):
    ''' if exp has `load` operation, then return the size of load
        
        if not, return the max size of register, for convenience
        we choose to guess now, because registers smaller than 64bit
        will have a father of `Extract` type, we use the extract size

        we do this for get size of source operand of an instruction
    '''
    children = [exp]
    while len(children) > 0:
        curExp = children[0]
        children.pop(0)
        if curExp.decl().name().startswith("load"):
            return int(curExp.decl().name()[4:])
        
        children.extend(curExp.children())

    reg_sizes = list(guess_reg_type_smaller(exp).values())
    ''' reg is 64-bit as default, if not found extraction, it implies the register(s)
        are all 64-bit
    '''
    return max(reg_sizes) if len(reg_sizes) > 0 else 64