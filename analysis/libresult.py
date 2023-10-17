import json
from enum import Enum
from z3 import *
from util import *
from iced_x86 import *
'''
    ---------- final result format ----------

    [
        {
            "addr" : address of mapped instruction
            "matchPos" : match position
            "offset" : offset from match point
            "expression" : match object, may be lldb or gdb's supported format
        }
    ]
'''

''' all possible match position
'''
class MatchPosition(Enum):
    invalid = 0
    src_value = 1
    src_addr = 2
    dst_value = 4
    dst_addr = 8

def getMemTypeStr(memSize:MemorySize):
    if memSize == MemorySize.UINT8 or memSize == MemorySize.INT8:
        return "char *"
    elif memSize == MemorySize.UINT16 or memSize == MemorySize.INT16:
        return "short *"
    elif memSize == MemorySize.UINT32 or memSize == MemorySize.INT32:
        return "int *"
    elif memSize == MemorySize.UINT64 or memSize == MemorySize.INT64:
        return "long long *"
    else:
        return "*"


def isAddrPos(pos:MatchPosition) -> bool:
    return pos == MatchPosition.src_addr or pos == MatchPosition.dst_addr

def isDestPos(pos:MatchPosition) -> bool:
    return pos == MatchPosition.dst_value or pos == MatchPosition.dst_addr


def setpos(z3Expr:ExprRef, pos:MatchPosition = MatchPosition.invalid):
    setattr(z3Expr, "matchPos", pos)


''' get gdb-valid string of memory use in an instruction
'''
def get_address_str_of_insn(insn:Instruction) -> str:
    # `disp`
    res = f"{insn.memory_displacement}"
    if not insn.is_ip_rel_memory_operand:
        # `disp + baseReg`
        res += f" + ${register_to_str[insn.memory_base].lower()}" if insn.memory_base != Register.NONE else ""
        # `disp + baseReg + scale*indexReg`
        res += f" + ${register_to_str[insn.memory_index].lower()}*{insn.memory_index_scale}" if insn.memory_index != Register.NONE else ""
    return res


''' get gdb-valid string of specified operand of an instruction
'''
def get_value_str_of_operand(insn:Instruction, ind:int) -> str:
    
    if insn.op_kind(ind) == OpKind.MEMORY:
        address = get_address_str_of_insn(insn)   
        return f"*({getMemTypeStr(insn.memory_size)})({address})"

    elif insn.op_kind(ind) == OpKind.REGISTER:
        if not (insn.op_register(ind) != Register.NONE):
            print('hit')
        return f"${register_to_str[insn.op_register(ind)].lower()}"
    
    else:
        print(f"can't convert opkind {opKind_to_str[insn.op_kind(ind)]} to str", file=sys.stderr)
        return ""

class Result:
    def __init__(self, addr:int, matchPos:MatchPosition, indirect:int, dwarfType:DwarfType, variable_type:VariableType, irsb_addr=0, ind=0, offset:int = 0) -> None:
        self.addr:int = addr
        self.name:str = ""
        self.matchPos:MatchPosition = matchPos
        ''' -1, 0
            match to &v, v
        '''
        self.indirect:int = indirect
        self.dwarfType:DwarfType = dwarfType
        self.variable_type:VariableType = variable_type
        self.offset:int = offset
        self.expression = ""
        self.irsb_addr = irsb_addr
        self.ind = ind
        self.piece_num:int = -1
        ''' no certain which operand is need, 
            so record all, join with '@'
        '''
        self.uncertain:bool = False
    
    def keys(self):
        return ('addr', 'name', 'matchPos', 'indirect', 'dwarfType', 'variable_type', 'offset', 'expression', 'uncertain')
    
    def __getitem__(self, item):
        if item == "matchPos":
            return self.matchPos.value
        elif item == "dwarfType":
            return self.dwarfType.value
        elif item == 'variable_type':
            return self.variable_type.value
        return getattr(self, item)
    
    def __str__(self) -> str:
        return f"0x{self.addr:X} name:{self.name} dwarfType:{self.dwarfType.name} variable_type:{self.variable_type.name} pos:{self.matchPos.name} indirect_level:{self.indirect} offset:{self.offset} {self.piece_num}:{self.irsb_addr}:{self.ind}"
    
    def update(self, name:str, piece_num:int):
        self.name = name
        self.piece_num = piece_num

    def construct_expression(self, insn:Instruction) -> bool:
        if insn.op_count < 1:
            return False
        ''' only use the target operand, because it's confirmed
            
        '''
        
        ''' if `src_addr`, it means op1 must be the source, 
            not mixed with other

        '''
        
        code_str = code_to_str[insn.code]
        src_ind, dst_ind = 1, 0
        if code_str.startswith("PUSH"):
            src_ind, dst_ind = None, 0
        elif insn.op_count == 1:
            src_ind, dst_ind = 0, 0

        ''' these instructions have 2 operands and are all read,
            any of the 2 operands can be matched
        '''
        self.uncertain = code_str.startswith("CMP") or code_str.startswith("TEST")
        if self.uncertain:
            if isAddrPos(self.matchPos):
                assert(insn.op0_kind == OpKind.MEMORY or insn.op1_kind == OpKind.MEMORY)
                address = get_address_str_of_insn(insn)
                self.expression = address
            else:
                value0, value1 = get_value_str_of_operand(insn, 0), get_value_str_of_operand(insn, 1)
                self.expression = value0 + "@" + value1 +"@"
            self.addOffset()
            return True
                

        if isDestPos(self.matchPos):

            if self.matchPos == MatchPosition.dst_addr:
                assert(insn.op_kind(dst_ind) == OpKind.MEMORY)
                address = get_address_str_of_insn(insn)
                self.expression = address
            
            elif self.matchPos == MatchPosition.dst_value:
                value = get_value_str_of_operand(insn, dst_ind)
                if not value:
                    return False
                self.expression = value


        else:

            if self.matchPos == MatchPosition.src_addr:
                ''' matchPos is `src_addr`, then the match must not mix src and dst
                    operand,
                '''
                assert(insn.op_kind(src_ind) == OpKind.MEMORY)
                address = get_address_str_of_insn(insn)
                self.expression = address

            else:
                ''' for src_value, we record the just like dst_value,
                    because we don't know whether src is mixed with dst
                '''
                value:str = get_value_str_of_operand(insn, dst_ind)
                if not value:
                    return False
                self.expression = value
        
        self.addOffset()
                
        return True
    
    def addOffset(self):
        if self.offset > 0:
            self.expression = '(' + self.expression + ' - ' + str(self.offset) + ')'
        elif self.offset < 0:
            self.expression = '(' + self.expression + str(self.offset) + ')'
            