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

def isAddrPos(pos:MatchPosition) -> bool:
    return pos == MatchPosition.src_addr or pos == MatchPosition.dst_addr

def isDestPos(pos:MatchPosition) -> bool:
    return pos == MatchPosition.dst_value or pos == MatchPosition.dst_addr


def setpos(z3Expr:ExprRef, pos:MatchPosition = MatchPosition.invalid):
    setattr(z3Expr, "matchPos", pos)

class Result:
    def __init__(self, addr:int, matchPos:MatchPosition, indirect:int, dwarfType:DwarfType, irsb_addr=0, ind=0, offset:int = 0) -> None:
        self.addr:int = addr
        self.name:str = ""
        self.matchPos:MatchPosition = matchPos
        ''' -1, 0
            match to &v, v
        '''
        self.indirect:int = indirect
        self.dwarfType:DwarfType = dwarfType
        self.offset:int = offset
        self.expression = ""
        self.irsb_addr = irsb_addr
        self.ind = ind
        self.piece_num:int = -1
    
    def keys(self):
        return ('addr', 'name', 'matchPos', 'indirect', 'dwarfType', 'offset', 'expression')
    
    def __getitem__(self, item):
        if item == "matchPos":
            return self.matchPos.value
        elif item == "dwarfType":
            return self.dwarfType.value
        return getattr(self, item)
    
    def __str__(self) -> str:
        return f"0x{self.addr:X} name:{self.name} dwarfType:{self.dwarfType.name}    pos:{self.matchPos.name} indirect level:{self.indirect} {self.piece_num}:{self.irsb_addr}:{self.ind}"
    
    def update(self, piece_addrs:list[int], name:str, piece_num:int):
        self.addr = piece_addrs[self.addr]
        self.name = name
        self.piece_num = piece_num

    def construct_expression(self, insn:Instruction) -> bool:
        ''' only use the target operand, because it's confirmed
            trust op0 in iced_x86 is target
        '''
        
        ''' if `src_addr`, it means op1 must be the source, 
            not mixed with other

        '''
        
        if isDestPos(self.matchPos):
            if insn.op_count < 1:
                return False
            if insn.op0_kind == OpKind.MEMORY:
                # `disp`
                address = f"{insn.memory_displacement}"
                if not insn.is_ip_rel_memory_operand:
                    # `disp + baseReg`
                    address += f" + ${register_to_str[insn.memory_base].lower()}" if insn.memory_base != Register.NONE else ""
                    # `disp + baseReg + scale*indexReg`
                    address += f" + ${register_to_str[insn.memory_index].lower()}*{insn.memory_index_scale}" if insn.memory_index != Register.NONE else ""
                
                if self.matchPos == MatchPosition.dst_addr:
                    self.expression = address
                    self.addOffset()

                elif self.matchPos == MatchPosition.dst_value:
                    ''' for dst_value, we need compare the derefernce of binary address with dwarf var
                    '''
                    self.expression = f"*({address})"
                    self.addOffset()
                    self.expression += f" & {(1<<memorySize_to_int[insn.memory_size]) - 1}" if memorySize_to_int[insn.memory_size] < 64 else "0"
            
            elif insn.op0_kind == OpKind.REGISTER:
                self.expression = f"${register_to_str[insn.op0_register].lower()}"
                self.addOffset()
            else:
                print(f"can't convert opkind {opKind_to_str[insn.op0_kind]} to str", file=sys.stderr)
                return False
        
        else:
            if insn.op_count<2:
                return False
            if self.matchPos == MatchPosition.src_addr:
                ''' matchPos is `src_addr`, then the match must not mix src and dst
                    operand,
                '''
                assert(insn.op1_kind == OpKind.MEMORY)
                # `disp`
                address = f"{insn.memory_displacement}"
                # `disp + baseReg`
                address += f" + ${register_to_str[insn.memory_base].lower()}" if insn.memory_base != Register.NONE else ""
                # `disp + baseReg + scale*indexReg`
                address += f" + ${register_to_str[insn.memory_index].lower()}*{insn.memory_index_scale}" if insn.memory_index != Register.NONE else ""
                
                self.expression = address
                self.addOffset()
                
            else:
                ''' for src_value, we record the just like dst_value,
                    because we don't know whether src is mixed with dst
                '''
                if insn.op0_kind == OpKind.MEMORY:
                    # `disp`
                    address = f"{insn.memory_displacement}"
                    if not insn.is_ip_rel_memory_operand:
                        # `disp + baseReg`
                        address += f" + ${register_to_str[insn.memory_base].lower()}" if insn.memory_base != Register.NONE else ""
                        # `disp + baseReg + scale*indexReg`
                        address += f" + ${register_to_str[insn.memory_index].lower()}*{insn.memory_index_scale}" if insn.memory_index != Register.NONE else ""
                    
                    self.expression = f"*({address})"
                    self.addOffset()
                    self.expression += f" & {(1<<memorySize_to_int[insn.memory_size]) - 1}" if memorySize_to_int[insn.memory_size] < 64 else ""
                
                elif insn.op0_kind == OpKind.REGISTER:
                    self.expression = f"${register_to_str[insn.op0_register].lower()}"
                    self.addOffset()
                else:
                    print(f"can't convert opkind {opKind_to_str[insn.op0_kind]} to str", file=sys.stderr)
                    return False
                
        return True
    
    def addOffset(self):
        if self.offset > 0:
            self.expression = '(' + self.expression + ' - ' + str(self.offset) + ')'
        elif self.offset < 0:
            self.expression = '(' + self.expression + str(self.offset) + ')'
            