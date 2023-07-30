import json
from enum import Enum
from z3 import *
from util import *
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

def isAddr(pos:MatchPosition) -> bool:
    return pos == MatchPosition.src_addr or pos == MatchPosition.dst_addr

def setpos(z3Expr:ExprRef, pos:MatchPosition = MatchPosition.invalid):
    setattr(z3Expr, "matchPos", pos)

class Result:
    def __init__(self, addr:int, matchPos:MatchPosition, indirect:int, dwarfType:DwarfType, irsb_addr=0, ind=0) -> None:
        self.addr:int = addr
        self.name:str = ""
        self.matchPos:MatchPosition = matchPos
        ''' -1, 0
            match to &v, v
        '''
        self.indirect:int = indirect
        self.dwarfType:DwarfType = dwarfType
        self.offset:int = 0
        self.expression = None
        self.irsb_addr = irsb_addr
        self.ind = ind
    
    def keys(self):
        return ('addr', 'matchPos', 'indirect', 'offset', 'expression', )
    
    def __getitem__(self, item):
        return getattr(self, item)
    
    def __str__(self) -> str:
        return f"0x{self.addr:X} name:{self.name} dwarfType:{self.dwarfType.name}    pos:{self.matchPos.name} indirect level:{self.indirect} {self.piece_num}:{self.irsb_addr}:{self.ind}"
    
    def update(self, piece_addrs:list[int], name:str, piece_num:int):
        self.addr = piece_addrs[self.addr]
        self.name = name
        self.piece_num = piece_num