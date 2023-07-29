import json
from enum import Enum

'''
    ---------- final result format ----------

    [
        {
            "addr" : address of mapped instruction
            "matchTy" : match type
            "offset" : offset from match point
            "expression" : match object, may be lldb or gdb's supported format
        }
    ]
'''

''' all match types
'''
class MatchType(Enum):
    invalid = 0
    src_value = 1
    src_addr = 2
    dst_value = 4
    dst_addr = 8


class Result:
    def __init__(self, addr:int, matchTy:MatchType) -> None:
        self.addr:int = addr
        self.matchTy:MatchType = matchTy
        self.offset:int = 0
        self.expression = None
    
    def keys(self):
        return ('addr', 'matchTy', 'offset', 'expression', )
    
    def __getitem__(self, item):
        return getattr(self, item)
    
    def __str__(self) -> str:
        return f"0x{self.addr:X} {self.matchTy.name}"
    
    def update(self, base_addr:int):
        self.addr += base_addr