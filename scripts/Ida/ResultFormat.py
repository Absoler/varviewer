from enum import  Enum
import  string
class MatchPosition(Enum):
    invalid = 0
    src_value = 1
    src_addr = 2
    dst_value = 4
    dst_addr = 8


class DwarfType(Enum):
    MEMORY = 0
    REGISTER = 1
    VALUE = 2


class VariableType(Enum):
    INVALID = -1
    MEM_GLOABL = 0
    MEM_CFA = 1
    MEM_SINGLE = 2
    MEM_MULTI = 3

    REG_PARAM = 4
    REG_OTHER = 5

    IMPLICIT = 6


class Result:
    def __init__(self, name: str, addr: int, expression:string,operand_type:string,matchPos: MatchPosition, indirect: int, dwarfType: DwarfType,
                 variable_type: VariableType, irsb_addr=0, ind=0, offset: int = 0, src_size: int = -1) -> None:
        self.addr: int = addr
        self.name: str = name
        self.matchPos: MatchPosition = matchPos
        ''' src_size is the size of src operand in instruction, we use it to cast dst value
            to src type, because:

            src and dst operand in x86 mov instruction may have different size
            if matchPos is `src_value` and we need use dst value to replace src value
        '''
        self.src_size: int = src_size
        ''' specify the match part of binary operand is `v` or `&v`
            if -1, means match `&v`, and can't occur when matchPos is `src_addr` or `dst_addr`,
            because it's equal to indirect == 0 and matchPos is `src_value` or `dst_value`
        '''
        self.indirect: int = indirect
        self.dwarfType: DwarfType = dwarfType
        self.variable_type: VariableType = variable_type
        self.offset: int = offset
        self.expression:string = expression
        self.operand_type:string = operand_type
        self.irsb_addr = irsb_addr
        self.ind = ind
        self.piece_num: int = -1
        ''' no certain which operand is need, 
            so record all, join with '@'
        '''
        self.uncertain: bool = False

    def to_dict(self):
        return {
            'addr': self.addr,
            'name': self.name,
            'operand_type_ida':self.operand_type,
            'matchPos': self.matchPos.value,
            'indirect': self.indirect,
            'dwarfType': self.dwarfType.value,
            'variable_type': self.variable_type.value,
            'offset': self.offset,
            'expression': self.expression,
            'uncertain': self.uncertain
        }
    def keys(self):
        return (
        'addr', 'name', 'matchPos', 'indirect', 'dwarfType', 'variable_type', 'offset', 'expression', 'uncertain')

    def __getitem__(self, item):
        if item == "matchPos":
            return self.matchPos.value
        elif item == "dwarfType":
            return self.dwarfType.value
        elif item == 'variable_type':
            return self.variable_type.value
        return getattr(self, item)

    def __str__(self) -> str:
        return f"0x{self.addr:X} name:{self.name} dwarfType:{self.dwarfType.name} variable_type:{self.variable_type.name} pos:{self.matchPos.name} indirect:{self.indirect} offset:{self.offset} {self.piece_num}:{self.irsb_addr}:{self.ind}"
