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





class Result:
    def __init__(self, name: str, addr: int, expression:string,operand_type:string,matchPos: MatchPosition) -> None:
        self.addr: int = addr
        self.addr_hex = hex(addr)
        self.name: str = name
        self.matchPos: MatchPosition = matchPos
        self.expression:string = expression
        self.operand_type:string = operand_type

    def to_dict(self):
        return {
            'addr': self.addr,
            'addr_hex': self.addr_hex,
            'name': self.name,
            'operand_type_ida':self.operand_type,
            'matchPos': self.matchPos.value,
            'expression': self.expression,
        }
    def keys(self):
        return (
        'addr','addr_hex','name','matchPos','operand_type',  'expression')

    def __getitem__(self, item):
        if item == "matchPos":
            return self.matchPos.value
        return getattr(self, item)

    def __str__(self) -> str:
        return f"0x{self.addr:X} name:{self.name}  pos:{self.matchPos.name} "
