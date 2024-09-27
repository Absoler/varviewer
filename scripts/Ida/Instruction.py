import idautils
import string
import  idc
import  InstructionOp

'''
the function idc.get_operand_type(address,index) returns one of the follwing number,
represent the corresponding operand type  8~13 is special for x86
'''
class InstructionOperandType:
    Operand_Type = {
        idc.o_void: "No Operand",  # 0
        idc.o_reg: "Register Operand",  # 1
        idc.o_mem: "Direct Memory Reference",  # 2
        idc.o_phrase: "Memory Ref",  # 3 [Base Reg + Index Reg]
        idc.o_displ: "Memory Operand with Offset",  # 4 [Base Reg + Index Reg + Displacement]
        idc.o_imm: "Immediate Operand",  # 5
        idc.o_far: "Far jump operand",  # 6
        idc.o_near: "Relativily or Absolute Jump Operand",  # 7

        idc.o_trreg: "Trace Register",  # 8
        idc.o_dbreg: "debug Register",  # 9
        idc.o_crreg: "Control Register",  # 10
        idc.o_fpreg: "Floating Point Register",  # 11
        idc.o_mmxreg: "MMX Register",  # 12
        idc.o_xmmreg: "XMM Register"  # 13
}

'''
Instruction
'''
class Instruction:
    Register_List = idautils.GetRegisterList()

    def __init__(self, instruction_address,
                 instruction_disasm_code,
                 instuction_opcode,
                 instruction_operand_count,
                 instruction_comments,
                 instruction_operand_list=[],
                 ) -> None:
        self.Instruction_Address: int = instruction_address
        self.Instruction_Address_16 : string = hex(instruction_address)
        self.Instruction_Disasm_Code: string = instruction_disasm_code
        self.Instruction_Opcode: string = instuction_opcode
        self.Instruction_Operand_Count: int = instruction_operand_count
        if instruction_comments is None:
            self.Has_Comments: bool = False
            self.Instruction_Comments: string = None
        else:
            self.Has_Comments: bool = True
            self.Instruction_Comments: string = instruction_comments
        '''
        format : [(operand,operand_type,operand_type_num,operand_value)]

        a example :  add   eax, edx
            [(eax,Register Operand,idc.o_reg,0),	
            (edx,Register Operand,idc.o_reg,2)]
        '''
        self.Instruction_Operand_List: list = instruction_operand_list
        for i in range(instruction_operand_count):
            operand = InstructionOp.get_operand(instruction_address, i)
            '''
            InstructionOp.get_operands_type return the number represent type
            '''
            operand_type_num = InstructionOp.get_operands_type(instruction_address, i)
            if operand_type_num not in InstructionOperandType.Operand_Type:
                continue;
            else:
                operand_type = InstructionOperandType.Operand_Type[operand_type_num]

            if operand_type == "Invalid Operand":
                continue

            operand_value:int = InstructionOp.get_operands_value(instruction_address, i)
            self.Instruction_Operand_List.append((operand, operand_type, operand_type_num, operand_value))

    def to_dict(self):
        return {
            "Address": self.Instruction_Address,
            "Disasm_Code": self.Instruction_Disasm_Code,
            "Opcode": self.Instruction_Opcode,
            "Operand_Count": self.Instruction_Operand_Count,
            "Comments": self.Instruction_Comments,
            "Operands": self.Instruction_Operand_List
        }

    @classmethod
    def get_register_name(cls,register_index):
        return Instruction.Register_List[register_index]

    '''
    bound checking helper
    '''
    def check_bound(self, n):
        if n >= self.operand_count or n < 0:
            raise IndexError(f"Operand index out of range: {n} (expected 0 to {self.Instruction_Operand_Count - 1})")

    '''
    return the nth operand(the raw format, example : eax)
    '''

    def get_operand_info(self, n) ->string:
        self.check_bound(n)
        return self.Instruction_Operand_List[n][0]

    '''
    return the type of nth operand (string format ,example : "Register Operand")
    '''

    def get_operand_type(self, n) -> string:
        self.check_bound(n)
        return self.Instruction_Operand_List[n][1]

    '''
    return the type of nth operand (num format, example : idc.o_reg)
    '''

    def get_operand_type_num(self, n) -> int:
        self.check_bound(n);
        return self.Instruction_Operand_List[n][2]

    '''
    return the value of nth operand, if is a register, return the num represent 
    '''
    def get_operand_value(self, n) ->int:
        self.check_bound(n)
        return self.Instruction_Operand_List[n][3]

    @property
    def address(self):
        return self.Instruction_Address
    @address.setter
    def address(self, address):
        self.Instruction_Address = address

    @property
    def address_16(self):
        return self.Instruction_Address_16
    @address_16.setter
    def address_16(self,address_16):
        self.Instruction_Address_16 = address_16

    @property
    def diasm_code(self):
        return self.Instruction_Disasm_Code
    @diasm_code.setter
    def diasm_code(self, disasm_code):
        self.Instruction_Disasm_Code = disasm_code

    @property
    def opcode(self):
        return self.Instruction_Opcode
    @opcode.setter
    def opcode(self, opcode):
        self.Instruction_Opcode = opcode

    @property
    def operand_count(self):
        return self.Instruction_Operand_Count
    @operand_count.setter
    def operand_count(self, operand_count):
        self.Instruction_Operand_Count = operand_count

    @property
    def operand_list(self):
        return self.Instruction_Operand_List
    @operand_list.setter
    def operand_list(self, operand_list):
        self.Instruction_Operand_List = operand_list

    @property
    def has_comments(self):
        return self.Has_Comments;
    @has_comments.setter
    def has_comments(self, flag: bool):
        self.Has_Comments = flag

    @property
    def comments(self):
        return self.Instruction_Comments
    @comments.setter
    def comments(self, comments):
        self.Instruction_Comments = comments

    def __str__(self) -> string:
        return f"Address:{self.address},Disasm_Code:{self.diasm_code},Operand_Count:{self.operand_count},Operand_list:{self.operand_list}"

