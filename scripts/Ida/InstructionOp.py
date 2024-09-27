import idc
import string
import ida_ua
'''
return the operand type 
'''
def get_operands_type(instruction_address,index) -> string:
    return idc.get_operand_type(instruction_address,index)


'''
return the op of the instruction
'''
def get_op_of_the_instruction(instruction_address) -> string:
    return idc.print_insn_mnem(instruction_address)

'''
return the disasm code in the address
'''
def get_disasm_code(instruction_address) -> string:
    return idc.generate_disasm_line(instruction_address, 0)

'''
return the num of operand in a instruction
'''
def get_operand_count(instruction_address) -> int:
    operand_count = 0
    for operand_index in range(6):
        operand_type = idc.get_operand_type(instruction_address, operand_index)
        if operand_type == idc.o_void:
            break
        else:
            operand_count += 1
    return operand_count

'''
return the ith operand of the instruction
'''
def get_operand(instruction_address,index) -> string:
    return idc.print_operand(instruction_address,index)

'''
return the ith operand value of the instruction
'''
def get_operands_value(instruction_address,index) -> int:
    return idc.get_operand_value(instruction_address,index)


'''
remove space and find ;
'''
def get_comments(instruction_address) -> string:
    disasm_code = get_disasm_code(instruction_address)
    if disasm_code == "":
        return None
    semicolon_index = disasm_code.find(';')
    if semicolon_index == -1:
        return None;
    return disasm_code[semicolon_index + 1:].strip()

