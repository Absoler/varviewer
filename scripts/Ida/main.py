import sys
import  os
import traceback
import  re
import ida_funcs
import ida_ua
import idc
import idautils
import string
import json
import  ida_nalt
import  ida_name
import InstructionOp
from Instruction import Instruction
from Instruction import InstructionOperandType
from ResultFormat import *
from RegisterOp import  *


'''
return the start address of the giving segment of the binary file
'''
def get_segm(segm_name) -> string:
    try:
        for seg in idautils.Segments():
            if idc.get_segm_name(seg) == segm_name:
                return seg
    except:
        sys.stderr.write(traceback.format_exc());


'''
skip the op wo do not care about
'''
def is_skip_operation(ia) -> bool:
    Skip_List = ['call', 'cdq', 'cwo', 'cbw', 'cqo', 'cdqe', 'cwde']
    # dd db dw dq has no zhujifu opcode
    if InstructionOp.get_op_of_the_instruction(ia) == [] or InstructionOp.get_op_of_the_instruction(ia) == "":
        return True
    # in skip list
    if InstructionOp.get_op_of_the_instruction(ia) in Skip_List:
        return True
    # no operand
    if InstructionOp.get_operand_count(ia) == 0:
        return True
    # jump operation
    if InstructionOp.get_op_of_the_instruction(ia).startswith('j') \
            or InstructionOperandType.Operand_Type[InstructionOp.get_operands_type(ia, 0)] == "Far jump operand" \
            or InstructionOperandType.Operand_Type[
        InstructionOp.get_operands_type(ia, 0)] == "Relativily or Absolute Jump Operand":
        return True

    # rep operation,ida think it has two opered , and both return ""
    if InstructionOp.get_operand_count(ia) == 2 and InstructionOp.get_operand(ia, 0) == ""\
            and InstructionOp.get_operand(ia,1) == "":
        return True
    # align 20h
    if InstructionOp.get_disasm_code(ia).startswith('align'):
        return True

    return False;

'''
trans the complement code to decimal
'''
def twos_complement_to_decimal(value, bits) -> int:
    # 如果符号位为1（最高位为1），则是负数
    if value & (1 << (bits - 1)):
        # 计算负数值: 减去 2^bits
        return value - (1 << bits)
    else:
        # 正数直接返回
        return value

'''
whether a string can be transed to int
'''
def is_safe_int(s):
    try:
        if s.startswith("0x") or s.startswith("0X") or (s.startswith("0") and len(s) > 1) or s.endswith('h'):
            int(s[:-1:], 16)  # 尝试十六进制转换
        else:
            int(s)  # 尝试十进制转换
        return True
    except ValueError:
        return False

'''
save to json file
'''
def save_to_json(file_path,data):
    with open(file_path,'w') as f:
        json.dump([instr.to_dict() for instr in data], f, indent=4)

'''
deal text segment

'''
def process():
    # start address of text
    input_file_name = ida_nalt.get_root_filename()
    Instruction_List = []
    Result_List = []
    kernel_analysis = False
    if input_file_name == "vmlinux4":
        print("kernel anlysis")
        kernel_analysis = True;
        text_segm = get_segm('.text')
        segm_start, segm_end = idc.get_segm_start(text_segm), idc.get_segm_end(text_segm)
        assert segm_start <= segm_end, 'Invalid Address Layout'
        '''
            idautils.Heads() return all of the instruction address in segm_start and segm_end
        '''
        for ia in idautils.Heads(segm_start, segm_end):
            # print(hex(ia));
            if is_skip_operation(ia):
                continue

            temp = Instruction(ia, InstructionOp.get_disasm_code(ia),
                               InstructionOp.get_op_of_the_instruction(ia),
                               InstructionOp.get_operand_count(ia),
                               InstructionOp.get_comments(ia),
                               [])
            Instruction_List.append(temp)
    else:
        print("common program anlysis")
        for func_start in idautils.Functions():
            if idc.get_segm_name(func_start) != '.text':
                continue;
            flag = idc.get_func_attr(func_start,idc.FUNCATTR_FLAGS)
            #skip libray and thunk
            if flag & idc.FUNC_LIB or flag & idc.FUNC_THUNK:
                continue
            func = ida_funcs.get_func(func_start)
            func_name = idc.get_func_name(func_start)
            #function ida does not recognize
            if func_name.startswith('sub_'):
                continue
            if func is not None:
                print(f"function start:{hex(func.start_ea)},function end:{hex(func.end_ea)},function_name:{func_name}")
                for ea in idautils.Heads(func.start_ea,func.end_ea):
                    print(hex(ea))
                    if is_skip_operation(ea):
                        continue
                    temp = Instruction(ea, InstructionOp.get_disasm_code(ea),
                                       InstructionOp.get_op_of_the_instruction(ea),
                                       InstructionOp.get_operand_count(ea),
                                       InstructionOp.get_comments(ea),
                                       [])
                    Instruction_List.append(temp)

    json_file_name = input_file_name + '.json'
    json_file_path = os.path.join(R'D:\Files\PythonCode\IdaVarviewer\JsonFile',json_file_name)
    save_to_json(json_file_path,Instruction_List)


    result_file_name = input_file_name + '_result' + '.json'
    result_file_path = os.path.join(R'D:\Files\PythonCode\IdaVarviewer\JsonFile',result_file_name)


    '''
    deal with the Instruction
    '''
    for ins in Instruction_List:
        print(ins)
        for index in range(ins.operand_count):
            # print(ins.address_16,ins.get_operand_info(index),ins.get_operand_type(index),ins.get_operand_type_num(index))
            #some operation like "idiv ecx" have two operand,get the first operand will return empty string "
            if ins.get_operand_info(index) == "":
                continue

            #skip the immediate operand
            elif ins.get_operand_type(index) == "Immediate Operand":
                continue
            #
            #             Register Operand
            #
            elif ins.get_operand_type(index) == "Register Operand":
                register_index = ins.get_operand_value(index)
                showed_register_name = ins.get_operand_info(index)
                flag,real_register_name = get_real_register_name(register_index,showed_register_name);
                real_register_name = '$' + real_register_name
                if flag:
                    match_pos = MatchPosition.dst_value if index == 0 else MatchPosition.src_value
                    temp_result = Result(name=ins.get_operand_info(index), addr=ins.address, expression=real_register_name,
                                         operand_type=ins.get_operand_type(index), matchPos=match_pos, indirect=0,
                                         dwarfType=DwarfType.MEMORY, variable_type=VariableType.MEM_CFA, offset=0)
                    Result_List.append(temp_result)
            #
            #          Direct Memory Reference
            #
            elif ins.get_operand_type(index) == "Direct Memory Reference":
                memory_address = ins.get_operand_value(index)
                #get_name return the name in the address
                showed_name:string = ida_name.get_name(memory_address )
                #the name can be data or func,we should only care about data
                if showed_name != "":
                    # start with __ and we are not in kernel, ignore it
                    if showed_name.startswith('__') and kernel_analysis == False:
                        continue
                    if(ida_funcs.get_func(memory_address ) == None):
                        #symbol and ,skip it
                            #print(f"变量:{showed_name}")
                            match_pos = MatchPosition.dst_value if index == 0 else MatchPosition.src_value
                            temp_result = Result(name = showed_name,addr=ins.address,expression=memory_address,operand_type=ins.get_operand_type(index),matchPos=match_pos,indirect=0,
                                                 dwarfType=DwarfType.MEMORY,variable_type=VariableType.MEM_CFA,offset=0
                                                 )
                            Result_List.append(temp_result)
                    else:
                        pass
            #
            #     Memory Ref, [Base Reg + Index Reg]
            #
            elif ins.get_operand_type(index) == "Memory Ref":
                showed_name:string = ins.get_operand_info(index)
                # remove the "*word ptr"
                if 'word' in showed_name and 'ptr' in showed_name:
                    showed_name = showed_name[showed_name.find('[')::]
                #one register  eg:[rax]
                if showed_name.startswith('[') and showed_name.endswith(']') and showed_name.find('+') == -1 and showed_name.find('-') == -1:
                   # remove [ ]
                   cursor = showed_name.find('[')
                   # screen showed name
                   showed_register_name = showed_name[cursor + 1::].replace(']', '')
                   register_index = ins.get_operand_value(index)
                   flag,real_register_name = get_real_register_name(register_index,showed_register_name)
                   if flag:
                     real_register_name = '($' + real_register_name + ')'
                     match_pos = MatchPosition.dst_addr if index == 0 else MatchPosition.src_addr
                     temp_result = Result(name = showed_register_name,addr=ins.address,expression=real_register_name,operand_type=ins.get_operand_type(index),matchPos=match_pos,indirect=0,
                                                 dwarfType=DwarfType.MEMORY,variable_type=VariableType.MEM_CFA,offset=0
                                              )
                     Result_List.append(temp_result)
            #
            #      "Memory Operand with Offset"  [Base Reg + Index Reg + Displacement]
            #
            elif ins.get_operand_type(index) == "Memory Operand with Offset":
                insn = ida_ua.insn_t()
                insnlen = ida_ua.decode_insn(insn, ins.address)
                pattern = r'^.+\[\w+\]$'
                showed_name = ins.get_operand_info(index)
                if 'word' in showed_name and 'ptr' in showed_name:
                    showed_name = showed_name[showed_name.find('[')::]
                #reg + displacement,one reg
                if showed_name.count('+') == 1:
                    cursor = ins.get_operand_info(index).find('+')
                    showed_displacement = showed_name[cursor+1::].replace(']','')
                    real_displacement = twos_complement_to_decimal(insn.ops[index].addr,64)
                    if real_displacement != 0 and not is_safe_int(showed_displacement):
                        #have a recorved name
                        register_name = ins.get_operand_info(index)[:cursor:].replace('[','')
                        if real_displacement < 0:
                            expression = '($' + register_name + str(real_displacement) + ')'
                        else:
                            expression = '($' + register_name + '+' +str(real_displacement) + ')'
                        match_pos = MatchPosition.dst_value if index == 0 else MatchPosition.src_value
                        temp_result = Result(name=showed_displacement, addr=ins.address, expression=expression,
                                             operand_type=ins.get_operand_type(index), matchPos=match_pos, indirect=0,
                                             dwarfType=DwarfType.MEMORY, variable_type=VariableType.MEM_CFA, offset=0
                                             )
                        Result_List.append(temp_result)
                # pgdir_shift[physbase]
                elif re.match(pattern,showed_name) is not None:
                        register_index = insn.ops[index].reg
                        showed_register_name = showed_name[showed_name.find('[')::].replace(']','')
                        showed_replacement: string = showed_name[:showed_name.find('['):]
                        flag,real_register_name = get_real_register_name(register_index,showed_register_name)
                        real_displacement = twos_complement_to_decimal(insn.ops[index].addr,64)
                        match_pos = MatchPosition.dst_value if index == 0 else MatchPosition.src_value
                        if real_displacement < 0:
                            expression = '($' + real_register_name + str(real_displacement) + ')'
                        else:
                            expression = '($' + real_register_name + '+' + str(real_displacement) + ')'
                        temp_result = Result(name=showed_replacement, addr=ins.address, expression=expression,
                                                     operand_type=ins.get_operand_type(index), matchPos=match_pos,
                                                     indirect=0,dwarfType=DwarfType.MEMORY, variable_type=VariableType.MEM_CFA,offset=0
                                                     )
                        Result_List.append(temp_result)
    '''
    outpust result into json format
    '''
    save_to_json(result_file_path,Result_List);



def main():
    process()


if __name__ == '__main__':
    main()
    print(1)
