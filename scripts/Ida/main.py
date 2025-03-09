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
import  ida_loader
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
    input_file_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    input_file_dir = os.path.dirname(input_file_path)
    # print(f"input file path : {input_file_path}")
    json_file_path = os.path.join(input_file_dir,json_file_name)
    save_to_json(json_file_path,Instruction_List)

    result_file_name = input_file_name + '_result' + '.json'
    result_file_path = os.path.join(input_file_dir,result_file_name)
    print(f"JSON file path: {json_file_path}")
    print(f"Result file path: {result_file_path}")

    '''
    deal with the Instruction
    '''
    global_cnt:int = 0
    for ins in Instruction_List:
        print(ins)
        for index in range(ins.operand_count):
            # print(ins.address_16,ins.get_operand_info(index),ins.get_operand_type(index),ins.get_operand_type_num(index))
            #some operation like "idiv ecx" have two operand,get the first operand will return empty string "
            if ins.get_operand_info(index) == "" or ins.get_operand_info(index).startswith("ds:"):
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
                    temp_result = Result(name=ins.get_operand_info(index), addr=ins.address, expression=real_register_name,matchPos=match_pos,operand_type=ins.get_operand_type(index))
                    Result_List.append(temp_result)
            #
            #          Direct Memory Reference
            #
            # elif ins.get_operand_type(index) == "Direct Memory Reference":
            #     global_cnt += 1
            #     memory_address = ins.get_operand_value(index)
            #     #get_name return the name in the address
            #     showed_name:string = ida_name.get_name(memory_address )
            #     #the name can be data or func,we should only care about data
            #     if showed_name != "":
            #         # start with __ and we are not in kernel, ignore it
            #         if showed_name.startswith('__') and kernel_analysis == False:
            #             continue
            #         if(ida_funcs.get_func(memory_address ) == None):
            #             #symbol and ,skip it
            #                 #print(f"变量:{showed_name}")
            #                 match_pos = MatchPosition.dst_value if index == 0 else MatchPosition.src_value
            #                 temp_result = Result(name = showed_name,addr=ins.address,expression=memory_address,operand_type=ins.get_operand_type(index),matchPos=match_pos,indirect=0,
            #                                      dwarfType=DwarfType.MEMORY,variable_type=VariableType.MEM_CFA,offset=0
            #                                      )
            #                 Result_List.append(temp_result)
            #         else:
            #             pass
            #
            #     Memory Ref, [Base Reg + Index Reg]
            #
            elif ins.get_operand_type(index) == "Memory Ref":
                showed_name:string = ins.get_operand_info(index)
                # remove the "*word ptr"
                if 'word' in showed_name and 'ptr' in showed_name:
                    showed_name = showed_name[showed_name.find('[')::]
                add_count = showed_name.count('+')
                sub_count = showed_name.count('-')
                mul_count = showed_name.count('*')
                #one register  eg:[rax]
                if add_count == 0 and sub_count == 0:
                   # remove [ ]
                   cursor = showed_name.find('[')
                   # screen showed name
                   showed_register_name = showed_name[cursor + 1::].replace(']', '')
                   register_index = ins.get_operand_value(index)
                   flag,real_register_name = get_real_register_name(register_index,showed_register_name)
                   if flag:
                     real_register_name = '($' + real_register_name + ')'
                     match_pos = MatchPosition.dst_value if index == 0 else MatchPosition.src_value
                     temp_result = Result(name = showed_register_name,addr=ins.address,expression=real_register_name,operand_type=ins.get_operand_type(index),matchPos=match_pos)
                     Result_List.append(temp_result)
                #[rbx + rax]
                elif add_count + sub_count == 1 and mul_count == 0:
                    pass
                #[rbx + 4 * rax]
                elif add_count + sub_count == 1 and mul_count == 1:
                    pass
                #[rsp + 60h + mgsbuf] msgbuf = -60h
                elif add_count + sub_count == 2 and mul_count == 0:
                    pass
                else:
                    # in deed this four branch is not necessary,
                    # because this can not map to a variable in source
                    # i just use this to record the format may occur
                    pass

            #
            #      "Memory Operand with Offset"  [Base Reg + Index Reg + Displacement]
            #
            elif ins.get_operand_type(index) == "Memory Operand with Offset":
                insn = ida_ua.insn_t()
                insnlen = ida_ua.decode_insn(insn, ins.address)
                showed_name = ins.get_operand_info(index)
                if 'word' in showed_name and 'ptr' in showed_name:
                    showed_name = showed_name[showed_name.find('[')::]
                if 'byte' in showed_name and 'ptr' in showed_name:
                    showed_name = showed_name[showed_name.find('[')::]

                add_count = showed_name.count('+')
                sub_count = showed_name.count('-')
                mul_count = showed_name.count('*')
                # reg + displacement,one reg [rsp + var_30]
                if add_count == 1 and sub_count == 0 and mul_count == 0:
                    cursor = ins.get_operand_info(index).find('+')
                    showed_displacement = showed_name[cursor+1::].replace(']','')
                    real_displacement = twos_complement_to_decimal(insn.ops[index].addr,64)
                    register_index = insn.ops[index].reg
                    if real_displacement != 0 and not is_safe_int(showed_displacement):
                        #have a recorved name
                        flag,register_name = get_real_register_name(register_index,'')
                        if real_displacement < 0:
                            expression = '($' + register_name + str(real_displacement) + ')'
                        else:
                            expression = '($' + register_name + '+' +str(real_displacement) + ')'
                        match_pos = MatchPosition.dst_value if index == 0 else MatchPosition.src_value
                        temp_result = Result(name=showed_displacement, addr=ins.address, expression=expression,
                                             operand_type=ins.get_operand_type(index), matchPos=match_pos)
                        Result_List.append(temp_result)
                #[rdi + rbp * 8 + 8] [rsp + 0A8H + var_28 + 4]
                elif add_count + sub_count >= 2 and (mul_count >= 1 or mul_count == 0):
                        #以 + - 分割
                        showed_name = showed_name.strip("[]")
                        match = re.search(r'[+-]',showed_name)
                        if match:
                            showed_name = showed_name[match.start()+1:]
                        parts = re.split(r'[+-]',showed_name)
                        # 去除空字符串并去除两端空格
                        parts = [p.strip() for p in parts if p.strip()]
                        register_index = insn.ops[index].reg
                        real_displacement = twos_complement_to_decimal(insn.ops[index].addr,64)
                        if real_displacement != 0:
                           for part in parts:
                              if part.count('*') != 0:
                                  continue

                              if not is_safe_int(part):
                                  flag,register_name = get_real_register_name(register_index,'')
                                  if real_displacement < 0:
                                    expression = '($' + register_name + str(real_displacement) + ')'
                                  else:
                                    expression = '($' + register_name + '+' + str(real_displacement) + ')'
                                  match_pos = MatchPosition.dst_value if index == 0 else MatchPosition.src_value
                                  temp_result = Result(name=part, addr=ins.address, expression=expression,
                                                   operand_type=ins.get_operand_type(index), matchPos=match_pos)
                                  Result_List.append(temp_result)
                # pgdir_shift[physbase]
                elif add_count == 0 and sub_count == 0:
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
                                                     operand_type=ins.get_operand_type(index), matchPos=match_pos)
                        Result_List.append(temp_result)
    '''
    outpust result into json format
    '''
    Result_List = [x for x in Result_List if x.name != ""  and not x.name.startswith("var_") and not x.name.startswith("arg_")]
    print(f"Total Result Num : {len(Result_List)}")
    save_to_json(result_file_path,Result_List);



def main():
    process()


if __name__ == '__main__':
    main()
    print("extract over")