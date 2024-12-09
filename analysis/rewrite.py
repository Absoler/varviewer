#!/usr/local/bin/python3
from iced_x86 import *
import sys
from elftools.elf.elffile import ELFFile
import angr
import os
from networkx.drawing.nx_pydot import write_dot
from util import *

def getBranch(ins:Instruction):
    if not (code_to_str[ins.code].startswith("JMP") or\
            code_to_str[ins.code].startswith("JN") or\
            code_to_str[ins.code].startswith("JE") or\
            code_to_str[ins.code].startswith("JA") or\
            code_to_str[ins.code].startswith("JB") or\
            code_to_str[ins.code].startswith("JG") or\
            code_to_str[ins.code].startswith("JL") or\
            code_to_str[ins.code].startswith("CALL")):
        return None
    if ins.op0_kind == OpKind.NEAR_BRANCH64 or \
        ins.op0_kind == OpKind.NEAR_BRANCH32 or\
        ins.op0_kind == OpKind.NEAR_BRANCH16:
        return ins.near_branch_target
    else:
        ''' op0_kind is REGISTER or MEMORY
        '''
        return -1

def construct(insts:list[Instruction], startpc:int, endpc:int) -> (str, list[int]):  # type: ignore
    length = sum([len(ins) for ins in insts])
    formatter = Formatter(FormatterSyntax.GAS)
    formatter.rip_relative_addresses = True
    formatter.gas_show_mnemonic_size_suffix = False
    prefix = """
.section .data
.section .text
.globl _start
_start:
"""
    postfix = """
end:
nop
"""
    offset = 0
    res = prefix

    label_map:dict[int, str] = {}
    addr_list:list[int] = []
    for ins in insts:
        target = getBranch(ins)
        if target and startpc <= target < endpc:
            label_map[target] = f"label_0x{target:X}"
        addr_list.append(ins.ip)

    for ins in insts:
        target = getBranch(ins)
        
        if ins.ip in label_map:
            res += f"{label_map[ins.ip]}:\n"
        if target:
            ins_str = mnemoic_to_str[ins.mnemonic]
            if startpc <= target < endpc:
                ins_str += f" label_0x{target:X}"
            else:
                ''' -1 or not in range [startpc, endpc)
                '''
                ins_str += f" end"
            res += ins_str + "\n"
        else:
            res += formatter.format(ins) + "\n"
    res += postfix
    return res, addr_list



if __name__ == "__main__":
    path = sys.argv[1]
    startpc, endpc = sys.argv[2], sys.argv[3]
    startpc = int(startpc, 16) if "0x" in startpc else int(startpc)
    endpc = int(endpc, 16) if "0x" in endpc else int(endpc)
    file = open(path, "rb")
    elf = ELFFile(file)
    text = elf.get_section_by_name(".text")
    code_addr = text['sh_addr']
    code = text.data()
    if len(code) == 0:
        code = text.stream.read()
        print("text.data() failed", file=sys.stderr)

    decoder = Decoder(64, code, ip=code_addr)
    

    insts = []
    lastip = 0
    for ins in decoder:
        if ins.ip >= endpc:
            break
        if ins.ip >= startpc:
            insts.append(ins)
        lastip = ins.ip
    
    assembly_code, _ = construct(insts, startpc, endpc)
    print(assembly_code)

    temp_name = "piece"
    with open(temp_name + ".S", "w") as piece_file:
        piece_file.write(assembly_code)
    ret = os.system(f"as {temp_name}.S -o {temp_name}.o && ld {temp_name}.o -Ttext 0 -o {temp_name}")
    if ret != 0:
        file.close()
        exit()

    proj = angr.Project(temp_name, load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFGFast()
    write_dot(cfg.graph, temp_name+".dot")
    os.system(f"dot {temp_name}.dot -T png -o {temp_name}.png")
    
    from libanalysis import traverse
    vex_file = open(temp_name+".vex", "w")
    traverse(proj, cfg, file=vex_file)
    vex0_file = open(temp_name+".vex.0", "w")
    traverse(proj, cfg, file=vex0_file, opt_level = 0)
    vex_file.close()
    vex0_file.close()
    
    file.close()


