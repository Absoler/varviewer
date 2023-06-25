#!/usr/local/bin/python3
from iced_x86 import *
import sys
from elftools.elf.elffile import ELFFile
import angr
import os
from networkx.drawing.nx_pydot import write_dot

code_to_str = {Code.__dict__[key]:key for key in Code.__dict__ if isinstance(Code.__dict__[key], int)}
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
        print(f"{ins} {ins.op0_kind}")

def construct(insts:list[Instruction], startpc:int, endpc:int) -> str:
    length = sum([len(ins) for ins in insts])
    formatter = Formatter(FormatterSyntax.GAS)
    formatter.rip_relative_addresses = True
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
    for ins in insts:
        target = getBranch(ins)
        before = len(ins)
        if target and startpc <= target < endpc:
            
            ins.near_branch64 = target-startpc
        elif target:
            ins.near_branch64 = length
            # ins.near_branch64 = endpc
        after = len(ins)
        assert(before==after)
        res += formatter.format(ins) + "\n"
    res += postfix
    return res



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
    for ins in decoder:
        if ins.ip >= startpc:
            insts.append(ins)
        if ins.ip >= endpc:
            break
    
    assembly_code = construct(insts, startpc, endpc)
    print(assembly_code)

    temp_name = "my_assembly"
    with open(temp_name + ".s", "w") as as_file:
        as_file.write(assembly_code)
    ret = os.system(f"as {temp_name}.s -o {temp_name}.o && ld {temp_name}.o -Ttext 0 -o {temp_name}")
    if ret != 0:
        file.close()
        exit()

    proj = angr.Project(temp_name, load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFGFast()
    write_dot(cfg.graph, temp_name+".dot")
    os.system(f"dot {temp_name}.dot -T png -o {temp_name}.png")
    
    
    file.close()


