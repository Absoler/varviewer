#!/usr/local/bin/python3

from rewrite import *
from variable import *
from libanalysis import *

'''
    use for testing a single variable, so prepare
    1. a single json file only containing the variable dwarf info
    2. complete executable
'''

def err(info:str = ""):
    print(f"error at {info}", file=sys.stderr)
    exit(1)

if __name__ == "__main__":

    # prepare dwarf expression
    mgr = VarMgr()
    jsonpath = "test.json" if len(sys.argv) <= 2 else sys.argv[2]
    mgr.load(jsonpath)
    addrExp = mgr.vars[0]

    # prepare disassembly
    binFile = open(sys.argv[1], "rb")
    elf = ELFFile(binFile)
    text = elf.get_section_by_name(".text")
    code_addr = text['sh_addr']
    code = text.data()
    if len(code) == 0:
        code = text.stream.read()
        print("text.data() failed", file=sys.stderr)

    decoder = Decoder(64, code, ip=code_addr)
    all_insts:Instruction = []
    for ins in decoder:
        all_insts.append(ins)
        
    piece_name = "/tmp/piece"
    startpc, endpc = addrExp.startpc, addrExp.endpc
    l, r = find_l_ind(all_insts, startpc), find_l_ind(all_insts, endpc)
    piece_asm, piece_addrs = construct(all_insts[l:r], startpc, endpc)
    with open(piece_name + ".S", "w") as piece_as_file:
        piece_as_file.write(piece_asm)
    
    ret = os.system(f"as {piece_name}.S -o {piece_name}.o && ld {piece_name}.o -Ttext 0 -o {piece_name}")
    if ret != 0:
        err("as and ld")
    
    piece_file = open(piece_name, "rb")
    proj = angr.Project(piece_file, load_options={'auto_load_libs' : False})
    cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
    analysis:Analysis = Analysis(proj, cfg)
    analysis.analyzeCFG()

    reses = analysis.match(addrExp, DwarfType(addrExp.type), piece_addrs, True, True)

    all_reses = []
    for res in reses:
        res.construct_expression(all_insts[find_l_ind(all_insts, res.addr)])
        print(res.__str__())
        print(json.dumps(dict(res), indent=4))