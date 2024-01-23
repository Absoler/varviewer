#!/usr/local/bin/python3
import sys, shutil, os
sys.path.append(f"{os.getcwd()}/..")
from libanalysis import Analysis
from variable import *
from libresult import *
from rewrite import *
import json


# ----------------------------------------
#   test cases:
#   1 register expand expansion
#   1 multi memory
#   2 CFA
#   2 single
#   2 register parameter
#   2 other register
#   2 implicit
# ----------------------------------------

care_keys = ["addr", "name", "matchPos", "indirect", "dwarfType", "detailedDwarfType", "offset"]

if __name__ == "__main__":
    binpath = sys.argv[1]   # set path of built `vmlinux`
    binfile = open(binpath, "rb")
    elf = ELFFile(binfile)
    text = elf.get_section_by_name(".text")
    code_addr = text['sh_addr']
    code = text.data()
    if len(code) == 0:
        code = text.stream.read()
        print("text.data() failed", file=sys.stderr)

    decoder = Decoder(64, code, ip=code_addr)
    all_insts:list[Instruction] = []
    for ins in decoder:
        all_insts.append(ins)
    
    # load variable info
    mgr = VarMgr()
    mgr.load("linux_var.json")

    # load test oracle
    with open("linux_ans.json", "r") as ans_file:
        ans:dict = json.load(ans_file)

    temppath = "/tmp/test"
    if os.path.exists(temppath):
        shutil.rmtree(temppath)
    os.mkdir(temppath)

    # init test result
    testres = { i.value : [0, 0] for i in DetailedDwarfType}
    for var in mgr.vars:
        testres[var.detailedDwarfType.value][1] += 1
    
    for piece_num in range(len(mgr.vars)):
        piece_name:str = temppath + "/piece_" + str(piece_num)
        addrexp = mgr.vars[piece_num]
        startpc, endpc = addrexp.startpc, addrexp.endpc

        l, r = find_l_ind(all_insts, startpc), find_l_ind(all_insts, endpc)
        if l==r:
            continue
        piece_asm, piece_addrs = construct(all_insts[l:r], startpc, endpc)
        with open(piece_name + ".S", "w") as piece_asm_file:
            piece_asm_file.write(piece_asm)
        with open(piece_name + ".addr", "w") as piece_addr_file:
            piece_addr_file.write(' '.join(map(str, piece_addrs)))
        ret = os.system(f"as {piece_name}.S -o {piece_name}.o && ld {piece_name}.o -Ttext 0 -o {piece_name}")
        if ret != 0:
            continue
        
        piece_file = open(piece_name, "rb")
        proj = angr.Project(piece_file, load_options={'auto_load_libs' : False})
        cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
        analysis = Analysis(proj, cfg)
        analysis.analyzeCFG()

        reses = analysis.match(addrexp, DwarfType(addrexp.dwarfType), piece_addrs, True, False)
        piece_file.close()


        for res in reses:
            success = True

            if res.name not in ans:
                continue

            res_dict = dict(res)
            for key in care_keys:
                if res_dict[key] != ans[res.name][key]:
                    success = False
                    break
                    
            if success:
                testres[res.detailedDwarfType.value][0] += 1
    
    print(f"test result:")
    for t in DetailedDwarfType:
        print(f"{t}:    {testres[t.value][0]}/{testres[t.value][1]}")

        