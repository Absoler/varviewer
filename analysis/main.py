#!/usr/local/bin/python3

from rewrite import *
from variable import *
from libanalysis import *
import shutil
import time
import argparse


def find_l_ind(insts:list[Instruction], ip:int):
    ''' find the the first index of insts that insts[index].ip >= ip
    [.. ip, ind ..]
    '''
    l, r = 0, len(insts)
    while l<r:
        mid = int((l+r)/2)
        if insts[mid].ip >= ip:
            r = mid
        else:
            l = mid+1
    return l



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binPath")
    parser.add_argument("jsonPath")
    parser.add_argument("-uC","--useCache", action='store_true')
    args = parser.parse_args()

    mgr = VarMgr()

    binPath = args.binPath
    jsonPath = args.jsonPath
    
    # prepare disassembly
    binFile = open(binPath, "rb")
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


    # prepare dwarf info
    mgr.load(jsonPath)

    # prepare pieces
    piece_limit = 1000000
    tempPath = "/tmp/varviewer/"
    useCache = args.useCache
    ''' if set `useCache`, means we have run this already
    '''
    if not useCache:
        if os.path.exists(tempPath):
            shutil.rmtree(tempPath)
        os.mkdir(tempPath)

    # start analysis

    
    for piece_num in range(mgr.local_ind, len(mgr.vars)):
        
        startTime = time.time()
        if piece_num > piece_limit + mgr.local_ind:
            break
        if piece_num < 100000:
            continue
        
        piece_name = tempPath + 'piece_' + str(piece_num)
        addrExp = mgr.vars[piece_num]
        startpc, endpc = addrExp.startpc, addrExp.endpc

        if not useCache or not os.path.exists(piece_name):     
            l, r = find_l_ind(all_insts, startpc), find_l_ind(all_insts, endpc)
            if l==r:
                continue
            piece_asm = construct(all_insts[l:r], startpc, endpc)
            with open(piece_name + ".S", "w") as piece_file:
                piece_file.write(piece_asm)
            ret = os.system(f"as {piece_name}.S -o {piece_name}.o && ld {piece_name}.o -Ttext 0 -o {piece_name}")
            if ret != 0:
                continue
        
        
        piece_file = open(piece_name, "rb")

        print(f"piece num {piece_num}")

        print(f"-- open piece {time.time()-startTime}")
        startTime = time.time()

        dwarf_hint = Hint()
        dwarf_expr = addrExp.get_Z3_expr(dwarf_hint)
        # solver.add(*dwarf_hint.conds)

        print(f"-- summary dwarf {time.time()-startTime}")
        startTime = time.time()

        proj = angr.Project(piece_file, load_options={'auto_load_libs' : False})
        cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
        analysis = Analysis(proj, cfg)
        analysis.analyzeCFG()

        print(f"-- analysis {time.time()-startTime}")
        startTime = time.time()

        reses = analysis.match(dwarf_expr)
        
        print(f"-- summary vex and match {time.time()-startTime}")
        startTime = time.time()
        

        for res in reses:
            res.update(startpc)
            print(res)

        piece_file.close()
        analysis.clear()

        

