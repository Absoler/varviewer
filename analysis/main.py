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
    result = {}
    solver = Solver()
    for piece_num in range(mgr.local_ind, len(mgr.vars)):
        
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
        dwarf_hint = Hint()
        dwarf_expr = addrExp.get_Z3_expr(dwarf_hint)
        solver.add(*dwarf_hint.conds)


        proj = angr.Project(piece_file, load_options={'auto_load_libs' : False})
        cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
        analysis = Analysis(proj)
        analysis.analyzeCFG(cfg)

        nodes:list[angr.knowledge_plugins.cfg.cfg_node.CFGNode] = list(cfg.graph.nodes)
        for node in nodes:
            if node.block is None:
                continue
            
            blk = proj.factory.block(node.addr, opt_level=0)
            
            curAddr = -1
            for ir in blk.vex.statements:
                if isinstance(ir, pyvex.stmt.IMark):
                    curAddr = ir.addr
                    continue

                vex_expr:BitVecRef = None
                vex_addr:BitVecRef = None

                mapInfo:dict = {}

                if isinstance(ir, pyvex.stmt.Put):
                    if ir.offset not in vex_to_dwarf:
                        continue
                    vex_expr = analysis.get_z3_expr_from_vex(ir.data, blk)
                    vex_expr = post_format(vex_expr)
                    mapInfo["reg"] = vex_reg_names[ir.offset] if ir.offset in vex_reg_names else vex_reg_names[ir.offset-1]
                    mapInfo["tag"] = ir.tag
                        
                elif isinstance(ir, pyvex.stmt.Store):
                    vex_expr = analysis.get_z3_expr_from_vex(ir.data, blk)
                    vex_expr = post_format(vex_expr)
                    vex_addr = analysis.get_z3_expr_from_vex(ir.addr, blk)
                    vex_addr = post_format(vex_addr)
                    mapInfo["tag"] = ir.tag

                elif isinstance(ir, pyvex.stmt.WrTmp):
                    if isinstance(ir.data, pyvex.expr.Load):
                        vex_addr = analysis.get_z3_expr_from_vex(ir.data.addr, blk)
                        vex_addr = post_format(vex_addr)
                        mapInfo["tag"] = ir.tag

                # ''' adjust size of vex_addr and vex_expr to 64
                # '''
                # if vex_expr != None and vex_expr.size() < 64:
                #     old_size = vex_expr.size()
                #     vex_expr = SignExt(64-old_size, vex_expr) if isinstance(vex_expr, BitVecNumRef) else ZeroExt(64-old_size, vex_expr)
                # if vex_addr != None and vex_addr.size() < 64:
                #     old_size = vex_addr.size()
                #     vex_addr = SignExt(64-old_size, vex_addr) if isinstance(vex_addr, BitVecNumRef) else ZeroExt(64-old_size, vex_addr)

                # if vex_expr != None and vex_expr.size() > 64:
                #     vex_expr = Extract(63, 0, vex_expr)
                # if vex_addr != None and vex_addr.size() > 64:
                #     vex_addr = Extract(63, 0, vex_addr)

                solver.reset()
                solver.add(loads_cond)
                solver.add(loadu_cond)

                startTime = time.time()

                if addrExp.type == 0 and vex_addr != None:
                    ''' make assumptions
                    '''
                    conds = make_reg_type_conds(vex_addr)
                    solver.add(*conds)
                    solver.add(vex_addr != dwarf_expr)
                    

                    mapInfo["type"] = 0
                
                    if solver.check() == unsat:
                        if piece_num not in result:
                            result[piece_num] = []
                        result[piece_num].append(curAddr)
                        print(f"{curAddr+startpc:X} {addrExp.name} {mapInfo}")

                if addrExp.type == 1 and vex_expr != None:
                    pass
                


                if addrExp.type == 2 and vex_expr != None:
                    ''' make assumptions
                    '''

                    conds = make_reg_type_conds(vex_expr)
                    solver.add(*conds)
                    solver.add(vex_expr != dwarf_expr)

                    mapInfo["type"] = 2
                
                    if solver.check() == unsat:
                        if piece_num not in result:
                            result[piece_num] = []
                        result[piece_num].append(curAddr)
                        print(f"{curAddr+startpc:X} {addrExp.name} {mapInfo}")
            
                endTime = time.time()
                if endTime - startTime > 5:
                    print(f"use time {endTime - startTime}")
        piece_file.close()
    print(result)  

        

