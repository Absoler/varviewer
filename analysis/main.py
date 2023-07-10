#!/usr/local/bin/python3

from rewrite import *
from variable import *
from libanalysis import *
import shutil


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
    mgr = VarMgr()

    binPath = sys.argv[1]
    jsonPath = sys.argv[2]
    
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
    useCache = True
    if not useCache:
        if os.path.exists(tempPath):
            shutil.rmtree(tempPath)
        os.mkdir(tempPath)
        for piece_num in range(mgr.local_ind, len(mgr.vars)):
            addrExp = mgr.vars[piece_num]
            if piece_num > piece_limit + mgr.local_ind:
                break

            piece_name = tempPath + 'piece_' + str(piece_num)
            startpc, endpc = addrExp.startpc, addrExp.endpc
            l, r = find_l_ind(all_insts, startpc), find_l_ind(all_insts, endpc)
            if l==r:
                continue
            piece_asm = construct(all_insts[l:r], startpc, endpc)
            with open(piece_name + ".S", "w") as piece_file:
                piece_file.write(piece_asm)
            ret = os.system(f"as {piece_name}.S -o {piece_name}.o && ld {piece_name}.o -Ttext 0 -o {piece_name}")
            if ret != 0:
                pass

    # start analysis
    result = {}
    for piece_num in range(mgr.local_ind, len(mgr.vars)):
        
        if piece_num > piece_limit + mgr.local_ind:
            break
        
        piece_name = tempPath + 'piece_' + str(piece_num)
        if not os.path.exists(piece_name):
            continue
        piece_file = open(piece_name, "rb")

        addrExp = mgr.vars[piece_num]
        dwarf_expr = addrExp.get_Z3_expr()


        proj = angr.Project(piece_file, load_options={'auto_load_libs' : False})
        cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
        analyzeCFG(cfg)

        nodes:list[angr.knowledge_plugins.cfg.cfg_node.CFGNode] = list(cfg.graph.nodes)
        for node in nodes:
            if node.block is None:
                continue

            curAddr = -1
            for ir in node.block.vex.statements:
                if isinstance(ir, pyvex.stmt.IMark):
                    curAddr = ir.addr
                    continue

                vex_expr:BitVecRef = None
                vex_addr:BitVecRef = None

                if isinstance(ir, pyvex.stmt.Put):
                    vex_expr = get_z3_expr_from_vex(ir.data, node)

                elif isinstance(ir, pyvex.stmt.Store):
                    vex_expr = get_z3_expr_from_vex(ir.data, node)
                    vex_addr = get_z3_expr_from_vex(ir.addr, node)

                elif isinstance(ir, pyvex.stmt.WrTmp):
                    if isinstance(ir.data, pyvex.expr.Load):
                        vex_addr = get_z3_expr_from_vex(ir.data.addr, node)

                ''' adjust size of vex_addr and vex_expr to 64
                '''
                if vex_expr != None and vex_expr.size() < 64:
                    old_size = vex_expr.size()
                    vex_expr = SignExt(64-old_size, vex_expr) if isinstance(vex_expr, BitVecNumRef) else ZeroExt(64-old_size, vex_expr)
                if vex_addr != None and vex_addr.size() < 64:
                    old_size = vex_addr.size()
                    vex_addr = SignExt(64-old_size, vex_addr) if isinstance(vex_addr, BitVecNumRef) else ZeroExt(64-old_size, vex_addr)

                solver = Solver()
                if addrExp.type == 0 and vex_addr != None:
                    ''' make assumptions
                    '''
                    reg_map = guess_reg_type(vex_addr)
                    z3_regs:list[BitVecRef] = extract_regs_from_z3(vex_addr)
                    for z3_reg in z3_regs:
                        if z3_reg.decl().name() not in reg_map:
                            continue
                        cond = cond_extract(z3_reg, reg_map[z3_reg.decl().name()])
                        solver.add(cond)
                        if z3_reg.size() < 64:
                            solver.add(SignExt(64-z3_reg.size(), z3_reg)==BitVec(z3_reg.decl().name(), 64))

                    solver.add(vex_addr != dwarf_expr)
                
                    if solver.check() == unsat:
                        if piece_num not in result:
                            result[piece_num] = []
                        result[piece_num].append(curAddr)
                        print(f"{curAddr} {addrExp.name}")

                if addrExp.type == 1 and vex_expr != None:
                    pass
                


                if addrExp.type == 2 and vex_expr != None:
                    ''' make assumptions
                    '''
                    reg_map = guess_reg_type(vex_expr)
                    z3_regs:list[BitVecRef] = extract_regs_from_z3(vex_expr)
                    for z3_reg in z3_regs:
                        if z3_reg.decl().name() not in reg_map:
                            continue
                        cond = cond_extract(z3_reg, reg_map[z3_reg.decl().name()])
                        solver.add(cond)
                        if z3_reg.size() < 64:
                            solver.add(SignExt(64-z3_reg.size(), z3_reg)==BitVec(z3_reg.decl().name(), 64))

                    solver.add(vex_expr != dwarf_expr)
                
                    if solver.check() == unsat:
                        if piece_num not in result:
                            result[piece_num] = []
                        result[piece_num].append(curAddr)
                        print(f"{curAddr} {addrExp.name}")
            
        piece_file.close()
    print(result)  

        

