#!/usr/local/bin/python3

from rewrite import *
from variable import *
from analysis import *


if __name__ == "__main__":
    mgr = VarMgr()
    jsonpath = "/home/varviewer/extracter/redis.json.bak"
    mgr.load(jsonpath)

    addrExp = mgr.getVar(4507560, 4507642, "node")
    addrExp.restoreCFA(4507628)
    # addrExp = mgr.getVar(4522020, 4522024, "idx")

    # proj = angr.Project(sys.argv[1], load_options={'auto_load_libs' : False})
    # cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
    # analyzeCFG(cfg)

    # node = cfg.get_any_node(0)

    # dwarf_z3_expr:BitVecRef = addrExp.get_Z3_expr()
    # vex_z3_expr:BitVecRef = get_z3_expr_from_vex(node.block.vex.statements[15].data, node)
    # print(f"dwarf:\n{simplify(dwarf_z3_expr)}\n\n{dwarf_z3_expr}\n")
    # print(f"vex:\n{simplify(vex_z3_expr)}\n\n{vex_z3_expr}")
    

    # ''' make assumptions
    # '''
    # regs:list[BitVecRef] = extract_regs_for_dwarf(dwarf_z3_expr)
    # s = Solver()
    # conds = []
    # for reg in regs:
    #     # cond = BitVec(reg, 64) == Concat(BitVecVal(0, 32), Extract(31,0,BitVec(reg, 64)))
    #     cond = And(BitVec(reg, 64) <= 0xffffffff, BitVec(reg, 64) >= 0)
                  
    #     s.add(cond)
    
    # s.add(dwarf_z3_expr!=vex_z3_expr)
    # # solve(*conds, dwarf_z3_expr!=vex_z3_expr)
    # print(s.check())
    
    