#!/usr/local/bin/python3

from rewrite import *
from variable import *
from libanalysis import *


if __name__ == "__main__":
    mgr = VarMgr()
    jsonpath = "/home/varviewer/extracter/redis.json"
    mgr.load(jsonpath)

    # addrExp = mgr.getVar(4507560, 4507642, "node")
    # addrExp.restoreCFA(4507628)
    addrExp = mgr.vars[51187]

    proj = angr.Project(sys.argv[1], load_options={'auto_load_libs' : False})
    cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
    analyzeCFG(cfg)

    node = cfg.get_any_node(118)

    hint = Hint()
    dwarf_z3_expr:BitVecRef = addrExp.get_Z3_expr(hint)
    vex_z3_expr:BitVecRef = get_z3_expr_from_vex(node.block.vex.statements[20].data, node)
    print(f"dwarf:\n{simplify(dwarf_z3_expr)}\n\n{dwarf_z3_expr}\n")
    print(f"vex:\n{simplify(vex_z3_expr)}\n\n{vex_z3_expr}")
    
    reg_map = guess_reg_type(vex_z3_expr)

    ''' make assumptions
    '''
    regs:list[BitVecRef] = extract_regs_from_z3(dwarf_z3_expr)
    s = Solver()

    success = False
    
    s.add(dwarf_z3_expr!=vex_z3_expr)
    if s.check()==unsat:
        success = True
    else:
        
        conds = []
        for z3_reg in regs:
            if z3_reg.decl().name() not in reg_map:
                continue
            cond = cond_extract(z3_reg, reg_map[z3_reg.decl().name()])
            s.add(cond)
                  
    
    success = success or (s.check()==unsat)
    print(success)
    if not success:
        m = s.model()
        for z3_reg in regs:
            m.eval(z3_reg)
    