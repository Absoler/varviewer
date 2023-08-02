#!/usr/local/bin/python3

from rewrite import *
from variable import *
from libanalysis import *
from networkx.drawing.nx_pydot import write_dot
import os
binPath = sys.argv[1]

proj = angr.Project(binPath, load_options={'auto_load_libs' : False})
cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
analysis = Analysis(proj, cfg)
analysis.analyzeCFG()
write_dot(cfg.graph, binPath+".dot")
os.system(f"dot {binPath}.dot -T png -o {binPath}.png")

mgr = VarMgr()
if len(sys.argv) > 3:
    jsonPath = sys.argv[2]
    mgr.load(jsonPath)
    addrExp = mgr.vars[int(sys.argv[3])]
    addrExp.is_const()

    hint = Hint()
    dwarf_exp = addrExp.get_Z3_expr(hint)

    reses = analysis.match(dwarf_exp, addrExp.type, False)

    print(reses)