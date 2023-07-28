#!/usr/local/bin/python3

from rewrite import *
from variable import *
from libanalysis import *
from networkx.drawing.nx_pydot import write_dot
import os
binPath = sys.argv[1]

proj = angr.Project(binPath, load_options={'auto_load_libs' : False})
analysis = Analysis(proj)
cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
analysis.analyzeCFG(cfg)
write_dot(cfg.graph, binPath+".dot")
os.system(f"dot {binPath}.dot -T png -o {binPath}.png")

mgr = VarMgr()
if len(sys.argv) > 2:
    jsonPath = sys.argv[2]
    mgr.load(jsonPath)

nodes:list[angr.knowledge_plugins.cfg.cfg_node.CFGNode] = list(cfg.graph.nodes)
for node in nodes:
    if node.block is None:
        continue

    for i, ir in enumerate(node.block.vex.statements):
        if isinstance(ir, pyvex.stmt.IMark):
            continue

        vex_expr:BitVecRef = None
        vex_addr:BitVecRef = None

        mapInfo:dict = {}

        if isinstance(ir, pyvex.stmt.Put):
            if ir.offset not in vex_to_dwarf:
                continue
            vex_expr = analysis.get_z3_expr_from_vex(ir.data, proj.factory.block(node.addr, opt_level=0))
            vex_expr = post_format(vex_expr)
            
                
        elif isinstance(ir, pyvex.stmt.Store):
            vex_expr = analysis.get_z3_expr_from_vex(ir.data, proj.factory.block(node.addr, opt_level=0))
            vex_expr = post_format(vex_expr)
            vex_addr = analysis.get_z3_expr_from_vex(ir.addr, proj.factory.block(node.addr, opt_level=0))
            vex_addr = post_format(vex_addr)
            

        elif isinstance(ir, pyvex.stmt.WrTmp):
            if isinstance(ir.data, pyvex.expr.Load):
                vex_addr = analysis.get_z3_expr_from_vex(ir.data.addr, proj.factory.block(node.addr, opt_level=0))
                vex_addr = post_format(vex_addr)

        continue
