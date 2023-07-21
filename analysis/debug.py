#!/usr/local/bin/python3

from rewrite import *
from variable import *
from libanalysis import *

binPath = sys.argv[1]

proj = angr.Project(binPath, load_options={'auto_load_libs' : False})

cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
analyzeCFG(cfg)

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
            vex_expr = get_z3_expr_from_vex(ir.data, node)
            vex_expr = post_format(vex_expr)
            
                
        elif isinstance(ir, pyvex.stmt.Store):
            vex_expr = get_z3_expr_from_vex(ir.data, node)
            vex_expr = post_format(vex_expr)
            vex_addr = get_z3_expr_from_vex(ir.addr, node)
            vex_addr = post_format(vex_addr)
            

        elif isinstance(ir, pyvex.stmt.WrTmp):
            if isinstance(ir.data, pyvex.expr.Load):
                vex_addr = get_z3_expr_from_vex(ir.data.addr, node)
                vex_addr = post_format(vex_addr)

        continue
