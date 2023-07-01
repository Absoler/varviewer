#!/usr/local/bin/python3


import pyvex
import angr
import sys
from processVEX import register_names
from analysis import traverse

def count_written_regs(irsb:pyvex.IRSB):
    res = {}
    for ir in irsb.statements:
        if isinstance(ir, pyvex.stmt.Put) or isinstance(ir, pyvex.stmt.PutI):
            if ir.offset not in res:
                res[ir.offset] = 0
            res[ir.offset] += 1
    return res

p = angr.Project(sys.argv[1], load_options={'auto_load_libs':False})
cfg = p.analyses.CFGFast()

nodes:list[angr.knowledge_plugins.cfg.cfg_node.CFGNode] = list(cfg.graph.nodes)

cnt_0, cnt_1 = {}, {}

for node in nodes:
    if node.block is None:
        continue
    blk = p.factory.block(node.addr, opt_level=0)
    cnt = count_written_regs(blk.vex)
    for reg in cnt:
        if reg in cnt_0:
            cnt_0[reg] += cnt[reg]
        else:
            cnt_0[reg] = cnt[reg]
    
    blk = p.factory.block(node.addr, opt_level=1)
    cnt = count_written_regs(blk.vex)
    for reg in cnt:
        if reg in cnt_1:
            cnt_1[reg] += cnt[reg]
        else:
            cnt_1[reg] = cnt[reg]

keys = set(list(cnt_0.keys()) + list(cnt_1.keys()))
print(f"diff between opt0 and opt1")
for reg in keys:
    num0 = cnt_0[reg] if reg in cnt_0 else 0
    num1 = cnt_1[reg] if reg in cnt_1 else 0
    if num0 == num1:
        continue
    print(f"{register_names[reg]} written times of opt0 {num0} and opt1 {num1}")