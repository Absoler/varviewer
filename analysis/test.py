#!/usr/local/bin/python3

from rewrite import *
from parse_mapping import *
from analysis import *


if __name__ == "__main__":
    mgr = VarMgr()
    jsonpath = "/home/varviewer/extracter/redis.json"
    mgr.load(jsonpath)

    addrExp = list(mgr.find(4505349, varName="plain", decl_file="/home/redis-stable/src/quicklist.c"))[0]
    

    proj = angr.Project(sys.argv[1], load_options={'auto_load_libs' : False})
    cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
    analyzeCFG(cfg)

    node = cfg.get_any_node(0)
    isMatch = match(node.block.vex.statements[34].data, addrExp, node)
    print(isMatch)