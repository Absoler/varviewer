from variable import *

import sys

jsonFile = sys.argv[1]
mgr = VarMgr()
mgr.load(jsonFile)

for i in range(mgr.local_ind, len(mgr.vars)):
    ''' find DW_OP_bregx 0 ; DW_OP_stack_value
    '''
    addrExp = mgr.vars[i]

    if addrExp.decl_file == "/home/linux-6.0-rc6/lib/radix-tree.c" and addrExp.name == "rtp":
        with open("t", "a") as f:
            json.dump(dict(addrExp), f, indent=4)