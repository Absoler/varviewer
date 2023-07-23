from variable import *

import sys

jsonFile = sys.argv[1]
mgr = VarMgr()
mgr.load(jsonFile)

for i in range(mgr.local_ind, len(mgr.vars)):
    ''' find DW_OP_bregx 0 ; DW_OP_stack_value
    '''
    addrExp = mgr.vars[i]

    if addrExp.offset == 0 and addrExp.regs and not addrExp.mem and addrExp.type == 2:
        print(f"{addrExp.startpc} {addrExp.endpc}")