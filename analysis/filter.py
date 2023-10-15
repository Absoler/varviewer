from util import *
from variable import AddressExp
import bisect

class Filter:
    def __init__(self, prefixStr:str = "", focusPath:str = "") -> None:
        self.prefixStr = "" if len(prefixStr) == 0 else os.path.normpath(prefixStr)
        
        self.focusPath = focusPath
        self.focuses:list[list] = []
        self.build_focus_addresses()

    def build_focus_addresses(self):
        if len(self.focusPath) == 0:
            return
        
        with open(self.focusPath, "r") as focusFile:
            lines = focusFile.readlines()
            lines.pop(0)
            self.focuses
            for line in lines:
                self.focuses.append(list(map(lambda addr: int(addr, 16), line.split())))
                # self.focuses[-1].sort()
        # sort by start address
        sorted(self.focuses, key=lambda lst:lst[0])
        # merge intersecting address intervals
        dead_ids = []
        for i in range(len(self.focuses)):
            max_l = self.focuses[i][-1]
            r = max_l
            for j in range(i+1, len(self.focuses)):
                if self.focuses[j][0] <= max_l:
                    dead_ids.append(j)
                    r = max(r, self.focuses[j][-1])
            self.focuses[i][-1] = r
        self.focuses = [ self.focuses[i] for i in range(len(self.focuses)) if i not in dead_ids ]


    def valid(self, addrExp:AddressExp) -> bool:
        if self.prefixStr and not addrExp.decl_file.startswith(self.prefixStr):
            return False
        
        if len(self.focuses) == 0:
            return True
        
        ''' addrExp's range should include focus range
        '''
        ind = bisect.bisect_right(self.focuses, addrExp.startpc, key=lambda lst:lst[0]) - 1
        return ind != -1 and self.focuses[ind][-1] <= addrExp.endpc
        

