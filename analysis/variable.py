#!/usr/local/bin/python3
from bisect import bisect_right
import sys
import json
from iced_x86 import *
from dwarf_iced_map import iced_dwarf_regMap, dwarf_iced_regMap, dwarf_reg_names
import ctypes
from dwarf_vex_map import *
from z3 import *
from hint import Hint
from util import *

from libanalysis import load_funcs


class Expression:
    '''
    {
        "offset" : <Dwarf_Unsigned>
        "regs" : {
            <int>(reg_ind) : <int>(scale),
        }
        "mem" : <Expression>
        "mem_size" : <Dwarf_Small>
        "valid" : <bool>
        "empty" : <bool>
        "sign" : <bool>

        "hasChild" : <bool>
        "sub1" : <Expression>
        "sub2" : <Expression>
        "op" : <Dwarf_Unsigned>

        "isCFA" : <Bool>
    }
    '''
    def __init__(self, jsonExp:dict = {}) -> None:
        if jsonExp:
            self.sign:bool = jsonExp["sign"]
            self.offset:int = jsonExp["offset"] if not self.sign else ctypes.c_int64(jsonExp["offset"]).value
            self.regs = jsonExp["regs"]
            if self.regs:
                self.regs:dict = {int(reg) : self.regs[reg] for reg in self.regs}
            self.mem:Expression = Expression(jsonExp=jsonExp["mem"]) if "mem" in jsonExp else None
            self.mem_size:int = jsonExp["mem_size"] if "mem_size" in jsonExp else 64
            # self.valid:bool = jsonExp["valid"] # only record valid one
            self.empty:bool = jsonExp["empty"]

            self.hasChild:bool = jsonExp["hasChild"]
            if self.hasChild:
                self.sub1:Expression = Expression(jsonExp=jsonExp["sub1"])
                self.sub1.father = self
            else:
                self.sub1 = None
            if "sub2" in jsonExp:
                self.sub2:Expression = Expression(jsonExp=jsonExp["sub2"])
                self.sub2.father = self
            else:
                self.sub2 = None
            self.op:int = jsonExp["op"] if self.hasChild else None
            self.isCFA:bool = jsonExp["isCFA"]
            self.father = None

        else:
            self.sign:bool = False
            self.offset:int = 0
            self.regs = {}
            self.mem:Expression = None
            self.mem_size:int = 64
            # self.valid:bool = True
            self.empty:bool = False

            self.hasChild:bool = False
            self.sub1 = None
            self.sub2 = None
            self.op = None

            self.isCFA:bool = False
            self.father = None
    
    def setExprFrom(self, exp):
        self.sign = exp.sign
        self.offset = exp.offset
        self.regs = copy.copy(exp.regs)
        self.mem = exp.mem
        self.mem_size = exp.mem_size
        
        self.hasChild = exp.hasChild
        self.sub1 = exp.sub1
        self.sub2 = exp.sub2
        self.op = exp.op

        self.isCFA = exp.isCFA
        self.father = exp.father
        
    def add(self, other):
        ''' only valid if simple expression
        '''
        res = type(self)()
        res.offset = self.offset + other.offset
        for reg in self.regs:
            res.regs[reg] = self.regs[reg]
        
        for reg in other.regs:
            if reg in res.regs:
                res.regs[reg] += other.regs[reg]
            else:
                res.regs[reg] = other.regs[reg]

    def sub(self, other):
        ''' only valid if simple expression
        '''
        res = type(self)()
        res.offset = self.offset - other.offset
        for reg in self.regs:
            res.regs[reg] = self.regs[reg]
        
        for reg in other.regs:
            if reg in res.regs:
                res.regs[reg] -= other.regs[reg]
            else:
                res.regs[reg] = -other.regs[reg]

    def getAllnodes(self) -> list:
        res = [self]
        if self.mem:
            res.extend(self.mem.getAllnodes())
        
        if self.sub1:
            res.extend(self.sub1.getAllnodes())
        
        if self.sub2:
            res.extend(self.sub2.getAllnodes())

        return res


    def is_const(self):
        res = (self.regs == None and self.mem == None and not self.empty)
        if self.hasChild:
            res = res and self.sub1.is_const()
            res = res and self.sub2.is_const() if self.sub2 != None else res
        return res
    
    def is_reg(self):
        return self.regs is not None and self.offset == 0 and self.mem == None
    
    def isMem(self):
        return self.mem != None and self.offset == 0  and self.regs == None
    
    def get_Z3_expr(self, hint:Hint) -> BitVecRef:
    
        if self.hasChild:
            if self.op == DW_OP_abs:
                return Abs(self.sub1.get_Z3_expr(hint))
            
            elif self.op == DW_OP_neg:
                return -(self.sub1.get_Z3_expr(hint))
            
            elif self.op == DW_OP_not:
                return ~(self.sub1.get_Z3_expr(hint))
            
            elif self.op == DW_OP_and:
                exp1, exp2 = self.sub1.get_Z3_expr(hint), self.sub2.get_Z3_expr(hint)

                ''' add hints for `and 0xff..`
                '''
                if isinstance(exp1, BitVecNumRef) or isinstance(exp2, BitVecNumRef):
                    const = int(exp1.params()[0]) if isinstance(exp1, BitVecNumRef) else int(exp2.params()[0])
                    other = exp2 if isinstance(exp1, BitVecNumRef) else exp1
                    if const & (const-1) == 0:
                        hint.add(ULE(other, const))
                
                return exp1 & exp2

            
            elif self.op == DW_OP_or:
                return self.sub1.get_Z3_expr(hint) | self.sub2.get_Z3_expr(hint)
            
            elif self.op == DW_OP_xor:
                return self.sub1.get_Z3_expr(hint) ^ self.sub2.get_Z3_expr(hint)
            
            elif self.op == DW_OP_div:
                dividend = self.sub2.get_Z3_expr(hint)
                divisor = self.sub1.get_Z3_expr(hint)
                # integer signed division
                return If( And(dividend>0, divisor<0), (dividend-1)/divisor-1,
                          If(And(dividend<0, divisor>0), (dividend+1)/divisor-1,
                             dividend/divisor)) 
            
            elif self.op == DW_OP_mod:
                return self.sub2.get_Z3_expr(hint) % self.sub1.get_Z3_expr(hint)

            elif self.op == DW_OP_minus:
                return self.sub2.get_Z3_expr(hint) - self.sub1.get_Z3_expr(hint)
            
            elif self.op == DW_OP_plus or self.op == DW_OP_plus_uconst:
                return self.sub1.get_Z3_expr(hint) + self.sub2.get_Z3_expr(hint)

            elif self.op == DW_OP_mul:
                return self.sub1.get_Z3_expr(hint) * self.sub2.get_Z3_expr(hint)
            
            elif self.op == DW_OP_shl:
                return self.sub2.get_Z3_expr(hint) << self.sub1.get_Z3_expr(hint)
            
            elif self.op == DW_OP_shr:
                ''' 
                '''
                return LShR(self.sub2.get_Z3_expr(hint), self.sub1.get_Z3_expr(hint))

            elif self.op == DW_OP_shra:
                return self.sub2.get_Z3_expr(hint) >> self.sub1.get_Z3_expr(hint)

            elif self.op == DW_OP_eq:
                exp1, exp2 = self.sub1.get_Z3_expr(hint), self.sub2.get_Z3_expr(hint)
                return If(exp2==exp1, BitVecVal(1, 64), BitVecVal(0, 64))
            
            elif self.op == DW_OP_ge:
                exp1, exp2 = self.sub1.get_Z3_expr(hint), self.sub2.get_Z3_expr(hint)
                return If(exp2>=exp1, BitVecVal(1, 64), BitVecVal(0, 64))
            
            elif self.op == DW_OP_gt:
                exp1, exp2 = self.sub1.get_Z3_expr(hint), self.sub2.get_Z3_expr(hint)
                return If(exp2>exp1, BitVecVal(1, 64), BitVecVal(0, 64))
            
            elif self.op == DW_OP_le:
                exp1, exp2 = self.sub1.get_Z3_expr(hint), self.sub2.get_Z3_expr(hint)
                return If(exp2<=exp1, BitVecVal(1, 64), BitVecVal(0, 64))

            elif self.op == DW_OP_lt:
                exp1, exp2 = self.sub1.get_Z3_expr(hint), self.sub2.get_Z3_expr(hint)
                return If(exp2<exp1, BitVecVal(1, 64), BitVecVal(0, 64))

            elif self.op == DW_OP_ne:
                exp1, exp2 = self.sub1.get_Z3_expr(hint), self.sub2.get_Z3_expr(hint)
                return If(exp2!=exp1, BitVecVal(1, 64), BitVecVal(0, 64))

            else:
                assert(0)

        ''' mem
        '''
        if self.mem:
            if self.mem_size in load_funcs:
                if self.mem_size < 64:
                    return ZeroExt(64-self.mem_size, load_funcs[self.mem_size](self.mem.get_Z3_expr(hint)))
                return load_funcs[self.mem_size](self.mem.get_Z3_expr(hint))
            else:
                print("wrong memsize", file=sys.stderr)
                assert(0)

        
        ''' regs + offset
        '''
        res = BitVecVal(self.offset, 64)
        if self.regs:
            for reg in self.regs:
                if self.regs[reg] < 0:
                    res = res - (-self.regs[reg]) * BitVec(dwarf_reg_names[reg], 64)
                else:
                    res = res + self.regs[reg] * BitVec(dwarf_reg_names[reg], 64)

        return res
            
                

class AddressExp(Expression):
    def __init__(self, jsonAddrExp:dict = {}) -> None:
        '''
        {
            "addrExps" : [
                <AddressExp>
            ]
            "name" : <string>
            "is_variable" : <bool>
            "decl_file" : <string>
            "decl_row"  : <Dwarf_Unsigned>
            "decl_col"  : <Dwarf_Unsigned>
            "piece_num" : <int>
            "valid" : <bool>
        }

        AddressExp:

        {
            Expression part...

            "type" : <int>
            "startpc" : <Dwarf_Addr>
            "endpc" : <Dwarf_Addr>
            "reg" : <Dwarf_Half>
            "piece_start" : <Dwarf_Addr>,
            "piece_size" : <int>
            
            "needCFA" : <bool>
            "cfa_values" : [
                <Expression>
            ]
            "cfa_pcs" : [
                <Dwarf_Addr>
            ]
        }
        '''
        super(AddressExp, self).__init__(jsonAddrExp)
        if jsonAddrExp:
            
            self.reg:int = jsonAddrExp["reg"]
            self.type:int = jsonAddrExp["type"]

            self.startpc:int = jsonAddrExp["startpc"]
            self.endpc:int = jsonAddrExp["endpc"]
            self.piece_start = jsonAddrExp["piece_start"]
            self.piece_size = jsonAddrExp["piece_size"]

            self.needCFA = jsonAddrExp["needCFA"]
            self.cfa_pcs:list[int] = jsonAddrExp["cfa_pcs"] if self.needCFA else []
            self.cfa_values:list[AddressExp] = jsonAddrExp["cfa_values"] if self.needCFA else []

        else:
            self.reg = 128
            self.type = -1

            self.startpc = 0
            self.endpc = 0
            self.piece_start = 0
            self.piece_size = 0

            self.needCFA = False
            self.cfa_pcs:list[int] = []
            self.cfa_values:list[AddressExp] = []


        self.name:str = ""
        self.decl_file:str = ""
        
        ''' `True` if a variable else a parameter
        '''
        self.is_variable = True

        
    def __lt__(self, v):
        return self.startpc < v.startpc or (self.startpc == v.startpc and self.endpc < v.endpc)
    
    def __eq__(self, v) -> bool:
        return self.startpc == v.startpc and self.endpc == v.endpc
    
    def __hash__(self) -> int:
        return hash(self.name + "+" + self.decl_file)

    def is_same_simple_expr(self, other):
        res = self.offset == other.offset
        res = res or self.regs == other.regs
    
    def is_const(self):
        return super().is_const() and self.reg == 128



    def restoreCFA(self, addr:int):
        ''' cfa is `reg + offset` format,
        '''
        children:list[Expression] = self.getAllnodes()
        ind = bisect_right(self.cfa_pcs, addr, 0, len(self.cfa_pcs)) - 1
        cfa:Expression = Expression(self.cfa_values[ind])
        for child in children:
            if child.isCFA:
                out_offset = child.offset
                child.setExprFrom(cfa)
                child.offset += out_offset


    def get_Z3_expr(self, hint: Hint) -> BitVecRef:
        if self.type == DwarfType.REGISTER.value:
            return BitVec(dwarf_reg_names[self.reg], 64)
        return super().get_Z3_expr(hint)




count = 0    

class VarMgr:
    
    def __init__(self) -> None:
        self.vars:list[AddressExp] = []
        self.local_ind:int = -1

    def load(self, path:str):
        self.vars.clear()
        with open(path, "r") as f:
            self.addrs = json.loads(f.read())
        
        

        for addr in self.addrs:
            if "addrExps" not in addr:
                continue
            for addrExp in addr["addrExps"]:
                if "valid" not in addrExp or not addrExp["valid"]:
                    continue
                var:AddressExp = AddressExp(addrExp)
                var.name = addr["name"]
                var.decl_file = addr["decl_file"]
                var.is_variable = addr["is_variable"]
                self.vars.append(var)
        
        print(f"load {path} done!", file=sys.stderr)

        self.vars.sort()
        
        self.globals = []
        for i in range(0, len(self.vars)):
            if self.vars[i].startpc == 0 and self.vars[i].endpc == 0:
                self.globals.append(self.vars[i])
            else:
                self.local_ind = i
                break
    
    def find(self, pos:int, varName:str = "", varNameLst:list[str] = [], decl_file:str = "") -> set[AddressExp]:
        res = set()
        puppet = AddressExp()
        puppet.startpc = pos
        puppet.endpc = (1<<64)
        start_ind = bisect_right(self.vars, puppet) # find the right bound
        for i in range(start_ind-1, 0, -1):
            if self.vars[i].startpc <= pos and self.vars[i].endpc>pos:
                res.add(self.vars[i])
            
            if pos - self.vars[i].startpc > 0x20000:
                break
        
        for g in self.globals:
            res.add(g)

        # use varName
        if varName != "":
            res = set([var for var in res if var.name == varName])
        
        if len(varNameLst):
            res = set([var for var in res if var.name in varNameLst])

        # use decl_file
        if decl_file != "":
            res = set([var for var in res if var.decl_file == decl_file])
        
        return res
    
    def getVar(self, startpc:int, endpc:int, varName:str) -> AddressExp:
        puppet = AddressExp()
        puppet.startpc = startpc
        puppet.endpc = (1<<64)
        start_ind = bisect_right(self.vars, puppet)
        for i in range(start_ind-1, 0, -1):
            if self.vars[i].endpc == endpc and self.vars[i].name == varName:
                return self.vars[i]
        return None



if __name__ == "__main__":
    path_of_pyelftools = "/home/pyelftools/"
    sys.path.insert(0, path_of_pyelftools)
    from elftools.elf.elffile import ELFFile

    mgr = VarMgr()
    jsonpath = "/home/varviewer/extracter/redis.json"
    # jsonpath = "/home/DFchecker/varLocator/93_output.json"
    mgr.load(jsonpath)
    allcount = len(mgr.vars)
    ''' calculate ratio of debug info with large lifetime range
    '''
    basic = False
    if basic:
        size = 30
        bigcount, globalcount = [0]*size, 0
        threshold = [0x10 * (i+1) for i in range(int(size/2))] + [int(size/2) * 0x10 + 0x100*(i+1) for i in range(int(size/2))]
        
        aver = 0
        sum2 = 0

        for addrExp in mgr.vars:
            aver += (addrExp.endpc - addrExp.startpc)
            sum2 += (addrExp.endpc - addrExp.startpc) * (addrExp.endpc - addrExp.startpc)
            for i in range(size):
                if addrExp.endpc - addrExp.startpc > threshold[i]:
                    bigcount[i] += 1
                    # if i > 28:
                    #     print(f"{var.startpc} {var.endpc} {var.type}")
                
            if addrExp.startpc == addrExp.endpc == 0:
                    globalcount += 1
        
        aver /= len(mgr.vars)
        variance = (sum2 - len(mgr.vars) * aver * aver) / (len(mgr.vars)-1)
        print(f"average: {aver}")
        print(f"varianece {variance}")
        print(f"global range {globalcount}/{allcount}")

        for i in range(size):
            print(f"span over 0x{threshold[i]:X}:\t{bigcount[i]} / {allcount}")

    
    ''' validate and statistic depth of expression tree
    '''
    depth_map = {}
    invalid = 0
    for addrExp in mgr.vars:
        stack = [(1,addrExp)]
        depth = 1
        while len(stack):
            d, curVar = stack[-1]
            stack.pop()
            depth = max(depth, d)
            if curVar.mem:
                stack.append((d+1, curVar.mem))
                if (isinstance(curVar, AddressExp) and curVar.reg != 128) or curVar.offset != 0 or curVar.regs:
                    
                    invalid += 1
            if curVar.sub1:
                stack.append((d+1, curVar.sub1))
            if curVar.sub2:
                stack.append((d+1, curVar.sub2))
            
        if depth not in depth_map:
            depth_map[depth] = 0
        depth_map[depth] += 1
    print(f"invalid {invalid}")
    print(depth_map)


    ''' calculate branch instructions in lifetime range
    '''
    optionBranch = False
    if optionBranch:
        filepath = "/home/linux-6.0-rc6/vmlinux"
        # filepath = "/home/DFchecker/93_output"
        elf = ELFFile(open(filepath, "rb"))
        text = elf.get_section_by_name('.text')
        code_addr = text['sh_addr']
        code = text.data()
        if len(code) == 0:
            code = text.stream.read()
            print("text.data() failed", file=sys.stderr)
        
        decoder = Decoder(64, code, ip=code_addr)
        info_factory = InstructionInfoFactory()

        insts:list[Instruction] = []
        ins_infos:list[InstructionInfo] = []

        for ins in decoder:
            insts.append(ins)
            ins_infos.append(info_factory.info(ins))

        print("gather instructions done!", file=sys.stderr)
        
        ins_len = len(insts)

        def findId_r(addr:int, insts:list[Instruction]):
            # find the first ins that has the address >= addr
            lo, hi = 0, ins_len-1
            while lo < hi:
                mid = (lo + hi) // 2
                if insts[mid].ip >= addr:
                    hi = mid
                else:
                    lo = mid + 1
            return lo

        def findId_l(addr:int, insts:list[Instruction]):
            # find the last ins that has the address < addr
            lo, hi = 0, ins_len-1
            while lo < hi:
                mid = (lo+hi+1) // 2
                if insts[mid].ip < addr:
                    lo = mid
                else:
                    hi = mid - 1
            return hi
        
        code_to_str = {Code.__dict__[key]:key for key in Code.__dict__ if isinstance(Code.__dict__[key], int)}
        def isBranch(ins:Instruction):
            if not (code_to_str[ins.code].startswith("JMP") or\
                    code_to_str[ins.code].startswith("JN") or\
                    code_to_str[ins.code].startswith("JE") or\
                    code_to_str[ins.code].startswith("JA") or\
                    code_to_str[ins.code].startswith("JB") or\
                    code_to_str[ins.code].startswith("JG") or\
                    code_to_str[ins.code].startswith("JL") or\
                    code_to_str[ins.code].startswith("CALL")):
                return False
            if ins.op0_kind == OpKind.NEAR_BRANCH64 or \
                ins.op0_kind == OpKind.NEAR_BRANCH32 or\
                ins.op0_kind == OpKind.NEAR_BRANCH16:
                return ins.near_branch_target
            else:
                # some is mem
                # print(f"{ins} {ins.op0_kind}")
                pass
        
        jumpInCnt, jumpOutCnt = 0, 0
        overwriteCnt = 0
        reg1Cnt, reg2Cnt = 0, 0
        inmap = {}
        for addrExp in mgr.vars:
            if addrExp.startpc == addrExp.endpc:
                continue
            startInd, endInd = findId_r(addrExp.startpc, insts), findId_l(addrExp.endpc, insts)
            
            # reg relative to this var's loc expr
            rel_regs = [addrExp.reg] if addrExp.type == 1 else []
            if addrExp.type==DwarfType.MEMORY.value and addrExp.regs:
                assert(len(list(addrExp.regs.keys()))<=2)
                rel_regs.extend(list(addrExp.regs.keys()))

            inCnt = 0
            
            for i in range(startInd, endInd+1):
                ins:Instruction = insts[i]
                info:InstructionInfo = ins_infos[i]

                # gather regs written by this instruction
                regs_write = []
                for i in range(ins.op_count):
                    if ins.op_kind(i) != OpKind.REGISTER:
                        continue
                    if info.op_access(i) != OpAccess.WRITE and info.op_access(i) != OpAccess.COND_WRITE \
                        and info.op_access(i) != OpAccess.READ_WRITE and info.op_access(i) != OpAccess.READ_COND_WRITE:
                        continue
                    regs_write.append(ins.op_register(i))

                
                for z3_reg in regs_write:
                    if z3_reg not in iced_dwarf_regMap:
                        print(f"no prepare for reg {z3_reg}", file=sys.stderr)
                        continue
                    if iced_dwarf_regMap[z3_reg] in rel_regs:
                        overwriteCnt += 1
                        # print(f"{dwarf_reg_names[iced_dwarf_regMap[reg]]} modified {var.startpc:X} {var.endpc:X} by {ins.__str__()}")


                target = isBranch(ins)
                if target:
                    if target<addrExp.startpc or target>=addrExp.endpc:
                        jumpOutCnt += 1
                    else:
                        jumpInCnt += 1
                        inCnt += 1

                if inCnt not in inmap:
                    inmap[inCnt]=0
                inmap[inCnt] += 1
                if inCnt == 100:
                    print(f"{addrExp.startpc} {addrExp.endpc} {addrExp.type}")
        
        print(f"jump out of range {jumpOutCnt} / {allcount}")
        print(f"jump inside the range {jumpInCnt} / {allcount}")
        print(f"overwrite relevant reg {overwriteCnt} / {allcount}")
    # print(inmap)

'''
对linux kernel做了简单统计：
debug info中的variable信息共计 2074226 条
变量生命周期（pc范围）大于0x100的只有24267条，百分之一点多。大于0x1000的只有39条
在pc范围中存在跳转指令的有19035条，不到百分之一，并且它们都是跳出了pc范围，也就是pc范围内的分析只需要线性的即可
'''