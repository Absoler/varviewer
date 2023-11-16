#!/usr/local/bin/python3
import angr, pyvex
import sys
import copy
from dwarf_vex_map import *
from dwarf_iced_map import *
from z3 import *
import re
from hint import Hint
from util import *
from typing import NewType
from libresult import *
from variable import *
import time
import timeout_decorator


@timeout_decorator.timeout(1)
def solver_check(slv:Solver):
    return slv.check()

def solver_check_wrapper(slv:Solver):
    try:
        res = solver_check(slv)
    except TimeoutError as e:
        return unsat
    return res

def compare_exps(exp1:BitVecRef, exp2:BitVecRef, conds:list, useOffset:bool = False):
    ''' return constant offset of two `BitVecRef` if can else `None` 
    '''
    assert(exp1.size()==exp2.size())
    slv = Solver()
    for cond in conds:
        slv.add(cond)
    off = BitVec("off", exp1.size())
    if not useOffset:
        slv.add(off==0)
    slv.add(exp1-exp2==off)
    if solver_check_wrapper(slv) == sat:
        m = slv.model()
        old_off = m.eval(off)

        slv.add(off!=old_off)
        if solver_check_wrapper(slv) == unsat:
            return old_off
    return None

def traverse(p:angr.Project, cfg:angr.analyses.cfg.cfg_fast.CFGFast, processIRSB = None, file=sys.stdout, opt_level = 1):
    vis = set()
    cfg = p.analyses.CFGFast()
    indegree = dict(cfg.graph.in_degree)
    stack = [node for node in indegree if indegree[node]==0]
    while len(stack):
        node = stack[-1]
        stack.pop()
        if node.addr in vis:
            continue
        vis.add(node.addr)
        print(f"{node.name} start addr: {node.addr:X} of size: {node.size}", file=file)
        if node.block:
            if processIRSB:
                processIRSB(node)
            else:
                blk = p.factory.block(node.addr, opt_level=opt_level)    # opt_level default set to 1
                print(blk.vex._pp_str(), file=file)
        print(f"successors: {node.successors_and_jumpkinds()}", file=file)
        print(file=file)
        stack.extend(node.successors)




class Location:
    def __init__(self, node, ind) -> None:
        self.node:angr.knowledge_plugins.cfg.cfg_node.CFGNode = node
        self.ind:int = ind

    def __eq__(self, other: object) -> bool:
        return self.node.addr == other.node.addr and self.ind == other.ind
    
    def __hash__(self) -> int:
        return hash(hash(self.node.addr) + hash(self.ind))
    
    def __str__(self) -> str:
        return f"({self.node.name} 0x{self.node.addr:X} {self.ind})\n"


class RegFactSet:
    USEFUL_REG = 32
    def __init__(self) -> None:
        ''' reg_facts[i] record the possible definition place(s) of register i
        '''
        self.clear()
    
    def clear(self) -> None:
        ''' location(s) of `put` a register
        '''
        self.reg_facts:list[set[Location]] = [set() for _ in range(self.USEFUL_REG)]

    def get(self, regOff:int):
        return self.reg_facts[get_reg_ind(regOff)] if is_useful_reg(regOff) else None
    
    def setFact(self, regOff:int, fact:set):
        if not is_useful_reg(regOff):
            return
        self.reg_facts[get_reg_ind(regOff)] = fact

    def getFact(self, regOff:int) -> set[Location]:
        return self.reg_facts[get_reg_ind(regOff)]
        
    def meet(self, other):
        for i in range(self.USEFUL_REG):
            for fact in other.reg_facts[i]:
                self.reg_facts[i].add(fact)
    
    def __eq__(self, other: object) -> bool:
        eq = True
        for i in range(self.USEFUL_REG):
            eq = eq and set(self.reg_facts[i]).__eq__(set(other.reg_facts[i]))
            if not eq:
                break
        return eq

    def copy(self):
        new = RegFactSet()
        for i in range(self.USEFUL_REG):
            new.reg_facts[i] = set()
            for loc in self.reg_facts[i]:
                new.reg_facts[i].add(copy.copy(loc))
            
        return new
    
    def toString(self) -> str:
        s = ""
        for i in range(self.USEFUL_REG):
            if not self.reg_facts[i]:
                continue
            s += vex_reg_names[i*8+self.USEFUL_REG] + ":\n" 
            for loc in self.reg_facts[i]:
                s += loc.node.__str__() + " " + loc.node.block.vex.statements[loc.ind].__str__() + "\n"
            s += '\n'
        return s
    
''' only record relevance with register(s)
'''
TempFactType = NewType('TempFactType', set[str])
class TempFactBlock:
    def __init__(self) -> None:
        # register(s) each temp variable has relevance with
        self.temp_regs_map:dict[int, TempFactType] = {}

    def copy(self):
        new = TempFactBlock()
        new.temp_regs_map = copy.copy(self.temp_regs_map)
        return new
    
    def update(self, tmp:int, regs:TempFactType) -> bool:
        change = False
        if tmp not in self.temp_regs_map:
            change = True
        else:
            change = (self.temp_regs_map[tmp] != regs)
        self.temp_regs_map[tmp] = regs
        return change


''' record the `def` ir of each register
'''
class Definition:
    def __init__(self) -> None:
        self.blockAddr_to_defs:dict[int, dict] = {}
    
    def clear(self):
        self.blockAddr_to_defs = {}
    
    def setBlock(self, irsb:pyvex.IRSB):
        to_defs = {}
        for i, ir in enumerate(irsb.statements):
            if isinstance(ir, pyvex.stmt.WrTmp):
                to_defs[ir.tmp] = ir.data
        self.blockAddr_to_defs[irsb.addr] = to_defs

    def getDef(self, irsb:pyvex.IRSB, tmp:int) -> pyvex.IRExpr:
        if irsb.addr not in self.blockAddr_to_defs:
            print(f"defs in {irsb.addr} not recorded", file=sys.stderr)
            return None
        return self.blockAddr_to_defs[irsb.addr][tmp]



class Analysis:
    def __init__(self, proj, cfg) -> None:
        self.irsb_map:dict[int, pyvex.block.IRSB] = {}

        self.context_reg_map:dict[Location, RegFactSet] = {}
        self.in_reg_map:dict[angr.knowledge_plugins.cfg.cfg_node.CFGNode, RegFactSet] = {}
        self.out_reg_map:dict[angr.knowledge_plugins.cfg.cfg_node.CFGNode, RegFactSet] = {}

        self.temp_map:dict[angr.knowledge_plugins.cfg.cfg_node.CFGNode, TempFactBlock] = {}

        self.def_mgr:Definition = Definition()
        self.proj = proj
        self.cfg:angr.analyses.cfg.cfg_fast.CFGFast = cfg
        self.addr_list:list[int] = []

    def clear(self):
        self.irsb_map = {}
        self.context_reg_map = {}
        self.in_reg_map = {}
        self.out_reg_map = {}
        self.temp_map = {}
        self.def_mgr.clear()
        self.proj = None
        self.cfg = None
        self.addr_list = []
        
    def query_reg_def(self, location:Location):
        node, i = location.node, location.ind
        while i>=0 and Location(node, i) not in self.context_reg_map:
            i -= 1
        if i >= 0:
            return self.context_reg_map[Location(node, i)]
        else:
            return self.in_reg_map[node]
    
    def query_temp_rel(self, node, tmp:int) -> TempFactType:
        tempFactBlock = self.temp_map[node]
        if tmp in tempFactBlock.temp_regs_map:
            return tempFactBlock.temp_regs_map[tmp]
        return set()

    def analyzeBlock_regDef(self, node:angr.knowledge_plugins.cfg.cfg_node.CFGNode) -> bool:
        ''' register facts analysis part
        '''
        if node.addr in self.irsb_map:
            irsb = self.irsb_map[node.addr]
        else:
            return False
        
        change:bool = False
        
        in_result:RegFactSet = self.in_reg_map[node]
        out_result:RegFactSet = in_result.copy()
        
        for i, ir in enumerate(irsb.statements):
            if ir.tag == 'Ist_Put':
                if not is_useful_reg(ir.offset):
                    continue
                out_result.setFact(ir.offset, {Location(node, i)})

                loc = Location(node, i)
                if loc in self.context_reg_map:
                    # if not change and context_map[loc] != out_result:
                    #     print(f"1 {ir.__str__()}")
                    change = change or self.context_reg_map[loc] != out_result
                else:
                    change = True
                    # print(f"2")

                self.context_reg_map[loc] = out_result.copy()

            elif ir.tag == 'Ist_PutI':
                print(f"{irsb.addr} get puti", file=sys.stderr)
        
        # if not change and out_map[node] != out_result:
        #     print(f"3 {out_map[node].toString()} {out_result.toString()}")
        change = change or self.out_reg_map[node] != out_result
        self.out_reg_map[node] = out_result

        return change

    def get_relevance_r(self, irExpr:pyvex.expr.IRExpr, location:Location):
        tempFactBlock:TempFactBlock = self.temp_map[location.node]

        if isinstance(irExpr, pyvex.expr.RdTmp):
            return tempFactBlock.temp_regs_map[irExpr.tmp]
        
        elif isinstance(irExpr, pyvex.expr.Unop) or isinstance(irExpr, pyvex.expr.Binop) or isinstance(irExpr, pyvex.expr.Triop) or isinstance(irExpr, pyvex.expr.Qop):
            retVal = set()
            for arg in irExpr.args:
                retVal.update(self.get_relevance_r(arg, location))
            return retVal
        
        elif isinstance(irExpr, pyvex.expr.Get):
            retVal = {get_base_name_vex(irExpr.offset)}
            ''' consider cfg, retrieve reg def from predecessors

                if reg is defined by `tmp` of other blocks, retrieve 
                temp fact from them
            '''
            reg_defs = self.query_reg_def(location)
            for loc in reg_defs.getFact(irExpr.offset):
                def_node, def_ind = loc.node, loc.ind
                data = self.irsb_map[def_node.addr].statements[def_ind].data
                if not isinstance(data, pyvex.expr.RdTmp):
                    continue
                other_temp_fact:TempFactType = self.query_temp_rel(def_node, data.tmp)
                retVal.update(other_temp_fact)

            return retVal

        elif isinstance(irExpr, pyvex.expr.Load):
            return self.get_relevance_r(irExpr.addr, location)
        
        else:
            return set()

    def analyzeBlock_relevance(self, node:angr.knowledge_plugins.cfg.cfg_node.CFGNode) -> bool:
        ''' analyze reg-relevance
        '''
        if node.addr in self.irsb_map:
            irsb = self.irsb_map[node.addr]
        else:
            return False

        change:bool = False
        tempFactBlock:TempFactBlock = self.temp_map[node]

        for i, ir in enumerate(irsb.statements):
            if isinstance(ir, pyvex.stmt.WrTmp):
                regs:TempFactType = self.get_relevance_r(ir.data, Location(node, i))
                change = tempFactBlock.update(ir.tmp, regs) or change
            
            if isinstance(ir, pyvex.stmt.CAS):
                ''' compare and set

                    .addr is the memory address.
                    .end  is the endianness with which memory is accessed

                    If .addr contains the same value as .expdLo, then .dataLo is
                    written there, else there is no write.  In both cases, the
                    original value at .addr is copied into .oldLo.
                '''
                regs:TempFactType = self.get_relevance_r(ir.addr, Location(node, i))
                change = tempFactBlock.update(ir.oldLo, regs) or change
                change = tempFactBlock.update(ir.oldHi, regs) or change
                
            if isinstance(ir, pyvex.stmt.Dirty):
                ''' dirty call, now only inherit relevant regs from its args
                '''
                args_regs = set()
                for arg in ir.args:
                    regs:TempFactType = self.get_relevance_r(arg, Location(node, i))
                    args_regs.update(regs)
                change = tempFactBlock.update(ir.tmp, args_regs) or change

            if isinstance(ir, pyvex.stmt.LoadG):
                ''' load with guard, only care about `addr`
                '''
                regs:TempFactType = self.get_relevance_r(ir.addr, Location(node, i))
                change = tempFactBlock.update(ir.dst, regs) or change

        return change
        
                



    def analyzeCFG(self):
        
        nodes:list[angr.knowledge_plugins.cfg.cfg_node.CFGNode] = list(self.cfg.graph.nodes)
        for node in nodes:
            self.in_reg_map[node] = RegFactSet()
            self.out_reg_map[node] = RegFactSet()

            self.temp_map[node] = TempFactBlock()

            if node.block:
                blk:angr.block.Block = self.proj.factory.block(node.addr, opt_level=0)
                self.irsb_map[node.addr] = blk.vex
                self.def_mgr.setBlock(self.irsb_map[node.addr])
                self.addr_list.extend(blk.instruction_addrs)
        
        # print(f"{len(nodes)} nodes in total")
        loopCnt = 0

        change = True
        while change:
            change = False
            for node in nodes:
                self.in_reg_map[node].clear()
                for pred in node.predecessors:
                    self.in_reg_map[node].meet(self.out_reg_map[pred])
                change = self.analyzeBlock_regDef(node) or change
            loopCnt += 1
        
        print(f"reg loop {loopCnt}")
        
        change = True
        loopCnt = 0
        while change:
            change = False
            for node in nodes:
                change = self.analyzeBlock_relevance(node) or change
            loopCnt += 1
            if loopCnt > 20:
                break
    
        print(f"temp loop {loopCnt}")

        self.addr_list = list(set(self.addr_list))
        self.addr_list.sort()

        ''' for test
        '''
        # for node in nodes:
        #     addr = node.addr
        #     print(f"addr: {addr:X} {node}")
        #     self.irsb_map[addr].pp()
        #     tempFactBlock = self.temp_map[node]
        #     for tmp in tempFactBlock.temp_regs_map:
        #         print(f"{tmp} {tempFactBlock.temp_regs_map[tmp]}")
        #     print(f"successors: {node.successors_and_jumpkinds()}")
        #     print()

    def dumpVex(self, path:str):
        with open(path, "w") as vexFile:
            for addr in self.irsb_map:
                irsb:pyvex.block.IRSB = self.irsb_map[addr]
                print(f"block addr {addr:X}", file=vexFile)
                print(irsb._pp_str(), file=vexFile)
                print("", file=vexFile)

    def processIRSB(self, node:angr.knowledge_plugins.cfg.cfg_node.CFGNode):
        irsb:pyvex.IRSB = node.block.vex
        print("In[]:\n" + self.in_reg_map[node].toString() + "\n")
        for i, ir in enumerate(irsb.statements):
            loc = Location(node, i)
            if loc in self.context_reg_map:
                print(loc.__str__() + (self.context_reg_map[loc].toString()) + '\n')


    def get_z3_expr_from_vex(self, irExpr:pyvex.IRExpr, irsb:pyvex.block.IRSB):
        ''' stop at the first register
        '''
        if isinstance(irExpr, pyvex.expr.Binop):
            
            if irExpr.op.startswith("Iop_Add"):
                return self.get_z3_expr_from_vex(irExpr.args[0], irsb) + self.get_z3_expr_from_vex(irExpr.args[1], irsb)
            
            elif irExpr.op.startswith("Iop_Sub"):
                return self.get_z3_expr_from_vex(irExpr.args[0], irsb) - self.get_z3_expr_from_vex(irExpr.args[1], irsb)
            
            elif irExpr.op.startswith("Iop_DivMod"):
                e1:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[0], irsb)
                e2:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                if e2.size() < e1.size():
                    e2 = ZeroExt(e1.size()-e2.size(), e2)
                return e1 % e2
            
            elif irExpr.op.startswith("Iop_Div"):
                e1:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[0], irsb)
                e2:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                if irExpr.op.startswith("Iop_DivS"):
                    ''' signed division
                    '''
                    if e2.size() < e1.size():
                        e2 = SignExt(e1.size()-e2.size(), e2)
                    return  If(And(e1>0, e2<0), (e1-1)/e2-1,
                            If(And(e1<0, e2>0), (e1+1)/e2-1, e1/e2))
                
                if e2.size() < e1.size():
                    e2 = ZeroExt(e1.size()-e2.size(), e2)
                return e1 / e2
            
            elif pyvex.expr.mull_signature_re.match(irExpr.op):
                size, _ = pyvex.expr.mull_signature(irExpr.op)
                size = int(size[5:])
                exp1, exp2 = self.get_z3_expr_from_vex(irExpr.args[0], irsb), self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                if "S" in irExpr.op:
                    return SignExt(size//2, exp1 * exp2)
                else:
                    return ZeroExt(size//2, exp1 * exp2)

            elif irExpr.op.startswith("Iop_Mul"):
                return self.get_z3_expr_from_vex(irExpr.args[0], irsb) * self.get_z3_expr_from_vex(irExpr.args[1], irsb)

            elif irExpr.op.startswith("Iop_And"):
                return self.get_z3_expr_from_vex(irExpr.args[0], irsb) & self.get_z3_expr_from_vex(irExpr.args[1], irsb)
            
            elif irExpr.op.startswith("Iop_Or"):
                return self.get_z3_expr_from_vex(irExpr.args[0], irsb) | self.get_z3_expr_from_vex(irExpr.args[1], irsb)
            
            elif irExpr.op.startswith("Iop_Xor"):
                return self.get_z3_expr_from_vex(irExpr.args[0], irsb) ^ self.get_z3_expr_from_vex(irExpr.args[1], irsb)
            
            elif irExpr.op.startswith("Iop_Shl"):
                base:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[0], irsb)
                index:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                if index.size() < base.size():
                    if isinstance(index, BitVecNumRef):
                        index = BitVecVal(index.as_long(), base.size())
                    else:
                        index = ZeroExt(base.size()-index.size(), index)
                return base << index
            
            elif irExpr.op.startswith("Iop_Shr"):
                base:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[0], irsb)
                index:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                if index.size() < base.size():
                    if isinstance(index, BitVecNumRef):
                        index = BitVecVal(index.as_long(), base.size())
                    else:
                        index = ZeroExt(base.size()-index.size(), index)
                return LShR(base, index)

            elif irExpr.op.startswith("Iop_Sar"):
                base:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[0], irsb)
                index:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                if index.size() < base.size():
                    if isinstance(index, BitVecNumRef):
                        index = BitVecVal(index.as_long(), base.size())
                    else:
                        index = ZeroExt(base.size()-index.size(), index)
                return If(base<0, (base+1)/(1<<index) - 1, base/(1<<index))
            
            elif cmpF_re.match(irExpr.op):
                exp1, exp2 = self.get_z3_expr_from_vex(irExpr.args[0], irsb), self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                return BitVec("cmpf", 32)

            elif cas_exp_cmp_re.match(irExpr.op):
                exp1, exp2 = self.get_z3_expr_from_vex(irExpr.args[0], irsb), self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                size = int(cas_exp_cmp_re.match(irExpr.op).group("size"))
                return BitVec("cas_exp", size)

            elif irExpr.op.startswith("Iop_CmpEQ"):
                exp1, exp2 = self.get_z3_expr_from_vex(irExpr.args[0], irsb), self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                return If(exp1==exp2, BitVecVal(1, 1), BitVecVal(0, 1))
            
            elif irExpr.op.startswith("Iop_CmpGE"):
                exp1, exp2 = self.get_z3_expr_from_vex(irExpr.args[0], irsb), self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                return If(exp1>=exp2, BitVecVal(1, 1), BitVecVal(0, 1))
            
            elif irExpr.op.startswith("Iop_CmpGT"):
                exp1, exp2 = self.get_z3_expr_from_vex(irExpr.args[0], irsb), self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                return If(exp1>exp2, BitVecVal(1, 1), BitVecVal(0, 1))
            
            elif irExpr.op.startswith("Iop_CmpLE"):
                exp1, exp2 = self.get_z3_expr_from_vex(irExpr.args[0], irsb), self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                return If(exp1<=exp2, BitVecVal(1, 1), BitVecVal(0, 1))
            
            elif irExpr.op.startswith("Iop_CmpLT"):
                exp1, exp2 = self.get_z3_expr_from_vex(irExpr.args[0], irsb), self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                return If(exp1<exp2, BitVecVal(1, 1), BitVecVal(0, 1))
            
            elif irExpr.op.startswith("Iop_CmpNE"):
                exp1, exp2 = self.get_z3_expr_from_vex(irExpr.args[0], irsb), self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                return If(exp1!=exp2, BitVecVal(1, 1), BitVecVal(0, 1))
            
            elif f_cast_re.match(irExpr.op):
                ''' omit extra rounding mode
                '''
                src_size, dst_size = int(f_cast_re.match(irExpr.op).group("srcsize")), int(f_cast_re.match(irExpr.op).group("dstsize"))
                old_expr:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[1], irsb)
                if src_size < dst_size:
                    return SignExt(dst_size-src_size, old_expr) if "S" in irExpr.op else ZeroExt(dst_size-src_size, old_expr)
                else:
                    return Extract(dst_size-1, 0, old_expr)

            elif bin_cast_re.match(irExpr.op):
                ''' concat args[0] and args[1] to a larger value
                '''
                
                src_size, dst_size = int(bin_cast_re.match(irExpr.op).group("srcsize")), int(bin_cast_re.match(irExpr.op).group("dstsize"))

                high_part = Extract(src_size-1, 0, self.get_z3_expr_from_vex(irExpr.args[0], irsb))
                low_part = Extract(src_size-1, 0, self.get_z3_expr_from_vex(irExpr.args[1], irsb))
                return Concat(high_part, low_part)

            else:
                print(f"unhandle op {irExpr.op}", file=sys.stderr)
                ''' 
                '''
                return self.get_z3_expr_from_vex(irExpr.args[0], irsb)
                assert(0)

        elif isinstance(irExpr, pyvex.expr.Unop):
            if irExpr.op.startswith("Iop_Abs"):
                return Abs(self.get_z3_expr_from_vex(irExpr.args[0], irsb))
            
            elif irExpr.op.startswith("Iop_Neg"):
                return -self.get_z3_expr_from_vex(irExpr.args[0], irsb)
            
            elif irExpr.op.startswith("Iop_Not"):
                return ~self.get_z3_expr_from_vex(irExpr.args[0], irsb)
            
            elif un_cast_re.match(irExpr.op):
                ''' convert operator
                '''
                src_size, dst_size = int(un_cast_re.match(irExpr.op).group("srcsize")), int(un_cast_re.match(irExpr.op).group("dstsize"))
                old_expr:BitVecRef = self.get_z3_expr_from_vex(irExpr.args[0], irsb)
                
                if isinstance(old_expr, BoolRef):
                    return old_expr
                
                assert(src_size==old_expr.size())
                if dst_size > src_size:
                    if "S" in irExpr.op:
                        return SignExt(dst_size-src_size, old_expr)
                    else:
                        # hope "U" in op
                        return ZeroExt(dst_size-src_size, old_expr)
                else:
                    if "HI" in irExpr.op:
                        return Extract(src_size-1, src_size - dst_size, old_expr)
                    return Extract(dst_size-1, 0, old_expr)
                
            else:
                print(f"unhandle op {irExpr.op}", file=sys.stderr)
                return self.get_z3_expr_from_vex(irExpr.args[0], irsb)
        
        elif isinstance(irExpr, pyvex.expr.RdTmp):
            # temp variable
            define = self.def_mgr.getDef(irsb, irExpr.tmp)
            return self.get_z3_expr_from_vex(define, irsb)
        
        elif isinstance(irExpr, pyvex.expr.Load):
            ''' memory

            hope addrExp is just a `mem`
            '''
            size = int(pyvex.const.type_str_re.match(irExpr.type).group("size"))
            if size in load_funcs:
                return load_funcs[size](self.get_z3_expr_from_vex(irExpr.addr, irsb))
            else:
                assert(0)

        elif isinstance(irExpr, pyvex.expr.Const):
            ''' const
            '''
            size = int(pyvex.const.type_str_re.match(irExpr.con.type).group("size"))
            if irExpr.con.__str__() == 'nan':
                return BitVecVal(0, size)
            return BitVecVal(irExpr.con.value, size)

        elif isinstance(irExpr, pyvex.expr.ITE):
            ''' selection based on cmp result, similar to `phi`
            '''
            cond = self.get_z3_expr_from_vex(irExpr.cond, irsb)
            if not isinstance(cond, BoolRef):
                cond = If(cond != 0, True, False)
            iftrue = self.get_z3_expr_from_vex(irExpr.iftrue, irsb)
            iffalse = self.get_z3_expr_from_vex(irExpr.iffalse, irsb)
            return If(cond, iftrue, iffalse)
        

        elif isinstance(irExpr, pyvex.expr.Get):
            ''' register
                we only use 64-bit version names
            '''
            if irExpr.offset not in vex_reg_names:
                if irExpr.offset - 1 in vex_reg_names:    
                    reg_name = vex_reg_names[irExpr.offset - 1]
                    return Extract(15, 8, BitVec(reg_name, 64))
                
                if irExpr.offset - 8 in vex_reg_names:
                    reg_name = vex_reg_names[irExpr.offset - 8]
                    return Extract(127, 64, BitVec(reg_name, 128))
                
                print(f'invalid register {irExpr.offset}')
                assert(0)

            reg_name = vex_reg_names[irExpr.offset]
            size = int(irExpr.type[5:])
            return Extract(size-1, 0, BitVec(reg_name, 64)) if size < 64 else ZeroExt(size-64, BitVec(reg_name, 64))

        elif isinstance(irExpr, pyvex.expr.GetI):
            ''' get elem from `IRRegArray`, hard to evaluate
                the index, so just create a fake valid
                return value
            '''
            size = int(irExpr.descr.elemTy[5:])
            return BitVec(f"IRRegArray_{irExpr.descr.base}[{irExpr.ix.__str__()}]", size)

        elif isinstance(irExpr, pyvex.expr.CCall):
            ''' call to a helper function
                not match, return a 
            '''
            size = int(pyvex.const.type_str_re.match(irExpr.retty).group("size"))
            return BitVec(f"ccall-{irExpr.cee.name}", size)

        
        print(irExpr)
        return None


    def match(self, addrExp:AddressExp, ty:DwarfType, piece_addrs:list, useOffset:bool, showTime:bool=False) -> list[Result]:
        # statistic variable
        potential_cnt = 0

        dwarf_expr:BitVecRef = addrExp.get_Z3_expr(Hint())
        variable_type:VariableType = addrExp.variable_type
        dwarf_regs = extract_regs_from_z3(dwarf_expr)
        dwarf_regs_names = {reg.decl().name() for reg in dwarf_regs}

        ''' dwarf_expr is the value of the variable recorded in the debug info entry
            dwarf_addr is its address

            for die whose type is IMPLICIT, we can strip the `DW_OP_stack_value` away,
            and take the rest as its address, here we just remove the top `load` z3 function if exists.
        '''
        dwarf_addr = None
        if ty == DwarfType.VALUE:
            dwarf_addr = get_addr(dwarf_expr)
        elif ty == DwarfType.MEMORY:
            dwarf_addr = dwarf_expr
            dwarf_expr = None
        

        nodes:list[angr.knowledge_plugins.cfg.cfg_node.CFGNode] = list(self.cfg.graph.nodes)
        slv = Solver()
        reses:list[Result] = []

        if showTime:
            startTime = time.time()
        for node in nodes:
            if node.addr not in self.irsb_map:
                continue
            irsb:pyvex.block.IRSB = self.irsb_map[node.addr]
            print(f"> meet {len(irsb.statements)} vex ir(s)")

            curAddr = -1
            tempFactBlock:TempFactBlock = self.temp_map[node]
            
            for i, ir in enumerate(irsb.statements):
                if isinstance(ir, pyvex.stmt.IMark):
                    curAddr = ir.addr
                    if curAddr == self.addr_list[-1]:
                        break
                    curAddr = piece_addrs[self.addr_list.index(curAddr)]
                    continue
                
                if addrExp.needCFA:
                    tmp_addrExp = copy.deepcopy(addrExp)
                    tmp_addrExp.restoreCFA(curAddr)
                    dwarf_expr = tmp_addrExp.get_Z3_expr(Hint())
                    dwarf_regs = extract_regs_from_z3(dwarf_expr)
                    dwarf_regs_names = {reg.decl().name() for reg in dwarf_regs}
                    if ty == DwarfType.VALUE:
                        dwarf_addr = get_addr(dwarf_expr)
                    elif ty == DwarfType.MEMORY:
                        dwarf_addr = dwarf_expr
                        dwarf_expr = None
                vex_expr:BitVecRef = None
                vex_exprs:list[BitVecRef] = []
                hasCandidate = False

                if isinstance(ir, pyvex.stmt.Put):
                    ''' put(reg) = tmp
                        
                        usually mapped to an instruction such as `mov tmp, reg` 
                        or `add tmp-reg, reg`

                        skip un-useful registers
                    '''

                    if not is_useful_reg(ir.offset):
                        continue

                    if isinstance(ir.data, pyvex.expr.RdTmp) and dwarf_regs_names.issubset(tempFactBlock.temp_regs_map[ir.data.tmp]):
                        # print(f"{dwarf_regs} {tempFactBlock.temp_regs_map[ir.data.tmp]}")
                        vex_expr = self.get_z3_expr_from_vex(ir.data, irsb)
                        vex_expr = post_format(vex_expr)
                        setpos(vex_expr, MatchPosition.src_value)
                        setattr(vex_expr, "src_size", getBinarySize(vex_expr))
                        vex_exprs.append(vex_expr)


                    # overwritten register should also be considered
                    data_size = ir.data.result_size(irsb.tyenv)
                    vex_expr = BitVec(get_base_name_vex(ir.offset), 64)
                    if data_size < 64:
                        vex_expr = vex_expr & BitVecVal(and_mask[data_size], 64)
                    setpos(vex_expr, MatchPosition.dst_value)
                    setattr(vex_expr, "src_size", -1)
                    vex_exprs.append(vex_expr)
                    hasCandidate = True
                
                elif isinstance(ir, pyvex.stmt.Store):
                    ''' store(addr) = data


                    '''

                    if isinstance(ir.addr, pyvex.expr.RdTmp) and dwarf_regs_names.issubset(tempFactBlock.temp_regs_map[ir.addr.tmp]):
                        # print(f"{dwarf_regs} {tempFactBlock.temp_regs_map[ir.addr.tmp]}")
                        vex_expr = self.get_z3_expr_from_vex(ir.addr, irsb)
                        vex_expr = post_format(vex_expr)
                        setpos(vex_expr, MatchPosition.dst_addr)
                        setattr(vex_expr, "src_size", -1)
                        vex_exprs.append(vex_expr)
                        hasCandidate = True

                    if isinstance(ir.data, pyvex.expr.RdTmp) and dwarf_regs_names.issubset(tempFactBlock.temp_regs_map[ir.data.tmp]):
                        # print(f"{dwarf_regs} {tempFactBlock.temp_regs_map[ir.data.tmp]}")
                        vex_expr = self.get_z3_expr_from_vex(ir.data, irsb)
                        vex_expr = post_format(vex_expr)
                        setpos(vex_expr, MatchPosition.src_value)
                        setattr(vex_expr, "src_size", getBinarySize(vex_expr))
                        vex_exprs.append(vex_expr)
                        hasCandidate = True

                elif isinstance(ir, pyvex.stmt.WrTmp) and isinstance(ir.data, pyvex.expr.Load):
                    ''' tmp = load(addr)
                    '''

                    if isinstance(ir.data.addr, pyvex.expr.RdTmp) and dwarf_regs_names.issubset(tempFactBlock.temp_regs_map[ir.data.addr.tmp]):
                        # print(f"{dwarf_regs} {tempFactBlock.temp_regs_map[ir.data.addr.tmp]}")
                        vex_expr = self.get_z3_expr_from_vex(ir.data.addr, irsb)
                        vex_expr = post_format(vex_expr)
                        setpos(vex_expr, MatchPosition.src_addr)
                        setattr(vex_expr, "src_size", int(ir.data.ty[5:]))
                        vex_exprs.append(vex_expr)
                        hasCandidate = True

                if showTime:
                    print(f"---- summary {time.time()-startTime}")
                    startTime = time.time()

                if not hasCandidate:
                    continue
                
                potential_cnt += len(vex_exprs)

                for vex_expr in vex_exprs:
                    ''' avoid z3 match for register location description
                    '''
                    if ty == DwarfType.REGISTER and not useOffset:
                        vex_regs = extract_regs_from_z3(vex_expr)
                        vex_regs_sizeNames = {(reg.decl().name(), reg.size()) for reg in vex_regs}
                        dwarf_regs_sizeNames = {(reg.decl().name(), reg.size()) for reg in dwarf_regs}
                        if vex_regs_sizeNames == dwarf_regs_sizeNames and not has_load(vex_expr) and not has_offset(vex_expr):
                            reses.append(Result(addrExp.name, curAddr, vex_expr.matchPos, 0, ty, variable_type, irsb.addr, i))
                        continue

                    # conds:list = make_reg_type_conds(vex_expr) + [loadu_cond, loads_cond]
                    conds:list = [loadu_cond, loads_cond]
                    
                    
                    # match `dwarf_expr` first, if fail, try match its address
                    if dwarf_expr != None:
                        offset = compare_exps(vex_expr, dwarf_expr, conds, useOffset)
                        if check_result(offset, vex_expr.matchPos, ty):
                            reses.append(Result(addrExp.name, curAddr, vex_expr.matchPos, 0, ty, variable_type, irsb.addr, i, offset.as_signed_long(), vex_expr.src_size))
                            continue

                    if dwarf_addr != None:
                        offset = compare_exps(vex_expr, dwarf_addr, conds, useOffset)
                        if check_result(offset, vex_expr.matchPos, ty):
                            reses.append(Result(addrExp.name, curAddr, vex_expr.matchPos, -1, ty, variable_type, irsb.addr, i, offset.as_signed_long(), vex_expr.src_size))
                            continue

                

                if showTime:
                    print(f"---- match {time.time()-startTime}")
                    startTime = time.time()
        
        print(f"< tried match {potential_cnt} potential vex expressions")

        return reses



if __name__ == "__main__":   
    proj = angr.Project(sys.argv[1], load_options={'auto_load_libs' : False})
    analysis = Analysis(proj)
    # traverse(proj, cfg, processIRSB=processIRSB)
    # traverse(proj, cfg)