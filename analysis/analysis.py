#!/usr/local/bin/python3
import angr, pyvex
import sys
import copy
from processVEX import *

def traverse(p:angr.Project, cfg:angr.analyses.cfg.cfg_fast.CFGFast, processIRSB = None, file=sys.stdout):
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
                blk = p.factory.block(node.addr, opt_level=1)    # opt_level default set to 1
                print(blk.vex._pp_str(), file=file)
        print(f"successors: {node.successors_and_jumpkinds()}", file=file)
        print(file=file)
        stack.extend(node.successors)


def check_reg(regOff:int):
    return 16 <= regOff <= 136

def get_reg_ind(regOff:int):
    return int((regOff-16)/8)

class location:
    def __init__(self, node, ind) -> None:
        self.node:angr.knowledge_plugins.cfg.cfg_node.CFGNode = node
        self.ind:int = ind

    def __eq__(self, other: object) -> bool:
        return self.node.addr == other.node.addr and self.ind == other.ind
    
    def __hash__(self) -> int:
        return hash(hash(self.node.addr) + hash(self.ind))
    
    def __str__(self) -> str:
        return f"({self.node.name} 0x{self.node.addr:X} {self.ind})\n"


class ResultSet:
    def __init__(self) -> None:
        ''' reg_facts[i] record the possible definition place(s) of register i
        '''
        self.clear()
    
    def clear(self) -> None:
        self.reg_facts:list[set[location]] = [set() for _ in range(16)]

    def get(self, regOff:int):
        return self.reg_facts[get_reg_ind(regOff)] if check_reg(regOff) else None
    
    def setFact(self, regOff:int, fact:set):
        if not check_reg(regOff):
            return
        self.reg_facts[get_reg_ind(regOff)] = fact

    def getFact(self, regOff:int) -> set[location]:
        return self.reg_facts[get_reg_ind(regOff)]
        
    def meet(self, other):
        for i in range(16):
            for fact in other.reg_facts[i]:
                self.reg_facts[i].add(fact)
    
    def __eq__(self, other: object) -> bool:
        eq = True
        for i in range(16):
            eq = eq and set(self.reg_facts[i]).__eq__(set(other.reg_facts[i]))
            if not eq:
                break
        return eq

    def copy(self):
        new = ResultSet()
        for i in range(16):
            new.reg_facts[i] = set()
            for loc in self.reg_facts[i]:
                new.reg_facts[i].add(copy.copy(loc))
            
        return new
    
    def toString(self) -> str:
        s = ""
        for i in range(16):
            if not self.reg_facts[i]:
                continue
            s += register_names[i*8+16] + ":\n" 
            for loc in self.reg_facts[i]:
                s += loc.node.__str__() + " " + loc.node.block.vex.statements[loc.ind].__str__() + "\n"
            s += '\n'
        return s

''' record the def ir of each register
'''
context_map:dict[location, ResultSet] = {}
in_map:dict[angr.knowledge_plugins.cfg.cfg_node.CFGNode, ResultSet] = {}
out_map:dict[angr.knowledge_plugins.cfg.cfg_node.CFGNode, ResultSet] = {}

class definition:
    def __init__(self) -> None:
        self.block_to_defs = {}
    
    def setBlock(self, irsb:pyvex.IRSB):
        to_defs = {}
        for i, ir in enumerate(irsb.statements):
            if isinstance(ir, pyvex.stmt.WrTmp):
                to_defs[ir.tmp] = ir.data
        self.block_to_defs[irsb] = to_defs

    def getDef(self, irsb:pyvex.IRSB, tmp:int) -> pyvex.IRExpr:
        if irsb not in self.block_to_defs:
            print(f"defs in {irsb} not recorded", file=sys.stderr)
            return None
        return self.block_to_defs[irsb][tmp]

def_mgr = definition()

def analyzeBlock(node:angr.knowledge_plugins.cfg.cfg_node.CFGNode) -> bool:
    
    if node.block:
        irsb = node.block.vex
    else:
        return False
    
    change:bool = False
    
    in_result:ResultSet = in_map[node]
    out_result:ResultSet = in_result.copy()
    
    for i, ir in enumerate(irsb.statements):
        if ir.tag == 'Ist_Put':
            if not check_reg(ir.offset):
                continue
            out_result.setFact(ir.offset, {location(node, i)})

            loc = location(node, i)
            if loc in context_map:
                # if not change and context_map[loc] != out_result:
                #     print(f"1 {ir.__str__()}")
                change = change or context_map[loc] != out_result
            else:
                change = True
                # print(f"2")

            context_map[loc] = out_result.copy()

        elif ir.tag == 'Ist_PutI':
            print(f"{irsb.addr} get puti", file=sys.stderr)
    
    # if not change and out_map[node] != out_result:
    #     print(f"3 {out_map[node].toString()} {out_result.toString()}")
    change = change or out_map[node] != out_result
    out_map[node] = out_result

    return change



def analyzeCFG(cfg:angr.analyses.cfg.cfg_fast.CFGFast):
    
    nodes:list[angr.knowledge_plugins.cfg.cfg_node.CFGNode] = list(cfg.graph.nodes)
    for node in nodes:
        in_map[node] = ResultSet()
        out_map[node] = ResultSet()

        if node.block:
            def_mgr.setBlock(node.block.vex)
    
    print(f"{len(nodes)} nodes in total")
    loopCnt = 0

    change = True
    while change:
        change = False
        for node in nodes:
            in_map[node].clear()
            for pred in node.predecessors:
                in_map[node].meet(out_map[pred])
            change = analyzeBlock(node) or change
        loopCnt += 1
    
        print(f"{loopCnt} loops")

def processIRSB(node:angr.knowledge_plugins.cfg.cfg_node.CFGNode):
    irsb:pyvex.IRSB = node.block.vex
    print("In[]:\n" + in_map[node].toString() + "\n")
    for i, ir in enumerate(irsb.statements):
        loc = location(node, i)
        if loc in context_map:
            print(loc.__str__() + (context_map[loc].toString()) + '\n')



from parse_mapping import AddressExp

class WrapVex:
    def __init__(self, ir) -> None:
        self.ir:pyvex.IRExpr = ir
        self.offset:int = 0
        self.regs:dict = {}



def is_simple_expr(expr:pyvex.expr.IRExpr, curNode) -> bool:
    ''' only has imme/reg and +/-
    '''
    
    if isinstance(expr, pyvex.expr.Binop):
        if expr.op.startswith("Iop_Add") or expr.op.startswith("Iop_Sub"):
            return is_simple_expr(expr.args[0], curNode) and is_simple_expr(expr.args[1], curNode)
        else:
            return False
    
    elif isinstance(expr, pyvex.expr.Unop):
        if expr.op.startswith("Iop_Neg") or pyvex.expr.cast_signature_re.match(expr.op):
            return is_simple_expr(expr.args[0], curNode)
        else:
            return False
        
    elif isinstance(expr, pyvex.expr.RdTmp):
        define:pyvex.IRExpr = def_mgr.getDef(curNode.block.vex, expr.tmp)
        return is_simple_expr(define, curNode)
    
    elif isinstance(expr, pyvex.IRExpr.Get):
        regOff:int = expr.offset
        return True
    
    elif isinstance(expr, pyvex.expr.Const):
        return True
    
    else:
        return False

def get_simple_expr(expr:pyvex.expr.IRExpr, curNode) -> AddressExp:
    ''' get regs and offset from a simple pyvex.expr
    '''
    if isinstance(expr, pyvex.expr.Binop):
        isAdd = True if expr.op.startswith("Iop_Add") else False
        exp1:AddressExp = get_simple_expr(expr.args[0])
        exp2:AddressExp = get_simple_expr(expr.args[1])
        return exp1.add(exp2) if isAdd else exp1.sub(exp2)
    
    elif isinstance(expr, pyvex.expr.Unop):
        assert(expr.op.startswith("Iop_Neg"))
        exp:AddressExp = get_simple_expr(expr.args[0])
        exp.offset = -exp.offset
        for reg in exp.regs:
            exp.regs[reg] = -exp.regs[reg]
        return exp

    elif isinstance(expr, pyvex.expr.Const):
        # const
        exp = AddressExp()
        exp.offset = expr.con.value
        return exp
    
    elif isinstance(expr, pyvex.expr.RdTmp):
        # temp variable
        define = def_mgr.getDef(curNode.block.vex, expr.tmp)
        return get_simple_expr(define)
    
    elif isinstance(expr, pyvex.expr.Get):
        # register
        exp = AddressExp()
        exp.regs[vex_to_dwarf[expr.offset]] = 1
        return exp
    
    else:
        assert(0)




def match(irExpr:pyvex.IRExpr, addrExp:AddressExp, curNode:angr.knowledge_plugins.cfg.cfg_node.CFGNode):
    isMatch:bool = False

    if isinstance(irExpr, pyvex.expr.Binop):
        if op_match(addrExp.op, irExpr.op):
            isMatch = match(irExpr.args[0], addrExp.sub1, curNode) and match(irExpr.args[1], addrExp.sub2, curNode)
            isMatch = isMatch or match(irExpr.args[0], addrExp.sub2, curNode) and match(irExpr.args[1], addrExp.sub1, curNode)
        
        elif is_simple_expr(irExpr, curNode):
            addrExp_from_ir = get_simple_expr(irExpr, curNode)
            isMatch = addrExp.is_same_simple_expr(addrExp_from_ir)
        
    elif isinstance(irExpr, pyvex.expr.Unop):
        if op_match(addrExp.op, irExpr.op):
            isMatch = match(irExpr.args[0], addrExp.sub1, curNode)
        
        elif is_simple_expr(irExpr, curNode):
            addrExp_from_ir = get_simple_expr(irExpr, curNode)
            isMatch = addrExp.is_same_simple_expr(addrExp_from_ir)
    
    elif isinstance(irExpr, pyvex.expr.RdTmp):
        # temp variable
        define = def_mgr.getDef(curNode.block.vex, irExpr.tmp)
        isMatch = match(define, addrExp, curNode)
    
    elif isinstance(irExpr, pyvex.expr.Load):
        ''' memory

        hope addrExp is just a `mem`
        '''
        assert(addrExp.isMem())
        isMatch = match(irExpr.addr, addrExp.mem, curNode)

    elif isinstance(irExpr, pyvex.expr.Const):
        ''' const
        '''
        isMatch = irExpr.con.value == addrExp.offset

    elif isinstance(irExpr, pyvex.expr.ITE):
        ''' selection based on cmp result, similar to `phi`
        '''
        isMatch = match(irExpr.iffalse, addrExp, curNode) or match(irExpr.iftrue, addrExp, curNode)
    

    elif isinstance(irExpr, pyvex.expr.Get):
        ''' register
        '''
        isMatch = vex_to_dwarf(irExpr.offset) == addrExp.reg
        if addrExp.regs and len(list(addrExp.regs.keys())) == 1:
            isMatch = isMatch or vex_to_dwarf(irExpr.offset) == list(addrExp.regs.keys())[0]


    else:
        isMatch = False
    
    return isMatch


if __name__ == "__main__":   
    proj = angr.Project(sys.argv[1], load_options={'auto_load_libs' : False})
    cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
    analyzeCFG(cfg)
    # traverse(proj, cfg, processIRSB=processIRSB)
    # traverse(proj, cfg)