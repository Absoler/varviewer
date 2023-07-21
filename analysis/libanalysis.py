#!/usr/local/bin/python3
import angr, pyvex
import sys
import copy
from dwarf_vex_map import *
from dwarf_iced_map import *
from z3 import *
import re
from hint import Hint

''' function symbols
'''
load8:FuncDeclRef = Function("load8", BitVecSort(64), BitVecSort(8))
load16:FuncDeclRef = Function("load16", BitVecSort(64), BitVecSort(16))
load32:FuncDeclRef = Function("load32", BitVecSort(64), BitVecSort(32))
load64:FuncDeclRef = Function("load64", BitVecSort(64), BitVecSort(64))
load128:FuncDeclRef = Function("load128", BitVecSort(64), BitVecSort(128))

load_funcs:dict = {
    8 : load8,
    16 : load16,
    32 : load32,
    64 : load64,
    128 : load128
}

x = BitVec("addr_x", 64)
loads_cond = ForAll(x, And(load64(x) == SignExt(56, load8(x)),
                          load64(x) == SignExt(48, load16(x)),
                          load64(x) == SignExt(32, load32(x)),
                          load64(x) == Extract(63, 0, load128(x))))

loadu_cond = ForAll(x, And(load64(x) == ZeroExt(56, load8(x)),
                          load64(x) == ZeroExt(48, load16(x)),
                          load64(x) == ZeroExt(32, load32(x)),
                          load64(x) == Extract(63, 0, load128(x))))

un_cast_re = re.compile(r"Iop_(F|V)?(?P<srcsize>\d+)(U|S|HI|LO)?to(F|V)?(?P<dstsize>\d+)")
bin_cast_re = re.compile(r"Iop_(F|V)?(?P<srcsize>\d+)(HL)to(F|V)?(?P<dstsize>\d+)")
cmpF_re = re.compile(r"Iop_Cmp(F)(?P<size>\d+)$")
''' float conversion, take an extra 32-bit rounding mode arg
'''
f_cast_re = re.compile(r"Iop_(F|I)(?P<srcsize>\d+)(U|S)?to(F|I)(?P<dstsize>\d+)(U|S)?")

def post_format(z3_expr:ExprRef):
    if isinstance(z3_expr, BoolRef):
        return If(z3_expr, BitVecVal(1, 64), BitVecVal(0, 64))
    
    if isinstance(z3_expr, BitVecRef):
        if z3_expr.size() != 64:
            z3_expr = Extract(63, 0, z3_expr) if z3_expr.size() > 64 else ZeroExt(64 - z3_expr.size(), z3_expr)


    return z3_expr

def getConstOffset(exp1:BitVecRef, exp2:BitVecRef, conds:list):
    ''' return constant offset of two `BitVecRef` if can else `None` 
    '''
    assert(exp1.size()==exp2.size())
    slv = Solver()
    for cond in conds:
        slv.add(cond)
    off = BitVec("off", exp1.size())
    slv.add(exp1-exp2==off)
    if slv.check():
        m = slv.model()
        old_off = m.eval(off)

        slv.add(off!=old_off)
        if slv.check() == unsat:
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
            s += vex_reg_names[i*8+16] + ":\n" 
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
        self.blockAddr_to_defs:dict[int, dict] = {}
    
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
    
    # print(f"{len(nodes)} nodes in total")
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
    
        # print(f"{loopCnt} loops")

def processIRSB(node:angr.knowledge_plugins.cfg.cfg_node.CFGNode):
    irsb:pyvex.IRSB = node.block.vex
    print("In[]:\n" + in_map[node].toString() + "\n")
    for i, ir in enumerate(irsb.statements):
        loc = location(node, i)
        if loc in context_map:
            print(loc.__str__() + (context_map[loc].toString()) + '\n')



def get_z3_expr_from_vex(irExpr:pyvex.IRExpr, curNode:angr.knowledge_plugins.cfg.cfg_node.CFGNode):
    ''' stop at the first register
    '''
    if isinstance(irExpr, pyvex.expr.Binop):
        
        if irExpr.op.startswith("Iop_Add"):
            return get_z3_expr_from_vex(irExpr.args[0], curNode) + get_z3_expr_from_vex(irExpr.args[1], curNode)
        
        elif irExpr.op.startswith("Iop_Sub"):
            return get_z3_expr_from_vex(irExpr.args[0], curNode) - get_z3_expr_from_vex(irExpr.args[1], curNode)
        
        elif irExpr.op.startswith("Iop_DivMod"):
            e1:BitVecRef = get_z3_expr_from_vex(irExpr.args[0], curNode)
            e2:BitVecRef = get_z3_expr_from_vex(irExpr.args[1], curNode)
            if e2.size() < e1.size():
                e2 = ZeroExt(e1.size()-e2.size(), e2)
            return e1 % e2
        
        elif irExpr.op.startswith("Iop_Div"):
            e1:BitVecRef = get_z3_expr_from_vex(irExpr.args[0], curNode)
            e2:BitVecRef = get_z3_expr_from_vex(irExpr.args[1], curNode)
            if e2.size() < e1.size():
                e2 = ZeroExt(e1.size()-e2.size(), e2)
            return e1 / e2
        
        elif pyvex.expr.mull_signature_re.match(irExpr.op):
            size, _ = pyvex.expr.mull_signature(irExpr.op)
            size = int(size[5:])
            exp1, exp2 = get_z3_expr_from_vex(irExpr.args[0], curNode), get_z3_expr_from_vex(irExpr.args[1], curNode)
            if "S" in irExpr.op:
                return SignExt(size//2, exp1 * exp2)
            else:
                return ZeroExt(size//2, exp1 * exp2)

        elif irExpr.op.startswith("Iop_Mul"):
            return get_z3_expr_from_vex(irExpr.args[0], curNode) * get_z3_expr_from_vex(irExpr.args[1], curNode)

        elif irExpr.op.startswith("Iop_And"):
            return get_z3_expr_from_vex(irExpr.args[0], curNode) & get_z3_expr_from_vex(irExpr.args[1], curNode)
        
        elif irExpr.op.startswith("Iop_Or"):
            return get_z3_expr_from_vex(irExpr.args[0], curNode) | get_z3_expr_from_vex(irExpr.args[1], curNode)
        
        elif irExpr.op.startswith("Iop_Xor"):
            return get_z3_expr_from_vex(irExpr.args[0], curNode) ^ get_z3_expr_from_vex(irExpr.args[1], curNode)
        
        elif irExpr.op.startswith("Iop_Shl"):
            base:BitVecRef = get_z3_expr_from_vex(irExpr.args[0], curNode)
            index:BitVecRef = get_z3_expr_from_vex(irExpr.args[1], curNode)
            if index.size() < base.size():
                if isinstance(index, BitVecNumRef):
                    index = BitVecVal(index.as_long(), base.size())
                else:
                    index = ZeroExt(base.size()-index.size(), index)
            return base << index
        
        elif irExpr.op.startswith("Iop_Shr"):
            base:BitVecRef = get_z3_expr_from_vex(irExpr.args[0], curNode)
            index:BitVecRef = get_z3_expr_from_vex(irExpr.args[1], curNode)
            if index.size() < base.size():
                if isinstance(index, BitVecNumRef):
                    index = BitVecVal(index.as_long(), base.size())
                else:
                    index = ZeroExt(base.size()-index.size(), index)
            return LShR(base, index)

        elif irExpr.op.startswith("Iop_Sar"):
            base:BitVecRef = get_z3_expr_from_vex(irExpr.args[0], curNode)
            index:BitVecRef = get_z3_expr_from_vex(irExpr.args[1], curNode)
            if index.size() < base.size():
                if isinstance(index, BitVecNumRef):
                    index = BitVecVal(index.as_long(), base.size())
                else:
                    index = ZeroExt(base.size()-index.size(), index)
            return If(base<0, (base+1)/(1<<index) - 1, base/(1<<index))
        
        elif cmpF_re.match(irExpr.op):
            exp1, exp2 = get_z3_expr_from_vex(irExpr.args[0], curNode), get_z3_expr_from_vex(irExpr.args[1], curNode)
            return BitVec("cmpf", 32)

        elif irExpr.op.startswith("Iop_CmpEQ"):
            exp1, exp2 = get_z3_expr_from_vex(irExpr.args[0], curNode), get_z3_expr_from_vex(irExpr.args[1], curNode)
            return If(exp1==exp2, BitVecVal(1, 1), BitVecVal(0, 1))
        
        elif irExpr.op.startswith("Iop_CmpGE"):
            exp1, exp2 = get_z3_expr_from_vex(irExpr.args[0], curNode), get_z3_expr_from_vex(irExpr.args[1], curNode)
            return If(exp1>=exp2, BitVecVal(1, 1), BitVecVal(0, 1))
        
        elif irExpr.op.startswith("Iop_CmpGT"):
            exp1, exp2 = get_z3_expr_from_vex(irExpr.args[0], curNode), get_z3_expr_from_vex(irExpr.args[1], curNode)
            return If(exp1>exp2, BitVecVal(1, 1), BitVecVal(0, 1))
        
        elif irExpr.op.startswith("Iop_CmpLE"):
            exp1, exp2 = get_z3_expr_from_vex(irExpr.args[0], curNode), get_z3_expr_from_vex(irExpr.args[1], curNode)
            return If(exp1<=exp2, BitVecVal(1, 1), BitVecVal(0, 1))
        
        elif irExpr.op.startswith("Iop_CmpLT"):
            exp1, exp2 = get_z3_expr_from_vex(irExpr.args[0], curNode), get_z3_expr_from_vex(irExpr.args[1], curNode)
            return If(exp1<exp2, BitVecVal(1, 1), BitVecVal(0, 1))
        
        elif irExpr.op.startswith("Iop_CmpNE"):
            exp1, exp2 = get_z3_expr_from_vex(irExpr.args[0], curNode), get_z3_expr_from_vex(irExpr.args[1], curNode)
            return If(exp1!=exp2, BitVecVal(1, 1), BitVecVal(0, 1))
        
        elif f_cast_re.match(irExpr.op):
            ''' omit extra rounding mode
            '''
            src_size, dst_size = int(f_cast_re.match(irExpr.op).group("srcsize")), int(f_cast_re.match(irExpr.op).group("dstsize"))
            old_expr:BitVecRef = get_z3_expr_from_vex(irExpr.args[1], curNode)
            if src_size < dst_size:
                return SignExt(dst_size-src_size, old_expr) if "S" in irExpr.op else ZeroExt(dst_size-src_size, old_expr)
            else:
                return Extract(dst_size-1, 0, old_expr)

        elif bin_cast_re.match(irExpr.op):
            ''' concat args[0] and args[1] to a larger value
            '''
            
            src_size, dst_size = int(bin_cast_re.match(irExpr.op).group("srcsize")), int(bin_cast_re.match(irExpr.op).group("dstsize"))

            high_part = Extract(src_size-1, 0, get_z3_expr_from_vex(irExpr.args[0], curNode))
            low_part = Extract(src_size-1, 0, get_z3_expr_from_vex(irExpr.args[1], curNode))
            return Concat(high_part, low_part)

        else:
            print(f"unhandle op {irExpr.op}", file=sys.stderr)
            ''' 
            '''
            return get_z3_expr_from_vex(irExpr.args[0], curNode)
            assert(0)

    elif isinstance(irExpr, pyvex.expr.Unop):
        if irExpr.op.startswith("Iop_Abs"):
            return Abs(get_z3_expr_from_vex(irExpr.args[0], curNode))
        
        elif irExpr.op.startswith("Iop_Neg"):
            return -get_z3_expr_from_vex(irExpr.args[0], curNode)
        
        elif irExpr.op.startswith("Iop_Not"):
            return ~get_z3_expr_from_vex(irExpr.args[0], curNode)
        
        elif un_cast_re.match(irExpr.op):
            ''' convert operator
            '''
            src_size, dst_size = int(un_cast_re.match(irExpr.op).group("srcsize")), int(un_cast_re.match(irExpr.op).group("dstsize"))
            old_expr:BitVecRef = get_z3_expr_from_vex(irExpr.args[0], curNode)
            
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
            return get_z3_expr_from_vex(irExpr.args[0], curNode)
    
    elif isinstance(irExpr, pyvex.expr.RdTmp):
        # temp variable
        define = def_mgr.getDef(curNode.block.vex, irExpr.tmp)
        return get_z3_expr_from_vex(define, curNode)
    
    elif isinstance(irExpr, pyvex.expr.Load):
        ''' memory

        hope addrExp is just a `mem`
        '''
        size = int(pyvex.const.type_str_re.match(irExpr.type).group("size"))
        if size in load_funcs:
            return load_funcs[size](get_z3_expr_from_vex(irExpr.addr, curNode))
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
        cond = get_z3_expr_from_vex(irExpr.cond, curNode)
        if not isinstance(cond, BoolRef):
            cond = If(cond != 0, True, False)
        iftrue = get_z3_expr_from_vex(irExpr.iftrue, curNode)
        iffalse = get_z3_expr_from_vex(irExpr.iffalse, curNode)
        return If(cond, iftrue, iffalse)
    

    elif isinstance(irExpr, pyvex.expr.Get):
        ''' register
            we only use 64-bit version names
        '''
        if irExpr.offset not in vex_reg_names:
            if irExpr.offset - 1 not in vex_reg_names:
                print(f'invalid register {irExpr.offset}')
                assert(0)
            reg_name = vex_reg_names[irExpr.offset - 1]
            return Extract(15, 8, BitVec(reg_name, 64))
        
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
    

def isReg(exp:BitVecRef) -> bool:
    return exp.decl().name() in vex_reg_size_codes

def extract_regs_from_z3(z3Expr:BitVecRef) -> list[BitVecRef]:
    ''' get all register names
    '''
    res = [z3Expr] if isReg(z3Expr) else []
    for child in z3Expr.children():
        res.extend(extract_regs_from_z3(child))
    return res

def is_regs_match(exp1:BitVecRef, exp2:BitVecRef):
    ''' 
    '''
    return True

def guess_reg_type(z3Expr:BitVecRef) -> dict[str, int]:
    ''' if reg is extracted to small type, record the bit num
    '''
    
    children = z3Expr.children()
    if len(children) == 0:
        return {}
    
    res = {}
    isExtract =  z3Expr.decl().name() == "extract"
    for child in children:
        if isExtract and isReg(child):
            r, l = z3Expr.params()
            res[child.decl().name()] = r-l+1
        res.update(guess_reg_type(child))
    
    return res
    

def cond_extract(reg:BitVecRef, bit_num:int):
    size = (1<<bit_num)
    # return And(reg<BitVecVal(size, 64), reg>=BitVecVal(0, 64))
    return ZeroExt(64-bit_num, Extract(bit_num-1, 0, reg)) == reg

if __name__ == "__main__":   
    proj = angr.Project(sys.argv[1], load_options={'auto_load_libs' : False})
    cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
    analyzeCFG(cfg)
    # traverse(proj, cfg, processIRSB=processIRSB)
    # traverse(proj, cfg)