#include "statistics.h"
using namespace std;


void
Statistics::reset(){
    varCnt = 0;
    exprCnt = 0;

    memoryCnt = 0;
    globalCnt = 0;
    cfaCnt = 0;
    memoryMultiCnt = 0;
    
    registerCnt = 0;
    
    implicitCnt = 0;
    implicitMultiCnt = 0;

    isParam = false;

    ops.clear();
    ops.reserve(32);
}

Statistics::Statistics(){
    reset();
}

void
Statistics::addOp(Dwarf_Small op){
    if (op == DW_OP_piece) {
        return;
    }
    ops.push_back(op);
}

void
Statistics::addVar(Dwarf_Half tag){
    varCnt += 1;
    isParam = (tag == DW_TAG_formal_parameter);
}

DetailedDwarfType
Statistics::solveOneExpr(){
    DetailedDwarfType res = DetailedDwarfType::INVALID;
    if (ops.size() == 0){
        return res;
    }

    exprCnt += 1;

    int dwarfType = 0;  // memory default
    bool hasCFA = false;

    for(unsigned i=0; i<ops.size(); ++i){

        Dwarf_Small op = ops[i];
        if(op == DW_OP_fbreg){
            hasCFA = true;
        }

        if(op >= DW_OP_reg0 && op <= DW_OP_reg31){
            dwarfType = 1;
        }
        if(op == DW_OP_stack_value){
            dwarfType = 2;
        }
    }

    if (dwarfType == 0) {
        memoryCnt += 1;
        res = DetailedDwarfType::MEM_SINGLE;
        if (ops.size() > 1U){
            memoryMultiCnt += 1;
            res = DetailedDwarfType::MEM_MULTI;
        }else if (ops[0] == DW_OP_addr){
            globalCnt += 1;
            res = DetailedDwarfType::MEM_GLOABL;
        }
        if (hasCFA){
            cfaCnt += 1;
            res = DetailedDwarfType::MEM_CFA;
        }

    }else if (dwarfType == 1) {
        paramRegCnt += (isParam ? 1:0);
        registerCnt += 1;
        res = (isParam ? DetailedDwarfType::REG_PARAM : DetailedDwarfType::REG_OTHER);
    }else {
        implicitCnt += 1;
        if (ops.size() > 2U){
            implicitMultiCnt += 1;
        }
        res = DetailedDwarfType::IMPLICIT;

    }

    {
        vector<Dwarf_Small> tmp;
        ops.swap(tmp);
    }
    return res;
}


string
Statistics::output(){
    string res;
    res += "all variables: " + to_string(varCnt) + "\n";
    res += "all expressions: " + to_string(exprCnt) + "\n";
    res += "memoryCnt: " + to_string(memoryCnt) + "    " + to_string((double)memoryCnt/(double)exprCnt) + "\n";
    res += "--- global count: " + to_string(globalCnt) + "    " + to_string((double)globalCnt/(double)exprCnt) + "    " + to_string((double)globalCnt/(double)memoryCnt) + "\n";
    res += "--- cfa related: " + to_string(cfaCnt)+ "    " + to_string((double)cfaCnt/(double)exprCnt) + "    " + to_string((double)cfaCnt/(double)(memoryCnt)) + "\n";
    res += "--- Multi: " + to_string(memoryMultiCnt) + "    " + to_string((double)memoryMultiCnt/(double)exprCnt) + "   " + to_string((double)memoryMultiCnt/(double)memoryCnt) + "\n";
    res += "--- single: " + to_string(memoryCnt - memoryMultiCnt - globalCnt - cfaCnt)+ "    " + to_string((double)(memoryCnt - memoryMultiCnt - globalCnt - cfaCnt)/(double)exprCnt) + "    " + to_string((double)(memoryCnt - memoryMultiCnt - globalCnt - cfaCnt)/(double)memoryCnt) +  "\n";
    res += "registerCnt: " + to_string(registerCnt) + "    " + to_string((double)registerCnt/(double)exprCnt) + "\n";
    res += "--- paramRegCnt: " + to_string(paramRegCnt) + "    " + to_string((double)paramRegCnt/(double)exprCnt) + "    " + to_string((double)paramRegCnt/(double)registerCnt) + "\n";
    res += "--- non-paramRegCnt: " + to_string(registerCnt - paramRegCnt) + "    " + to_string((double)(registerCnt - paramRegCnt)/(double)exprCnt) + "    " + to_string((double)(registerCnt - paramRegCnt)/(double)registerCnt) + "\n";
    res += "implicitCnt: " + to_string(implicitCnt) + "    " + to_string((double)implicitCnt/(double)exprCnt) + "\n";
    res += "--- Multi: " + to_string(implicitMultiCnt)+ "    " + to_string((double)implicitMultiCnt/(double)exprCnt) + "    " + to_string((double)implicitMultiCnt/(double)implicitCnt) +  "\n";
    res += "--- single: " + to_string(implicitCnt - implicitMultiCnt)+ "    " + to_string((double)(implicitCnt - implicitMultiCnt)/(double)exprCnt) + "    " + to_string((double)(implicitCnt-implicitMultiCnt)/(double)implicitCnt) +  "\n";
    return res;
}