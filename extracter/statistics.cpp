#include "statistics.h"
using namespace std;


void
Statistics::reset(){
    varCnt = 0;
    exprCnt = 0;

    memoryCnt = 0;
    memoryMultiCnt = 0;
    registerCnt = 0;
    implicitCnt = 0;
    implicitMultiCnt = 0;

    cfaCnt = 0;

    ops.clear();
    ops.reserve(32);
}

Statistics::Statistics(){
    reset();
}

void
Statistics::addOp(Dwarf_Small op){
    ops.push_back(op);
}

void
Statistics::addVar(){
    varCnt += 1;
}

void
Statistics::solveOneExpr(){
    if (ops.size() == 0){
        return;
    }

    exprCnt += 1;

    int dwarfType = 0;  // memory default

    for(unsigned i=0; i<ops.size(); ++i){

        Dwarf_Small op = ops[i];
        if(op == DW_OP_fbreg){
            cfaCnt += 1;
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
        if (ops.size() > 1U){
            memoryMultiCnt += 1;
        }
    }else if (dwarfType == 1) {
        registerCnt += 1;
    }else {
        implicitCnt += 1;
        if (ops.size() > 2U){
            implicitMultiCnt += 1;
        }

    }

    ops.clear();
}


string
Statistics::output(){
    string res;
    res += "all variables: " + to_string(varCnt) + "\n";
    res += "all expressions: " + to_string(exprCnt) + "\n";
    res += "memoryCnt: " + to_string(memoryCnt) + "    " + to_string((double)memoryCnt/(double)exprCnt) + "\n";
    res += "--- Multi: " + to_string(memoryMultiCnt) + "    " + to_string((double)memoryMultiCnt/(double)exprCnt) + "   " + to_string((double)memoryMultiCnt/(double)memoryCnt) + "\n";
    res += "--- single: " + to_string(memoryCnt - memoryMultiCnt)+ "    " + to_string((double)(memoryCnt - memoryMultiCnt)/(double)exprCnt) + "    " + to_string((double)(memoryCnt-memoryMultiCnt)/(double)memoryCnt) +  "\n";
    res += "registerCnt: " + to_string(registerCnt) + "    " + to_string((double)registerCnt/(double)exprCnt) + "\n";
    res += "implicitCnt: " + to_string(implicitCnt) + "    " + to_string((double)implicitCnt/(double)exprCnt) + "\n";
    res += "--- Multi: " + to_string(implicitMultiCnt)+ "    " + to_string((double)implicitMultiCnt/(double)exprCnt) + "    " + to_string((double)implicitMultiCnt/(double)implicitCnt) +  "\n";
    res += "--- single: " + to_string(implicitCnt - implicitMultiCnt)+ "    " + to_string((double)(implicitCnt - implicitMultiCnt)/(double)exprCnt) + "    " + to_string((double)(implicitCnt-implicitMultiCnt)/(double)implicitCnt) +  "\n";
    res += "cfa related: " + to_string(cfaCnt)+ "    " + to_string((double)cfaCnt/(double)exprCnt) + "    " + to_string((double)cfaCnt/(double)(memoryCnt + implicitCnt)) + "\n";
    return res;
}