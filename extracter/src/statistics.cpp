#include "include/statistics.h"

#include <iostream>
namespace varviewer {
void Statistics::reset() {
  // std::cout << "in statistics reset\n";
  varCnt = 0;
  exprCnt = 0;

  memoryCnt = 0;
  globalCnt = 0;
  cfaCnt = 0;
  memoryMultiCnt = 0;

  registerCnt = 0;

  implicitCnt = 0;
  implicitMultiCnt = 0;

  isParam_ = false;

  ops_.clear();
  ops_.reserve(32);
}

Statistics::Statistics() { reset(); }

void Statistics::addOp(Dwarf_Small op) {
  if (op == DW_OP_piece) {
    return;
  }
  ops_.push_back(op);
}

void Statistics::addVar(Dwarf_Half tag) {
  varCnt += 1;
  isParam_ = (tag == DW_TAG_formal_parameter);
}

DetailedDwarfType Statistics::solveOneExpr() {
  DetailedDwarfType res = DetailedDwarfType::INVALID;
  if (ops_.size() == 0) {
    return res;
  }
  std::cout << "statistics ops_ size:" << ops_.size() << "\n";
  exprCnt += 1;

  int dwarfType = 0;  // memory default
  bool hasCFA = false;

  for (unsigned i = 0; i < ops_.size(); ++i) {
    Dwarf_Small op = ops_[i];
    if (op == DW_OP_fbreg) {
      hasCFA = true;
    }

    if (op >= DW_OP_reg0 && op <= DW_OP_reg31) {
      dwarfType = 1;
    }
    if (op == DW_OP_stack_value) {
      dwarfType = 2;
    }
  }

  if (dwarfType == 0) {
    memoryCnt += 1;
    res = DetailedDwarfType::MEM_SINGLE;
    if (ops_.size() > 1U) {
      memoryMultiCnt += 1;
      res = DetailedDwarfType::MEM_MULTI;
    } else if (ops_[0] == DW_OP_addr) {
      globalCnt += 1;
      res = DetailedDwarfType::MEM_GLOABL;
    }
    if (hasCFA) {
      cfaCnt += 1;
      res = DetailedDwarfType::MEM_CFA;
    }

  } else if (dwarfType == 1) {
    paramRegCnt += (isParam_ ? 1 : 0);
    registerCnt += 1;
    res = (isParam_ ? DetailedDwarfType::REG_PARAM : DetailedDwarfType::REG_OTHER);
  } else {
    implicitCnt += 1;
    if (ops_.size() > 2U) {
      implicitMultiCnt += 1;
    }
    res = DetailedDwarfType::IMPLICIT;
  }
  // clear ops_
  {
    std::vector<Dwarf_Small> tmp;
    ops_.swap(tmp);
  }
  return res;
}

std::string Statistics::output() {
  std::string res;
  res += "all variables: " + std::to_string(varCnt) + "\n";
  res += "all expressions: " + std::to_string(exprCnt) + "\n";
  res +=
      "memoryCnt: " + std::to_string(memoryCnt) + "    " + std::to_string((double)memoryCnt / (double)exprCnt) + "\n";
  res += "--- global count: " + std::to_string(globalCnt) + "    " +
         std::to_string((double)globalCnt / (double)exprCnt) + "    " +
         std::to_string((double)globalCnt / (double)memoryCnt) + "\n";
  res += "--- cfa related: " + std::to_string(cfaCnt) + "    " + std::to_string((double)cfaCnt / (double)exprCnt) +
         "    " + std::to_string((double)cfaCnt / (double)(memoryCnt)) + "\n";
  res += "--- Multi: " + std::to_string(memoryMultiCnt) + "    " +
         std::to_string((double)memoryMultiCnt / (double)exprCnt) + "   " +
         std::to_string((double)memoryMultiCnt / (double)memoryCnt) + "\n";
  res += "--- single: " + std::to_string(memoryCnt - memoryMultiCnt - globalCnt - cfaCnt) + "    " +
         std::to_string((double)(memoryCnt - memoryMultiCnt - globalCnt - cfaCnt) / (double)exprCnt) + "    " +
         std::to_string((double)(memoryCnt - memoryMultiCnt - globalCnt - cfaCnt) / (double)memoryCnt) + "\n";
  res += "registerCnt: " + std::to_string(registerCnt) + "    " +
         std::to_string((double)registerCnt / (double)exprCnt) + "\n";
  res += "--- paramRegCnt: " + std::to_string(paramRegCnt) + "    " +
         std::to_string((double)paramRegCnt / (double)exprCnt) + "    " +
         std::to_string((double)paramRegCnt / (double)registerCnt) + "\n";
  res += "--- non-paramRegCnt: " + std::to_string(registerCnt - paramRegCnt) + "    " +
         std::to_string((double)(registerCnt - paramRegCnt) / (double)exprCnt) + "    " +
         std::to_string((double)(registerCnt - paramRegCnt) / (double)registerCnt) + "\n";
  res += "implicitCnt: " + std::to_string(implicitCnt) + "    " +
         std::to_string((double)implicitCnt / (double)exprCnt) + "\n";
  res += "--- Multi: " + std::to_string(implicitMultiCnt) + "    " +
         std::to_string((double)implicitMultiCnt / (double)exprCnt) + "    " +
         std::to_string((double)implicitMultiCnt / (double)implicitCnt) + "\n";
  res += "--- single: " + std::to_string(implicitCnt - implicitMultiCnt) + "    " +
         std::to_string((double)(implicitCnt - implicitMultiCnt) / (double)exprCnt) + "    " +
         std::to_string((double)(implicitCnt - implicitMultiCnt) / (double)implicitCnt) + "\n";
  return res;
}
}  // namespace varviewer
