#include "include/Expression.h"

#include <libdwarf-0/libdwarf.h>

#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <ios>
#include <iostream>
#include <string>

namespace varviewer {
/*
expression compression may cause problem to match with vex ir
*/
bool no_compress = true;

/* copy constructor */
Expression::Expression(const Expression &exp) {
  valid_ = exp.valid_;
  memcpy(reg_scale_, exp.reg_scale_, sizeof(reg_scale_));
  offset_ = exp.offset_;
  /* deep copy for shared_ptr */
  mem_ = exp.mem_ ? std::make_shared<Expression>(*exp.mem_) : nullptr;
  mem_size_ = exp.mem_size_;
  sign_ = exp.sign_;
  hasChild_ = exp.hasChild_;
  sub1_ = exp.sub1_ ? std::make_shared<Expression>(*exp.sub1_) : nullptr;  
  sub2_ = exp.sub2_ ? std::make_shared<Expression>(*exp.sub2_) : nullptr;  
  op_ = exp.op_;
  isCFA_ = exp.isCFA_;
}

/* defauly constructor */
Expression::Expression()
    : valid_(true),
      offset_(0),
      reg_scale_{0},
      mem_(nullptr),
      mem_size_(0),
      hasChild_(false),
      sub1_(nullptr),
      sub2_(nullptr),
      op_(0),
      isCFA_(false) {}

Expression::Expression(Dwarf_Unsigned _val_u) {
  Reset();
  offset_ = _val_u;
}

Expression::Expression(Dwarf_Signed _val_s) {
  Reset();
  offset_ = static_cast<Dwarf_Unsigned>(_val_s);
  sign_ = true;
}

Expression Expression::CreateEmpty() {
  Expression res;
  res.empty_ = true;
  return res;
}

Expression Expression::CreateCFA() {
  Expression res;
  res.isCFA_ = true;
  res.sign_ = true;
  return res;
}

bool Expression::Equal(const Expression &other) {
  bool res = (offset_ == other.offset_);
  res &= (mem_ == other.mem_);
  for (int i = 0; i < REG_END; ++i) {
    if (reg_scale_[i] != other.reg_scale_[i]) {
      res = false;
      break;
    }
  }

  res &= (hasChild_ == other.hasChild_);
  if (hasChild_) {
    res &= (op_ == other.op_);
    if (sub1_) {
      res &= (sub1_->Equal(*other.sub1_));
    }
    if (sub2_) {
      res &= (sub2_->Equal(*other.sub2_));
    }
  }

  res &= (isCFA_ == other.isCFA_);
  return res;
}

bool Expression::NoReg() const {
  for (int i = 0; i < REG_END; ++i) {
    if (reg_scale_[i]) return false;
  }
  return true;
}

bool Expression::ValidBinOp(const Expression &exp1, const Expression &exp2, Dwarf_Small op) {
  bool res = true;

  if (op == DW_OP_plus) {
  } else if (op == DW_OP_div) {
    if (no_compress) {
      return false;
    }
    res = exp1.NoReg();
    res &= (exp1.offset_ != 0);

  } else if (op == DW_OP_minus) {
  } else if (op == DW_OP_mod) {
    if (no_compress) {
      return false;
    }
    res = exp1.NoReg();
    res &= (exp1.offset_ != 0);

  } else if (op == DW_OP_mul) {
    res = exp1.NoReg() || exp2.NoReg();

  } else if (op == DW_OP_or) {
    if (no_compress) {
      return false;
    }
    res = exp1.NoReg() && exp2.NoReg();

  } else if (op == DW_OP_and) {
    if (no_compress) {
      return false;
    }
    res = exp1.NoReg() && exp2.NoReg();

  } else if (op == DW_OP_shl) {
    if (no_compress) {
      return false;
    }
    res = exp1.NoReg() && exp2.NoReg();

  } else if (op == DW_OP_shr) {
    if (no_compress) {
      return false;
    }
    res = exp1.NoReg() && exp2.NoReg();
  } else if (op == DW_OP_shra) {
    if (no_compress) {
      return false;
    }
    res = exp1.NoReg() && exp2.NoReg();
  } else if (op >= DW_OP_eq && op <= DW_OP_ne) {
    if (no_compress) {
      return false;
    }
    res = exp1.NoReg() && exp2.NoReg();
  }

  if (exp1.isCFA_ || exp2.isCFA_) {
    res = false;
  }
  if (exp1.mem_ || exp2.mem_) {
    res = false;
  }
  if (exp1.hasChild_ || exp2.hasChild_) {
    res = false;
  }

  return res;
}

Expression Expression::BinOp(const Expression &exp1, const Expression &exp2, Dwarf_Small op) {
  /*
      binary operation of two expression
  */

  Expression res = exp1;

  if (!ValidBinOp(exp1, exp2, op)) {
    // expand to a binary tree
    res.Reset();
    res.hasChild_ = true;
    res.sub1_ = std::make_shared<Expression>();
    res.sub1_->SetFromExp(exp1);
    res.sub2_ = std::make_shared<Expression>();
    res.sub2_->SetFromExp(exp2);
    res.op_ = op;

    return res;
  }
  if (op == DW_OP_plus) {
    res.offset_ += exp2.offset_;
    for (int i = 0; i < REG_END; ++i) {
      res.reg_scale_[i] += exp2.reg_scale_[i];
    }

  } else if (op == DW_OP_div) {
    Dwarf_Signed divisor = (Dwarf_Signed)res.offset_;

    res.offset_ = (Dwarf_Signed)exp2.offset_ / divisor;
    for (int i = 0; i < REG_END; ++i) {
      res.reg_scale_[i] = (Dwarf_Signed)exp2.reg_scale_[i] / divisor;
    }
  } else if (op == DW_OP_minus) {
    res.offset_ = exp2.offset_ - res.offset_;
    for (int i = 0; i < REG_END; ++i) {
      res.reg_scale_[i] = exp2.reg_scale_[i] - res.reg_scale_[i];
    }
  } else if (op == DW_OP_mod) {
    for (int i = 0; i < REG_END; ++i) {
      res.reg_scale_[i] = exp2.reg_scale_[i] % res.offset_;
    }
    res.offset_ = exp2.offset_ % res.offset_;

  } else if (op == DW_OP_mul) {
    if (res.NoReg()) {
      for (int i = 0; i < REG_END; ++i) {
        res.reg_scale_[i] = res.offset_ * exp2.reg_scale_[i];
      }
    } else {
      for (int i = 0; i < REG_END; ++i) {
        res.reg_scale_[i] = exp2.offset_ * res.reg_scale_[i];
      }
    }
    res.offset_ = res.offset_ * exp2.offset_;

  } else if (op == DW_OP_or) {
    // must no reg
    res.offset_ |= exp2.offset_;
  } else if (op == DW_OP_and) {
    res.offset_ &= exp2.offset_;
  } else if (op == DW_OP_shl) {
    res.offset_ = exp2.offset_ << res.offset_;
  } else if (op == DW_OP_shr) {
    res.offset_ = exp2.offset_ >> res.offset_;
  } else if (op == DW_OP_shra) {
    res.offset_ = (Dwarf_Signed)exp2.offset_ >> res.offset_;
  } else if (op == DW_OP_xor) {
    res.offset_ ^= exp2.offset_;
  } else if (op == DW_OP_eq) {
    res.offset_ = (res.offset_ == exp2.offset_ ? 1 : 0);
  } else if (op == DW_OP_ge) {
    res.offset_ = (exp2.offset_ >= res.offset_ ? 1 : 0);
  } else if (op == DW_OP_gt) {
    res.offset_ = (exp2.offset_ > res.offset_ ? 1 : 0);
  } else if (op == DW_OP_le) {
    res.offset_ = (exp2.offset_ <= res.offset_ ? 1 : 0);
  } else if (op == DW_OP_lt) {
    res.offset_ = (exp2.offset_ < res.offset_);
  } else if (op == DW_OP_ne) {
    res.offset_ = (exp2.offset_ != res.offset_ ? 1 : 0);
  }

  return res;
}

Expression Expression::UnaryOp(const Expression &exp, Dwarf_Small op) {
  Expression res = exp;
  if (!ValidUnaryOp(exp, op)) {
    // expand to a binary tree with `sub2_` is NULL
    res.Reset();
    res.sub1_ = std::make_shared<Expression>();
    res.sub1_->SetFromExp(exp);
    res.op_ = op;
    return res;
  }

  if (op == DW_OP_neg) {
    res.offset_ = -((Dwarf_Signed)res.offset_);
    for (int i = 0; i < REG_END; ++i) {
      res.reg_scale_[i] = -res.reg_scale_[i];
    }
  } else if (op == DW_OP_abs) {
    res.offset_ = std::abs((Dwarf_Signed)res.offset_);
  } else if (op == DW_OP_not) {
    res.offset_ = ~res.offset_;
  }

  return res;
}

bool Expression::ValidUnaryOp(const Expression &exp, Dwarf_Small op) {
  bool res = true;
  if (op == DW_OP_neg) {
  } else if (op == DW_OP_abs) {
    if (no_compress) {
      return false;
    }
    res = exp.NoReg();
  } else if (op == DW_OP_not) {
    if (no_compress) {
      return false;
    }
    res = exp.NoReg();
  }

  res = !exp.isCFA_;
  res = res && exp.mem_;
  res = res && exp.hasChild_;

  return res;
}

void Expression::Reset() {
  valid_ = true;
  memset(reg_scale_, 0, sizeof(reg_scale_));
  offset_ = 0;
  mem_ = nullptr;
  mem_size_ = 0;
  hasChild_ = false;
  sub1_ = nullptr;
  sub2_ = nullptr;
  op_ = 0;
  isCFA_ = false;
}

void Expression::Output() const {
  printf("offset_ : %llx", offset_);
  for (int i = 0; i < REG_END; ++i) {
    if (reg_scale_[i]) {
      printf(" + %lld * %s", reg_scale_[i], reg_names[i]);
    }
  }
  printf("\n");
}

void Expression::SetFromExp(const Expression &exp) {
  empty_ = exp.empty_;
  valid_ = exp.valid_;
  memcpy(reg_scale_, exp.reg_scale_, sizeof(reg_scale_));
  offset_ = exp.offset_;
  mem_ = exp.mem_;
  mem_size_ = exp.mem_size_;
  sign_ = exp.sign_;
  hasChild_ = exp.hasChild_;
  sub1_ = exp.sub1_;
  sub2_ = exp.sub2_;
  op_ = exp.op_;
  isCFA_ = exp.isCFA_;
}

std::string Expression::ToString() {
  std::string res("");
  if (isCFA_) {
    res = "cfa";
    if (sign_) {
      res += " + (" + std::to_string((Dwarf_Signed)offset_) + ")";
    } else {
      res += " + " + std::to_string(offset_);
    }
  } else if (hasChild_) {
    const char *op_name;
    dwarf_get_OP_name(op_, &op_name);
    if (sub1_ && sub2_) {
      res += "(" + sub1_->ToString() + ") ";
      res += std::string(op_name);
      res += " (" + sub2_->ToString() + ")";
    } else {
      res += std::string(op_name);
      res += " (" + sub1_->ToString() + ")";
    }
  } else {
    if (offset_) res += std::to_string(offset_);
    for (int i = 0; i < REG_END; ++i) {
      if (reg_scale_[i]) {
        res += " +" + std::string(reg_names[i]) + "*" + std::to_string(reg_scale_[i]);
      }
    }
    if (mem_) {
      res += " + *(" + mem_->ToString() + (mem_size_ != 64 ? std::to_string(mem_size_) : "") + ")";
    }
  }
  return res;
}

const char *reg_names[REG_END] = {"rax",   "rdx",   "rcx",   "rbx",  "rsi",  "rdi",  "rbp",  "rsp",   "r8",    "r9",
                                  "r10",   "r11",   "r12",   "r13",  "r14",  "r15",  "RA",   "xmm0",  "xmm1",  "xmm2",
                                  "xmm3",  "xmm4",  "xmm5",  "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12",
                                  "xmm13", "xmm14", "xmm15", "st0",  "st1",  "st2",  "st3",  "st4",   "st5",   "st6",
                                  "st7",   "mm0",   "mm1",   "mm2",  "mm3",  "mm4",  "mm5",  "mm6",   "mm7",   "rFLAGS",
                                  "es",    "cs",    "ss",    "ds",   "fs",   "gs"};
}  // namespace varviewer
