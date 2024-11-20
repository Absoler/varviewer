#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>

#include <memory>
#include <ostream>
#include <string>

#include "json.hpp"
#include "type.h"
namespace varviewer {

using json = nlohmann::json;

static constexpr int REG_END = 128;

extern const char *reg_names[REG_END];

/*
    Expression is a symbolic simulation of dynamic calculation of Dwarf expression
*/
class Expression {
 public:
  Expression();

  ~Expression() = default;

  Expression(Dwarf_Unsigned val_u);

  Expression(Dwarf_Signed val_s);

  static Expression CreateEmpty();

  static Expression CreateCFA();

  bool Equal(const Expression &other);

  static bool ValidBinOp(const Expression &exp1, const Expression &exp2, Dwarf_Small op);

  static Expression BinOp(const Expression &exp1, const Expression &exp2, Dwarf_Small op);

  static bool ValidUnaryOp(const Expression &exp, Dwarf_Small op);

  static Expression UnaryOp(const Expression &exp, Dwarf_Small op);

  bool NoReg() const;

  friend json createJsonforExpression(const Expression &exp);

  void Reset();  // clear data

  void Output() const;

  void SetFromExp(const Expression &);  // deep copy from another expression

  std::string ToString();

  /* error when generating this */
  bool valid_{true};
  /* optimized away by compiler */
  bool empty_{false};
  /* indicate whether signed */
  bool sign_{true};
  /*
    the value of `Expression` is val + reg0 * reg_scale[0] + reg1 * reg_scale[1] ... + *(mem)
  */
  Dwarf_Signed reg_scale_[REG_END];
  /* 对于全局变量 ，offset就是它的地址 */
  Dwarf_Unsigned offset_;

  std::shared_ptr<Expression> mem_;

  Dwarf_Small mem_size_ = 0;
  /*
      if true, then this expression is the currenet cfa value
  */
  bool isCFA_{false};
  /*
      operation can't express inside one expression will expand a single expression node to a binary tree
  */
  std::shared_ptr<Expression> sub1_{nullptr}, sub2_{nullptr};

  Dwarf_Small op_;

  bool hasChild_{false};
};

}  // namespace varviewer
