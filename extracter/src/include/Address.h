#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "Expression.h"
#include "jsonUtil.h"
#include "type.h"

namespace varviewer {

enum class DwarfType { MEMORY, REGISTER, VALUE };

/*
特定的地址表达式，继承自Expression
*/
class AddressExp : public Expression {
 public:
  AddressExp() = default;

  AddressExp(DwarfType type);

  // no reset startpc and endpc now
  void ResetData();

  void Output() const;

  std::string ToString();

  friend json createJsonforAddressExp(const AddressExp &addrexp);
  /*
  in dwarf standard, pieces belong to the same location expression,
    however I take each piece into an addrExp seperately, because each
    piece may have different `type`.
  */
  piece_type piece_;

  /*if type == MEMORY or type == CONSTANT, use Expression of the father class is enough*/
  DwarfType dwarfType_{DwarfType::MEMORY};

  /* detailed type of variable*/
  int detailedDwarfType_;

  /*valid if type == REGISTER 如果 reg==128，说明这个变量不是寄存器变量*/
  Dwarf_Half reg_{REG_END};

  /*endpc not include in range*/
  Dwarf_Addr startpc_, endpc_;

  /*whether need CFA*/
  bool needCFA_{false};
  /*
  only valid when `DW_OP_call_frame_cfa` used, record cfa values between [startpc, endpc)
  对应全局变量frameBase
  */
  std::vector<Dwarf_Addr> cfa_pcs_;

  std::vector<Expression> cfa_values_;
};

/*
    `Address` record address info of some lifetimes of a variable
*/
class Address {
 public:
  Address() = default;

  Address(DwarfType _type);

  void Output();

  void UpdateValid();

  friend json createJsonforAddress(const Address &addr);

  bool valid_{false};

  /*name*/
  std::string name_;

  std::shared_ptr<Type> type_info_;

  /* addrs包括所有AddressExp 一个addrExp对应一个location expression*/
  std::vector<AddressExp> addrs_;

  /* 源文件 */
  std::string decl_file_;

  /* 声明行，列 */
  Dwarf_Unsigned decl_row_, decl_col_;
};

}  // namespace varviewer
