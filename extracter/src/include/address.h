#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "expression.h"
#include "json_util.h"
#include "type.h"

namespace varviewer {

enum class DwarfType { MEMORY, REGISTER, VALUE };

/*
certain locotion expression
*/
class AddressExp : public Expression {
 public:
  AddressExp() = default;

  AddressExp(DwarfType type);

  AddressExp(const AddressExp &addrexp);

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

  /*valid if type == REGISTER, if reg == 128 , then this is not a register var */
  Dwarf_Half reg_{REG_END};

  /*endpc not include in range*/
  Dwarf_Addr startpc_, endpc_;

  /*whether need CFA*/
  bool needCFA_{false};
  /*
  only valid when `DW_OP_call_frame_cfa` used, record cfa values between [startpc, endpc)
  according to the global variable framebase
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

  Address(const Address &address) = default;

  Address &operator=(const Address &address) = default;

  void Output();

  void UpdateValid();

  friend json createJsonforAddress(const Address &addr);

  bool valid_{false};

  /* name */
  std::string name_;

  /* type info */
  std::shared_ptr<Type> type_info_;

  /* addrs contains of all AddrExp, one AddrExp correspond to a location operation*/
  std::vector<AddressExp> addrs_;

  /* source file */
  std::string decl_file_;

  /* declare row and line */
  Dwarf_Unsigned decl_row_, decl_col_;
};

}  // namespace varviewer
