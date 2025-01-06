#pragma once
#include <memory>
#include <unordered_set>
#include "address.h"
#include "expression.h"
#include "json.hpp"
#include "type.h"
class Address;
class AddressExp;
class Type;

namespace varviewer {
/*
    {
        "addrs" : [
            <AddressExp>
        ]
        "name" : <string>
        "decl_file" : <string>
        "decl_row"  : <Dwarf_Unsigned>
        "decl_col"  : <Dwarf_Unsigned>
        "piece_num" : <int>
        "valid" : <bool>
    }
*/

json createJsonforAddress(const Address &addr);

/*
    {
        Expression part ...

        "dwarfType" : <int>
        "detailedDwarfType" : <int>
        "startpc" : <Dwarf_Addr>
        "endpc" : <Dwarf_Addr>
        "reg" : <Dwarf_Half>
        "piece_start" : <Dwarf_Addr>,
        "piece_size" : <int>

        "needCFA" : <bool>
        "cfa_values" : [
            <Expression>
        ]
        "cfa_pcs" : [
            <Dwarf_Addr>
        ]
    }
*/
json createJsonforAddressExp(const AddressExp &addrexp);

/*
    {
        "offset" : <Dwarf_Unsigned>
        "regs" : {
            <int>(reg_ind) : <int>(scale),
        }
        "mem" : <Expression>
        "mem_size" : <Dwarf_Small>
        "valid" : <bool>
        "empty" : <bool>
        "sign" : <bool>

        "hasChild" : <bool>
        "sub1" : <Expression>
        "sub2" : <Expression>
        "op" : <Dwarf_Unsigned>

        "isCFA" : <Bool>
    }
*/
json createJsonforExpression(const Expression &exp);

/*
  {
      "typeName" : <string>
      "size" : <size_t>
      "userDefined" : <bool>
      "isPointer" : <bool>
      "pointerLevel" : <size_t>
      "members" : {
          <string>(offset) : {
              "name" : <string>
              "type" : <Type>  // may recursive here
          }
      }
  }
*/
json createJsonForType(const std::shared_ptr<Type> &type, std::unordered_set<std::string> &visited);

}  // namespace varviewer
