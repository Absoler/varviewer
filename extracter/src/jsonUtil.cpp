#include "include/jsonUtil.h"

#include <libdwarf-0/libdwarf.h>

#include <ios>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "include/Address.h"
#include "include/Expression.h"

namespace varviewer {
json createJsonforExpression(const Expression &exp) {
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
  nlohmann::json res;
  std::cout << "exp.sign : " << std::boolalpha << exp.sign_ << "\n";
  if (exp.sign_) {
    res["offset"] = static_cast<Dwarf_Signed>(exp.offset_);
  } else {
    res["offset"] = exp.offset_;
  }

  nlohmann::json reg_dict;
  for (int i = 0; i < REG_END; ++i) {
    if (exp.reg_scale_[i]) {
      reg_dict[std::to_string(i)] = exp.reg_scale_[i];
      // reg_dict[i] = exp.reg_scale[i];
    }
  }
  res["regs"] = reg_dict;
  res["valid"] = exp.valid_;
  res["empty"] = exp.empty_;
  if (exp.mem_) {
    res["mem"] = createJsonforExpression(*exp.mem_);
  }
  if (exp.mem_size_) {
    res["mem_size"] = exp.mem_size_;
  }
  res["sign"] = exp.sign_;

  res["hasChild"] = exp.hasChild_;
  if (exp.hasChild_) {
    res["op"] = exp.op_;
    if (exp.sub1_) {
      res["sub1"] = createJsonforExpression(*exp.sub1_);
    }
    if (exp.sub2_) {
      res["sub2"] = createJsonforExpression(*exp.sub2_);
    }
  }

  res["isCFA"] = exp.isCFA_;

  return res;
}

json createJsonforAddressExp(const AddressExp &addrexp) {
  /*
      {
          Expression part ...

          "type" : <int>
          "detailedDwarfType" : <bool>
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
  nlohmann::json res = createJsonforExpression(addrexp);
  res["dwarfType"] = static_cast<int>(addrexp.dwarfType_);
  res["detailedDwarfType"] = addrexp.detailedDwarfType_;
  res["startpc"] = addrexp.startpc_;
  res["endpc"] = addrexp.endpc_;
  res["reg"] = addrexp.reg_;
  res["piece_start"] = addrexp.piece_.first;
  res["piece_size"] = addrexp.piece_.second;

  res["needCFA"] = addrexp.needCFA_;
  if (addrexp.needCFA_) {
    res["cfa_values"] = std::vector<nlohmann::json>();
    for (auto cfa_value : addrexp.cfa_values_) {
      res["cfa_values"].push_back(createJsonforExpression(cfa_value));
    }
    res["cfa_pcs"] = addrexp.cfa_pcs_;
  }
  return res;
}

json createJsonforAddress(const Address &addr) {
  /*
      {
          "addrExps" : [
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
  nlohmann::json res;
  for (AddressExp addrExp : addr.addrs_) {
    res["addrExps"].push_back(createJsonforAddressExp(addrExp));
  }
  res["name"] = addr.name_;
  if (addr.type_info_ != nullptr) {
    res["type_info"] = createJsonForType(addr.type_info_);
  }
  res["decl_file"] = addr.decl_file_;
  res["decl_row"] = addr.decl_row_;
  res["decl_col"] = addr.decl_col_;
  res["valid"] = addr.valid_;

  return res;
}

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
              "type" : <Type>
          }
      }
  }
*/
json createJsonForType(const std::shared_ptr<Type> &type) {
  nlohmann::json res;

  res["typeName"] = type->GetTypeName();
  res["size"] = type->GetTypeSize();
  res["userDefined"] = type->IsUserDefined();
  res["isPointer"] = type->IsPointer();
  res["pointerLevel"] = type->GetPointerLevel();

  /* if user defined , add members info */
  if (type->IsUserDefined()) {
    auto members_json = nlohmann::json::object();

    /* get member info */
    const auto &member_names = type->GetMemberNames();
    const auto &member_types = type->GetMemberTypes();
    const auto &member_offsets = type->GetMemberOffsets();

    /* iter the memer name and record */
    for (const auto &name : member_names) {
      Dwarf_Unsigned offset = member_offsets.at(name);
      nlohmann::json member_info = nlohmann::json::object();
      member_info["name"] = name;
      auto type_info = member_types.at(name);
      /* recur */
      member_info["type"] = createJsonForType(type_info);
      members_json[std::to_string(offset)] = member_info;
    }

    /* add member info to the return json */
    res["members"] = members_json;
  }

  return res;
}
}  // namespace varviewer
